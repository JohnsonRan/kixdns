//! Observer API integration tests.
//!
//! A recording `EngineObserver` is installed through `Engine::builder` and the
//! tests assert the events the engine reports for static rules (slow and
//! fast path), response cache hits and misses (fresh and stale), rule cache
//! lookups and replays, rule evaluation and decisions, upstream attempts,
//! cancelled requests and configuration reloads.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{Name, RData, Record, RecordType};
use hickory_proto::serialize::binary::BinDecodable;

use kixdns::config::{Transport, parse_config};
use kixdns::engine::{Engine, FastPathResponse};
use kixdns::matcher::RuntimePipelineConfig;
use kixdns::observe::{
    CacheHit, CacheHitKind, ConfigLoaded, ConfigReloadFailed, DecisionDetail, DecisionKind,
    DecisionMade, EngineObserver, RequestContext, RequestOutcome, RequestStatus, RuleCacheLookup,
    RuleEvaluated, RuleMatched, RulePhase, UpstreamAttempt, UpstreamOutcome, UpstreamResult,
};

#[ctor::ctor]
fn init() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
}

// ============================================================================
// Recording observer / 记录型观察者
// ============================================================================

/// Owned copy of a `DecisionDetail`.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Detail {
    Static {
        rcode: ResponseCode,
        answers: usize,
    },
    Forward {
        upstream: String,
        transport: Option<Transport>,
    },
    Jump {
        pipeline: String,
    },
}

impl From<DecisionDetail<'_>> for Detail {
    fn from(detail: DecisionDetail<'_>) -> Self {
        match detail {
            DecisionDetail::Static { rcode, answers } => Detail::Static { rcode, answers },
            DecisionDetail::Forward {
                upstream,
                transport,
            } => Detail::Forward {
                upstream: upstream.to_string(),
                transport,
            },
            DecisionDetail::Jump { pipeline } => Detail::Jump {
                pipeline: pipeline.to_string(),
            },
            _ => unreachable!("unknown decision detail"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Event {
    Started {
        id: u64,
        qname: String,
        listener: String,
        client: SocketAddr,
        background: bool,
    },
    Finished {
        id: u64,
        status: RequestStatus,
    },
    Pipeline {
        id: u64,
        pipeline: String,
    },
    RuleCacheLookup {
        id: u64,
        pipeline: String,
        hit: bool,
        matched_rules: usize,
    },
    RuleEvaluated {
        id: u64,
        pipeline: String,
        rule: String,
        phase: RulePhase,
        matched: bool,
        matchers: usize,
    },
    Rule {
        id: u64,
        pipeline: String,
        rule: String,
        phase: RulePhase,
        decision: DecisionKind,
        fast_path: bool,
    },
    Decision {
        id: u64,
        pipeline: String,
        rule: Option<String>,
        detail: Detail,
    },
    CacheLookup {
        id: u64,
    },
    CacheHit {
        id: u64,
        kind: CacheHitKind,
        has_remaining_ttl: bool,
        original_ttl: Option<Duration>,
    },
    CacheMiss {
        id: u64,
    },
    UpstreamAttempt {
        id: u64,
        upstream: String,
        transport: Transport,
    },
    UpstreamResult {
        id: u64,
        upstream: String,
        outcome: UpstreamOutcome,
        rcode: Option<ResponseCode>,
        truncated: Option<bool>,
        has_error: bool,
    },
    ConfigLoaded {
        generation: u64,
        path: PathBuf,
        source: String,
    },
    ConfigReloadFailed {
        path: PathBuf,
        error: String,
    },
}

#[derive(Default)]
struct Recorder {
    events: Mutex<Vec<Event>>,
}

impl Recorder {
    fn push(&self, event: Event) {
        self.events.lock().unwrap().push(event);
    }

    fn events(&self) -> Vec<Event> {
        self.events.lock().unwrap().clone()
    }

    /// Remove and return everything recorded so far.
    fn drain(&self) -> Vec<Event> {
        std::mem::take(&mut *self.events.lock().unwrap())
    }

    /// Poll until `predicate` holds for the recorded events or `timeout` elapses.
    async fn wait_for(&self, timeout: Duration, predicate: impl Fn(&[Event]) -> bool) -> bool {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            if predicate(&self.events()) {
                return true;
            }
            if tokio::time::Instant::now() >= deadline {
                return false;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }
}

impl EngineObserver for Recorder {
    fn request_started(&self, ctx: &RequestContext<'_>) {
        self.push(Event::Started {
            id: ctx.request_id,
            qname: ctx.qname.to_string(),
            listener: ctx.listener_label.to_string(),
            client: ctx.client,
            background: ctx.background_refresh,
        });
    }

    fn request_finished(&self, ctx: &RequestContext<'_>, outcome: &RequestOutcome) {
        self.push(Event::Finished {
            id: ctx.request_id,
            status: outcome.status,
        });
    }

    fn pipeline_selected(&self, ctx: &RequestContext<'_>, pipeline: &str) {
        self.push(Event::Pipeline {
            id: ctx.request_id,
            pipeline: pipeline.to_string(),
        });
    }

    fn rule_cache_lookup(&self, ctx: &RequestContext<'_>, event: &RuleCacheLookup<'_>) {
        self.push(Event::RuleCacheLookup {
            id: ctx.request_id,
            pipeline: event.pipeline.to_string(),
            hit: event.hit,
            matched_rules: event.matched_rules,
        });
    }

    fn rule_evaluated(&self, ctx: &RequestContext<'_>, event: &RuleEvaluated<'_>) {
        self.push(Event::RuleEvaluated {
            id: ctx.request_id,
            pipeline: event.pipeline.to_string(),
            rule: event.rule.to_string(),
            phase: event.phase,
            matched: event.matched,
            matchers: event.matchers,
        });
    }

    fn rule_matched(&self, ctx: &RequestContext<'_>, event: &RuleMatched<'_>) {
        self.push(Event::Rule {
            id: ctx.request_id,
            pipeline: event.pipeline.to_string(),
            rule: event.rule.to_string(),
            phase: event.phase,
            decision: event.decision,
            fast_path: event.fast_path,
        });
    }

    fn decision_made(&self, ctx: &RequestContext<'_>, event: &DecisionMade<'_>) {
        self.push(Event::Decision {
            id: ctx.request_id,
            pipeline: event.pipeline.to_string(),
            rule: event.rule.map(str::to_string),
            detail: event.detail.into(),
        });
    }

    fn cache_lookup(&self, ctx: &RequestContext<'_>) {
        self.push(Event::CacheLookup { id: ctx.request_id });
    }

    fn cache_hit(&self, ctx: &RequestContext<'_>, event: &CacheHit) {
        self.push(Event::CacheHit {
            id: ctx.request_id,
            kind: event.kind,
            has_remaining_ttl: event.remaining_ttl.is_some(),
            original_ttl: event.original_ttl,
        });
    }

    fn cache_miss(&self, ctx: &RequestContext<'_>) {
        self.push(Event::CacheMiss { id: ctx.request_id });
    }

    fn upstream_attempt(&self, ctx: &RequestContext<'_>, event: &UpstreamAttempt<'_>) {
        self.push(Event::UpstreamAttempt {
            id: ctx.request_id,
            upstream: event.upstream.to_string(),
            transport: event.transport,
        });
    }

    fn upstream_result(&self, ctx: &RequestContext<'_>, event: &UpstreamResult<'_>) {
        self.push(Event::UpstreamResult {
            id: ctx.request_id,
            upstream: event.upstream.to_string(),
            outcome: event.outcome,
            rcode: event.rcode,
            truncated: event.truncated,
            has_error: event.error.is_some(),
        });
    }

    fn config_loaded(&self, event: &ConfigLoaded<'_>) {
        self.push(Event::ConfigLoaded {
            generation: event.generation,
            path: event.path.to_path_buf(),
            source: event.source.to_string(),
        });
    }

    fn config_reload_failed(&self, event: &ConfigReloadFailed<'_>) {
        self.push(Event::ConfigReloadFailed {
            path: event.path.to_path_buf(),
            error: event.error.to_string(),
        });
    }
}

// ============================================================================
// Helpers / 辅助函数
// ============================================================================

const PEER: &str = "127.0.0.1:53000";

fn peer() -> SocketAddr {
    PEER.parse().unwrap()
}

fn runtime_config(raw: &str) -> RuntimePipelineConfig {
    RuntimePipelineConfig::from_config(parse_config(raw).expect("parse config"))
        .expect("compile config")
}

fn observed_engine(raw: &str) -> (Engine, Arc<Recorder>) {
    let recorder = Arc::new(Recorder::default());
    let engine = Engine::builder(runtime_config(raw))
        .listener_label("edge")
        .observer(recorder.clone())
        .build()
        .expect("build engine");
    (engine, recorder)
}

fn query(qname: &str) -> Vec<u8> {
    let mut message = Message::new(0x1234, MessageType::Query, OpCode::Query);
    message.metadata.recursion_desired = true;
    message.add_query(Query::query(Name::from_str(qname).unwrap(), RecordType::A));
    message.to_vec().unwrap()
}

fn rcode_of(bytes: &[u8]) -> ResponseCode {
    Message::from_bytes(bytes).unwrap().metadata.response_code
}

/// Minimal UDP upstream that answers every query with one A record of the
/// given TTL. Aborting the returned task closes its socket.
/// 最小 UDP 上游：以给定 TTL 的一条 A 记录应答所有查询；中止返回的任务即关闭其 socket。
async fn spawn_echo_upstream(ttl: u32) -> (String, tokio::task::JoinHandle<()>) {
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap().to_string();
    let task = tokio::spawn(async move {
        let mut buf = [0u8; 1500];
        while let Ok((n, peer)) = socket.recv_from(&mut buf).await {
            let Ok(request) = Message::from_bytes(&buf[..n]) else {
                continue;
            };
            let Some(question) = request.queries.first().cloned() else {
                continue;
            };
            let mut response =
                Message::new(request.metadata.id, MessageType::Response, OpCode::Query);
            response.add_query(question.clone());
            response.add_answer(Record::from_rdata(
                question.name().clone(),
                ttl,
                RData::A(A(std::net::Ipv4Addr::LOCALHOST)),
            ));
            let _ = socket.send_to(&response.to_vec().unwrap(), peer).await;
        }
    });
    (addr, task)
}

/// Request id of the first `Started` event whose query name matches.
fn request_id_for(events: &[Event], qname: &str) -> u64 {
    events
        .iter()
        .find_map(|event| match event {
            Event::Started {
                id, qname: name, ..
            } if name == qname => Some(*id),
            _ => None,
        })
        .unwrap_or_else(|| panic!("no request_started for {qname}: {events:#?}"))
}

fn events_of(events: &[Event], request_id: u64) -> Vec<Event> {
    events
        .iter()
        .filter(|event| match event {
            Event::Started { id, .. }
            | Event::Finished { id, .. }
            | Event::Pipeline { id, .. }
            | Event::RuleCacheLookup { id, .. }
            | Event::RuleEvaluated { id, .. }
            | Event::Rule { id, .. }
            | Event::Decision { id, .. }
            | Event::CacheLookup { id }
            | Event::CacheHit { id, .. }
            | Event::CacheMiss { id }
            | Event::UpstreamAttempt { id, .. }
            | Event::UpstreamResult { id, .. } => *id == request_id,
            Event::ConfigLoaded { .. } | Event::ConfigReloadFailed { .. } => false,
        })
        .cloned()
        .collect()
}

fn started(id: u64, qname: &str) -> Event {
    Event::Started {
        id,
        qname: qname.into(),
        listener: "edge".into(),
        client: peer(),
        background: false,
    }
}

fn finished(id: u64) -> Event {
    Event::Finished {
        id,
        status: RequestStatus::Completed,
    }
}

fn static_config(ip: &str) -> String {
    serde_json::json!({
        "settings": { "default_upstream": "127.0.0.1:9" },
        "pipelines": [{
            "id": "main",
            "rules": [{
                "name": "static",
                "matchers": [{ "type": "any" }],
                "actions": [{ "type": "static_ip_response", "ip": ip }]
            }]
        }]
    })
    .to_string()
}

fn atomically_replace(path: &Path, contents: &str) {
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, contents).expect("write tmp config");
    std::fs::rename(&tmp, path).expect("rename config");
}

// ============================================================================
// Tests / 测试
// ============================================================================

#[tokio::test]
async fn builder_defaults_match_engine_new() {
    let raw = static_config("192.0.2.1");
    let plain = Engine::new(runtime_config(&raw), "default".to_string()).unwrap();
    assert!(plain.observer().is_none());
    assert_eq!(plain.config_generation(), 1);

    let built = Engine::builder(runtime_config(&raw)).build().unwrap();
    assert!(built.observer().is_none());
    assert_eq!(built.listener_label.as_ref(), "default");

    let (observed, _) = observed_engine(&raw);
    assert!(observed.observer().is_some());
    assert_eq!(observed.listener_label.as_ref(), "edge");
    observed.reload(runtime_config(&raw));
    assert_eq!(observed.config_generation(), 2);
}

#[tokio::test]
async fn static_rule_is_reported_on_slow_and_fast_paths() {
    let raw = serde_json::json!({
        "settings": { "default_upstream": "127.0.0.1:9", "min_ttl": 60 },
        "pipelines": [{
            "id": "main",
            "rules": [{
                "name": "block",
                "matchers": [{ "type": "domain_suffix", "value": "blocked.test" }],
                "actions": [{ "type": "static_response", "rcode": "NXDOMAIN" }]
            }]
        }]
    })
    .to_string();
    let (engine, recorder) = observed_engine(&raw);

    // Slow path: full request pipeline / 完整请求路径
    let response = engine
        .handle_packet(&query("a.blocked.test"), peer())
        .await
        .unwrap();
    assert_eq!(rcode_of(&response), ResponseCode::NXDomain);
    let events = recorder.drain();
    let id = request_id_for(&events, "a.blocked.test");
    assert_eq!(
        events_of(&events, id),
        vec![
            started(id, "a.blocked.test"),
            Event::Pipeline {
                id,
                pipeline: "main".into()
            },
            Event::CacheLookup { id },
            Event::CacheMiss { id },
            Event::RuleCacheLookup {
                id,
                pipeline: "main".into(),
                hit: false,
                matched_rules: 0,
            },
            Event::RuleEvaluated {
                id,
                pipeline: "main".into(),
                rule: "block".into(),
                phase: RulePhase::Request,
                matched: true,
                matchers: 1,
            },
            Event::Rule {
                id,
                pipeline: "main".into(),
                rule: "block".into(),
                phase: RulePhase::Request,
                decision: DecisionKind::Static,
                fast_path: false,
            },
            Event::Decision {
                id,
                pipeline: "main".into(),
                rule: Some("block".into()),
                detail: Detail::Static {
                    rcode: ResponseCode::NXDomain,
                    answers: 0,
                },
            },
            finished(id),
        ]
    );

    // Fast path, compiled static rule for a name not in the response cache
    // 快速路径：响应缓存中没有的名字命中编译后的静态规则
    let fast = engine
        .handle_packet_fast(&query("b.blocked.test"), peer())
        .unwrap();
    assert!(matches!(fast, Some(FastPathResponse::Direct(_))));
    let events = recorder.drain();
    let id = request_id_for(&events, "b.blocked.test");
    assert_eq!(
        events_of(&events, id),
        vec![
            started(id, "b.blocked.test"),
            Event::Pipeline {
                id,
                pipeline: "main".into()
            },
            Event::CacheLookup { id },
            Event::CacheMiss { id },
            Event::Rule {
                id,
                pipeline: "main".into(),
                rule: "block".into(),
                phase: RulePhase::Request,
                decision: DecisionKind::Static,
                fast_path: true,
            },
            Event::Decision {
                id,
                pipeline: "main".into(),
                rule: Some("block".into()),
                detail: Detail::Static {
                    rcode: ResponseCode::NXDomain,
                    answers: 0,
                },
            },
            finished(id),
        ]
    );

    // Fast path, response cache populated by the first request
    // 快速路径：第一个请求已写入响应缓存
    let fast = engine
        .handle_packet_fast(&query("a.blocked.test"), peer())
        .unwrap();
    assert!(matches!(fast, Some(FastPathResponse::CacheHit { .. })));
    let events = recorder.drain();
    let id = request_id_for(&events, "a.blocked.test");
    assert_eq!(
        events_of(&events, id),
        vec![
            started(id, "a.blocked.test"),
            Event::Pipeline {
                id,
                pipeline: "main".into()
            },
            Event::CacheLookup { id },
            Event::CacheHit {
                id,
                kind: CacheHitKind::Fresh,
                has_remaining_ttl: true,
                original_ttl: Some(Duration::from_secs(60)),
            },
            finished(id),
        ]
    );
}

#[tokio::test]
async fn rule_cache_hits_replay_matched_rules() {
    let raw = serde_json::json!({
        "settings": { "default_upstream": "127.0.0.1:9", "min_ttl": 0 },
        "pipelines": [{
            "id": "main",
            "rules": [
                {
                    "name": "audit",
                    "matchers": [{ "type": "any" }],
                    "actions": [{ "type": "log", "level": "debug" }]
                },
                {
                    "name": "block",
                    "matchers": [{ "type": "any" }],
                    "actions": [{ "type": "static_response", "rcode": "NXDOMAIN" }]
                }
            ]
        }]
    })
    .to_string();
    let (engine, recorder) = observed_engine(&raw);

    let rule_events = |events: &[Event], id: u64| -> Vec<(String, DecisionKind, bool)> {
        events_of(events, id)
            .into_iter()
            .filter_map(|event| match event {
                Event::Rule {
                    rule,
                    decision,
                    fast_path,
                    ..
                } => Some((rule, decision, fast_path)),
                _ => None,
            })
            .collect()
    };
    let decision = |id: u64| Event::Decision {
        id,
        pipeline: "main".into(),
        rule: Some("block".into()),
        detail: Detail::Static {
            rcode: ResponseCode::NXDomain,
            answers: 0,
        },
    };

    // First evaluation: both candidate rules are evaluated and match
    // 首次求值：两条候选规则都被求值并命中
    engine
        .handle_packet(&query("x.example"), peer())
        .await
        .unwrap();
    let events = recorder.drain();
    let id = request_id_for(&events, "x.example");
    assert_eq!(
        events_of(&events, id),
        vec![
            started(id, "x.example"),
            Event::Pipeline {
                id,
                pipeline: "main".into()
            },
            Event::CacheLookup { id },
            Event::CacheMiss { id },
            Event::RuleCacheLookup {
                id,
                pipeline: "main".into(),
                hit: false,
                matched_rules: 0,
            },
            Event::RuleEvaluated {
                id,
                pipeline: "main".into(),
                rule: "audit".into(),
                phase: RulePhase::Request,
                matched: true,
                matchers: 1,
            },
            Event::RuleEvaluated {
                id,
                pipeline: "main".into(),
                rule: "block".into(),
                phase: RulePhase::Request,
                matched: true,
                matchers: 1,
            },
            // rule_matched is reported once the pipeline's decision is known,
            // after every candidate was evaluated / 规则命中在管线决策确定后统一上报
            Event::Rule {
                id,
                pipeline: "main".into(),
                rule: "audit".into(),
                phase: RulePhase::Request,
                decision: DecisionKind::Continue,
                fast_path: false,
            },
            Event::Rule {
                id,
                pipeline: "main".into(),
                rule: "block".into(),
                phase: RulePhase::Request,
                decision: DecisionKind::Static,
                fast_path: false,
            },
            decision(id),
            finished(id),
        ]
    );

    // min_ttl = 0 keeps the static answer out of the response cache, so the
    // next slow-path request reaches the rule cache: the recorded rules are
    // replayed and the decision is reported without re-evaluating anything.
    // min_ttl = 0 使静态应答不进入响应缓存，下一次慢路径请求到达规则缓存：
    // 回放记录的规则并上报决策，不再重新求值。
    engine
        .handle_packet(&query("x.example"), peer())
        .await
        .unwrap();
    let events = recorder.drain();
    let id = request_id_for(&events, "x.example");
    assert_eq!(
        events_of(&events, id),
        vec![
            started(id, "x.example"),
            Event::Pipeline {
                id,
                pipeline: "main".into()
            },
            Event::CacheLookup { id },
            Event::CacheMiss { id },
            Event::RuleCacheLookup {
                id,
                pipeline: "main".into(),
                hit: true,
                matched_rules: 2,
            },
            Event::Rule {
                id,
                pipeline: "main".into(),
                rule: "audit".into(),
                phase: RulePhase::Request,
                decision: DecisionKind::Continue,
                fast_path: false,
            },
            Event::Rule {
                id,
                pipeline: "main".into(),
                rule: "block".into(),
                phase: RulePhase::Request,
                decision: DecisionKind::Static,
                fast_path: false,
            },
            decision(id),
            finished(id),
        ]
    );

    // The fast path reaches the same rule cache entry and replays it too
    // 快速路径到达同一规则缓存条目并同样回放
    let fast = engine
        .handle_packet_fast(&query("x.example"), peer())
        .unwrap();
    assert!(matches!(fast, Some(FastPathResponse::Direct(_))));
    let events = recorder.drain();
    let id = request_id_for(&events, "x.example");
    let mine = events_of(&events, id);
    assert!(mine.contains(&Event::RuleCacheLookup {
        id,
        pipeline: "main".into(),
        hit: true,
        matched_rules: 2,
    }));
    assert!(
        !mine
            .iter()
            .any(|event| matches!(event, Event::RuleEvaluated { .. })),
        "rule cache replays must not report rule_evaluated: {mine:#?}"
    );
    assert_eq!(
        rule_events(&events, id),
        vec![
            ("audit".to_string(), DecisionKind::Continue, true),
            ("block".to_string(), DecisionKind::Static, true),
        ]
    );
    assert!(mine.contains(&decision(id)));
}

#[tokio::test]
async fn upstream_success_then_fresh_and_stale_cache_hits() {
    let (upstream, _echo) = spawn_echo_upstream(1).await;
    let raw = serde_json::json!({
        "settings": {
            "default_upstream": "127.0.0.1:9",
            "min_ttl": 0,
            "serve_stale": true,
            "serve_stale_client_timeout_ms": 0
        },
        "pipelines": [{
            "id": "main",
            "rules": [{
                "name": "fwd",
                "matchers": [{ "type": "any" }],
                "actions": [{ "type": "forward", "upstream": upstream, "transport": "udp" }]
            }]
        }]
    })
    .to_string();
    let (engine, recorder) = observed_engine(&raw);

    // Miss: evaluated by the rules and forwarded to the echo upstream
    // 未命中：经规则求值后转发到回显上游
    let response = engine
        .handle_packet(&query("cache.example"), peer())
        .await
        .unwrap();
    assert_eq!(rcode_of(&response), ResponseCode::NoError);
    let events = recorder.drain();
    let id = request_id_for(&events, "cache.example");
    assert_eq!(
        events_of(&events, id),
        vec![
            started(id, "cache.example"),
            Event::Pipeline {
                id,
                pipeline: "main".into()
            },
            Event::CacheLookup { id },
            Event::CacheMiss { id },
            Event::RuleCacheLookup {
                id,
                pipeline: "main".into(),
                hit: false,
                matched_rules: 0,
            },
            Event::RuleEvaluated {
                id,
                pipeline: "main".into(),
                rule: "fwd".into(),
                phase: RulePhase::Request,
                matched: true,
                matchers: 1,
            },
            Event::Rule {
                id,
                pipeline: "main".into(),
                rule: "fwd".into(),
                phase: RulePhase::Request,
                decision: DecisionKind::Forward,
                fast_path: false,
            },
            Event::Decision {
                id,
                pipeline: "main".into(),
                rule: Some("fwd".into()),
                detail: Detail::Forward {
                    upstream: upstream.clone(),
                    transport: Some(Transport::Udp),
                },
            },
            Event::UpstreamAttempt {
                id,
                upstream: upstream.clone(),
                transport: Transport::Udp,
            },
            Event::UpstreamResult {
                id,
                upstream: upstream.clone(),
                outcome: UpstreamOutcome::Success,
                rcode: Some(ResponseCode::NoError),
                truncated: Some(false),
                has_error: false,
            },
            finished(id),
        ]
    );

    // Fresh hit within the 1s TTL / TTL 内的新鲜命中
    engine
        .handle_packet(&query("cache.example"), peer())
        .await
        .unwrap();
    let events = recorder.drain();
    let id = request_id_for(&events, "cache.example");
    assert_eq!(
        events_of(&events, id),
        vec![
            started(id, "cache.example"),
            Event::Pipeline {
                id,
                pipeline: "main".into()
            },
            Event::CacheLookup { id },
            Event::CacheHit {
                id,
                kind: CacheHitKind::Fresh,
                has_remaining_ttl: true,
                original_ttl: Some(Duration::from_secs(1)),
            },
            finished(id),
        ]
    );

    // Stale hit after the TTL expired (RFC 8767) / TTL 过期后的过期命中
    tokio::time::sleep(Duration::from_millis(1200)).await;
    engine
        .handle_packet(&query("cache.example"), peer())
        .await
        .unwrap();
    let events = recorder.drain();
    let id = request_id_for(&events, "cache.example");
    let mine = events_of(&events, id);
    assert!(
        mine.contains(&Event::CacheHit {
            id,
            kind: CacheHitKind::Stale,
            has_remaining_ttl: false,
            original_ttl: Some(Duration::from_secs(1)),
        }),
        "{mine:#?}"
    );
    assert!(
        !mine
            .iter()
            .any(|event| matches!(event, Event::CacheMiss { .. })),
        "a stale hit is not a miss: {mine:#?}"
    );
    assert!(mine.contains(&finished(id)));
}

#[tokio::test]
async fn background_refresh_reports_no_cache_events() {
    // A stale entry whose upstream has gone away: the foreground request is
    // served stale and spawns a background refresh, whose forward fails.
    // 上游已消失的过期条目：前台请求返回过期缓存并触发后台刷新，刷新转发失败。
    let (upstream, echo) = spawn_echo_upstream(1).await;
    let raw = serde_json::json!({
        "settings": {
            "default_upstream": "127.0.0.1:9",
            "min_ttl": 0,
            "serve_stale": true,
            "serve_stale_client_timeout_ms": 0,
            "upstream_timeout_ms": 200,
            "enable_tcp_fallback": false
        },
        "pipelines": [{
            "id": "main",
            "rules": [{
                "name": "fwd",
                "matchers": [{ "type": "any" }],
                "actions": [{ "type": "forward", "upstream": upstream, "transport": "udp" }]
            }]
        }]
    })
    .to_string();
    let (engine, recorder) = observed_engine(&raw);

    engine
        .handle_packet(&query("stale.example"), peer())
        .await
        .unwrap();
    echo.abort();
    tokio::time::sleep(Duration::from_millis(1200)).await;
    recorder.drain();

    engine
        .handle_packet(&query("stale.example"), peer())
        .await
        .unwrap();
    // Wait for the background refresh to run to completion / 等待后台刷新结束
    assert!(
        recorder
            .wait_for(Duration::from_secs(5), |events| {
                events.iter().any(|event| {
                    matches!(
                        event,
                        Event::Finished { id, .. }
                            if events.iter().any(|started| matches!(
                                started,
                                Event::Started { id: sid, background: true, .. } if sid == id
                            ))
                    )
                })
            })
            .await,
        "background refresh must finish: {:#?}",
        recorder.events()
    );

    let events = recorder.drain();
    let foreground = request_id_for(&events, "stale.example");
    let background = events
        .iter()
        .find_map(|event| match event {
            Event::Started {
                id,
                background: true,
                ..
            } => Some(*id),
            _ => None,
        })
        .expect("background refresh request");
    assert_ne!(foreground, background);

    let foreground_events = events_of(&events, foreground);
    assert!(foreground_events.contains(&Event::CacheLookup { id: foreground }));
    assert!(foreground_events.iter().any(|event| matches!(
        event,
        Event::CacheHit {
            kind: CacheHitKind::Stale,
            ..
        }
    )));

    let background_events = events_of(&events, background);
    assert!(
        background_events.iter().any(|event| matches!(
            event,
            Event::UpstreamResult {
                outcome: UpstreamOutcome::Error,
                ..
            }
        )),
        "the refresh forward must fail: {background_events:#?}"
    );
    assert!(
        !background_events.iter().any(|event| matches!(
            event,
            Event::CacheLookup { .. } | Event::CacheHit { .. } | Event::CacheMiss { .. }
        )),
        "a background refresh must report no cache events: {background_events:#?}"
    );
}

#[tokio::test]
async fn concurrent_upstreams_report_the_loser_as_aborted() {
    // One upstream answers at once, the other never does / 一个立即应答，一个黑洞
    let (echo, _echo_task) = spawn_echo_upstream(60).await;
    let blackhole_socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let blackhole = blackhole_socket.local_addr().unwrap().to_string();
    let raw = serde_json::json!({
        "settings": { "default_upstream": "127.0.0.1:9", "enable_tcp_fallback": false },
        "pipelines": [{
            "id": "main",
            "rules": [{
                "name": "race",
                "matchers": [{ "type": "any" }],
                "actions": [{
                    "type": "forward",
                    "upstream": format!("{echo},{blackhole}"),
                    "transport": "udp"
                }]
            }]
        }]
    })
    .to_string();
    let (engine, recorder) = observed_engine(&raw);

    let response = engine
        .handle_packet(&query("race.example"), peer())
        .await
        .unwrap();
    assert_eq!(rcode_of(&response), ResponseCode::NoError);
    let events = recorder.drain();
    let id = request_id_for(&events, "race.example");
    let mine = events_of(&events, id);

    let attempts: Vec<String> = mine
        .iter()
        .filter_map(|event| match event {
            Event::UpstreamAttempt { upstream, .. } => Some(upstream.clone()),
            _ => None,
        })
        .collect();
    let results: Vec<(String, UpstreamOutcome)> = mine
        .iter()
        .filter_map(|event| match event {
            Event::UpstreamResult {
                upstream, outcome, ..
            } => Some((upstream.clone(), *outcome)),
            _ => None,
        })
        .collect();
    assert_eq!(attempts, vec![echo.clone(), blackhole.clone()]);
    assert_eq!(results.len(), 2, "one result per attempt: {mine:#?}");
    assert!(results.contains(&(echo.clone(), UpstreamOutcome::Success)));
    assert!(results.contains(&(blackhole.clone(), UpstreamOutcome::Aborted)));
    drop(blackhole_socket);
}

#[tokio::test]
async fn failed_upstream_is_reported_with_error() {
    let raw = serde_json::json!({
        "settings": {
            "default_upstream": "127.0.0.1:9",
            "upstream_timeout_ms": 100,
            "enable_tcp_fallback": false
        },
        "pipelines": [{
            "id": "main",
            "rules": [{
                "name": "fwd",
                "matchers": [{ "type": "any" }],
                "actions": [{ "type": "forward", "upstream": "127.0.0.1:9", "transport": "udp" }]
            }]
        }]
    })
    .to_string();
    let (engine, recorder) = observed_engine(&raw);

    let response = engine
        .handle_packet(&query("down.example"), peer())
        .await
        .unwrap();
    assert_eq!(rcode_of(&response), ResponseCode::ServFail);
    let events = recorder.drain();
    let id = request_id_for(&events, "down.example");
    let mine = events_of(&events, id);
    assert!(mine.contains(&Event::UpstreamAttempt {
        id,
        upstream: "127.0.0.1:9".into(),
        transport: Transport::Udp,
    }));
    assert!(
        mine.contains(&Event::UpstreamResult {
            id,
            upstream: "127.0.0.1:9".into(),
            outcome: UpstreamOutcome::Error,
            rcode: None,
            truncated: None,
            has_error: true,
        }),
        "{mine:#?}"
    );
    assert_eq!(mine.last(), Some(&finished(id)));
}

#[tokio::test]
async fn cancelled_request_is_reported() {
    // An upstream that never answers / 永不应答的上游
    let silent = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let upstream = silent.local_addr().unwrap().to_string();
    let raw = serde_json::json!({
        "settings": {
            "default_upstream": "127.0.0.1:9",
            "upstream_timeout_ms": 5000,
            "enable_tcp_fallback": false
        },
        "pipelines": [{
            "id": "main",
            "rules": [{
                "name": "fwd",
                "matchers": [{ "type": "any" }],
                "actions": [{ "type": "forward", "upstream": upstream, "transport": "udp" }]
            }]
        }]
    })
    .to_string();
    let (engine, recorder) = observed_engine(&raw);

    let packet = query("slow.example");
    let result = tokio::time::timeout(
        Duration::from_millis(100),
        engine.handle_packet(&packet, peer()),
    )
    .await;
    assert!(
        result.is_err(),
        "the listener timeout must drop the request"
    );

    let events = recorder.drain();
    let id = request_id_for(&events, "slow.example");
    let mine = events_of(&events, id);
    assert!(mine.contains(&Event::UpstreamAttempt {
        id,
        upstream: upstream.clone(),
        transport: Transport::Udp,
    }));
    assert_eq!(
        mine.last(),
        Some(&Event::Finished {
            id,
            status: RequestStatus::Cancelled
        }),
        "{mine:#?}"
    );
    drop(silent);
}

#[tokio::test]
async fn hot_reload_reports_success_and_failure() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("pipeline.json");
    let v1 = static_config("192.0.2.1");
    std::fs::write(&path, &v1).unwrap();

    let (engine, recorder) = observed_engine(&v1);
    engine.notify_config_loaded(&path, &v1);
    assert_eq!(
        recorder.drain(),
        vec![Event::ConfigLoaded {
            generation: 1,
            path: path.clone(),
            source: v1.clone(),
        }]
    );

    kixdns::watcher::spawn(path.clone(), engine.clone());

    // Successful reload: re-swap until the watcher (which registers its
    // watch asynchronously) reports the new generation.
    // 成功重载：重复替换直到异步注册的 watcher 上报新的代数。
    let v2 = static_config("192.0.2.2");
    let mut reloaded = false;
    for _ in 0..20 {
        atomically_replace(&path, &v2);
        if recorder
            .wait_for(Duration::from_millis(500), |events| {
                events.iter().any(|event| {
                    matches!(
                        event,
                        Event::ConfigLoaded { generation, path: p, source }
                            if *generation >= 2 && p == &path && source == &v2
                    )
                })
            })
            .await
        {
            reloaded = true;
            break;
        }
    }
    assert!(
        reloaded,
        "config_loaded must be reported after a hot reload"
    );
    assert!(engine.config_generation() >= 2);
    let response = engine
        .handle_packet(&query("reload.example"), peer())
        .await
        .unwrap();
    let answer = Message::from_bytes(&response).unwrap();
    assert!(matches!(
        answer.answers.first().map(|record| &record.data),
        Some(RData::A(address)) if address.0 == std::net::Ipv4Addr::new(192, 0, 2, 2)
    ));
    let generation_after_success = engine.config_generation();
    recorder.drain();

    // Failed reload: invalid JSON keeps the previous configuration and is
    // reported once the bounded retries are exhausted.
    // 失败重载：无效 JSON 保留旧配置，重试耗尽后上报。
    let mut failed = false;
    for _ in 0..10 {
        atomically_replace(&path, "{ \"pipelines\": [");
        if recorder
            .wait_for(Duration::from_secs(2), |events| {
                events.iter().any(|event| {
                    matches!(event, Event::ConfigReloadFailed { path: p, error } if p == &path && error.contains("line"))
                })
            })
            .await
        {
            failed = true;
            break;
        }
    }
    assert!(
        failed,
        "config_reload_failed must be reported: {:#?}",
        recorder.events()
    );
    assert!(
        !recorder
            .events()
            .iter()
            .any(|event| matches!(event, Event::ConfigLoaded { .. })),
        "a rejected configuration must not be reported as loaded"
    );
    assert_eq!(engine.config_generation(), generation_after_success);
}
