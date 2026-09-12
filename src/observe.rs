//! Read-only observation hooks for the DNS engine.
//!
//! An [`EngineObserver`] receives structured events while the engine
//! processes requests (pipeline selection, rule matches, cache lookups,
//! upstream calls) and when the configuration is loaded or reloaded.
//! It exists so that metrics exporters, structured tracing and tests can
//! consume engine behaviour without depending on engine internals.
//!
//! Design constraints:
//!
//! - Observers cannot influence the engine. Every hook receives borrowed,
//!   immutable data; there is no way to intercept or rewrite a request.
//! - The hot path is not taxed when no observer is installed: the engine
//!   holds an `Option<Arc<dyn EngineObserver>>` and skips event
//!   construction after a single `is_some` check.
//! - Event payloads borrow from the engine (`&str` query names, rule ids,
//!   upstream addresses) instead of allocating. An observer that needs to
//!   keep data past the callback copies what it needs.
//! - All event structs and enums are `#[non_exhaustive]` so fields and
//!   variants can be added without breaking downstream implementations.
//!
//! [`NoopObserver`] is the "no hooks" implementation and [`TracingObserver`]
//! is a reference implementation that forwards every event to `tracing`.
//!
//! ```no_run
//! use std::sync::Arc;
//! use kixdns::engine::Engine;
//! use kixdns::observe::TracingObserver;
//!
//! # fn main() -> anyhow::Result<()> {
//! let cfg = kixdns::config::parse_config(r#"{ "pipelines": [] }"#)?;
//! let cfg = kixdns::matcher::RuntimePipelineConfig::from_config(cfg)?;
//! let engine = Engine::builder(cfg)
//!     .listener_label("default")
//!     .observer(Arc::new(TracingObserver))
//!     .build()?;
//! assert!(engine.observer().is_some());
//! # Ok(())
//! # }
//! ```

use std::net::SocketAddr;
use std::path::Path;
use std::time::Duration;

use hickory_proto::rr::{DNSClass, RecordType};

use crate::config::Transport;

/// Receiver of engine events. Every method has an empty default body, so an
/// implementation only overrides the events it cares about.
///
/// Hooks run synchronously on the request path; implementations must be
/// cheap and must never block.
#[allow(unused_variables)]
pub trait EngineObserver: Send + Sync + 'static {
    /// A client request entered the engine. Emitted exactly once per request,
    /// including background refresh requests (see
    /// [`RequestContext::background_refresh`]).
    fn request_started(&self, ctx: &RequestContext<'_>) {}

    /// The request left the engine. Paired with [`request_started`]; also
    /// emitted when the request future is dropped before completing (for
    /// example on a listener timeout), with
    /// [`RequestStatus::Cancelled`].
    ///
    /// [`request_started`]: EngineObserver::request_started
    fn request_finished(&self, ctx: &RequestContext<'_>, outcome: &RequestOutcome) {}

    /// A pipeline was chosen for the request: once after pipeline selection
    /// and again for every `jump_to_pipeline` decision.
    fn pipeline_selected(&self, ctx: &RequestContext<'_>, pipeline: &str) {}

    /// A rule's matchers evaluated to true.
    fn rule_matched(&self, ctx: &RequestContext<'_>, event: &RuleMatched<'_>) {}

    /// The response cache was consulted for the request.
    fn cache_lookup(&self, ctx: &RequestContext<'_>) {}

    /// The response cache answered the request.
    fn cache_hit(&self, ctx: &RequestContext<'_>, kind: CacheHitKind) {}

    /// A query is about to be sent to an upstream server.
    fn upstream_attempt(&self, ctx: &RequestContext<'_>, event: &UpstreamAttempt<'_>) {}

    /// An upstream attempt completed.
    fn upstream_result(&self, ctx: &RequestContext<'_>, event: &UpstreamResult<'_>) {}

    /// A configuration became active: the initial load and every successful
    /// hot reload.
    fn config_loaded(&self, event: &ConfigLoaded<'_>) {}

    /// A hot reload was rejected; the previous configuration stays active.
    fn config_reload_failed(&self, event: &ConfigReloadFailed<'_>) {}
}

/// Immutable description of the request an event belongs to.
///
/// `request_id` is unique for the lifetime of the engine and is the key to
/// correlate all events of one request.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct RequestContext<'a> {
    /// Engine-local request identifier, unique per engine instance.
    pub request_id: u64,
    /// Listener label of the engine that handles the request.
    pub listener_label: &'a str,
    /// Client address as seen by the listener.
    pub client: SocketAddr,
    /// Query name, lower-cased, without a trailing dot.
    pub qname: &'a str,
    /// Query type.
    pub qtype: RecordType,
    /// Query class.
    pub qclass: DNSClass,
    /// `true` when the request is an internal cache refresh rather than a
    /// client query. Refresh requests bypass the cache lookup.
    pub background_refresh: bool,
}

/// How a request ended.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct RequestOutcome {
    /// Wall-clock time between `request_started` and `request_finished`.
    pub latency: Duration,
    /// Completion status.
    pub status: RequestStatus,
}

/// Completion status of a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum RequestStatus {
    /// A response was produced (including SERVFAIL/REFUSED answers built by
    /// the engine itself).
    Completed,
    /// The engine returned an error; the listener answers SERVFAIL.
    Failed,
    /// The request future was dropped before completing.
    Cancelled,
}

/// A rule whose matchers evaluated to true.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct RuleMatched<'a> {
    /// Pipeline that owns the rule.
    pub pipeline: &'a str,
    /// Rule name from the configuration.
    pub rule: &'a str,
    /// Whether request or response matchers matched.
    pub phase: RulePhase,
    /// What the match leads to.
    pub decision: DecisionKind,
    /// `true` when the match came from the synchronous fast path
    /// (`handle_packet_fast`), which answers static rules without the full
    /// request pipeline.
    pub fast_path: bool,
}

/// Matching phase of a rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum RulePhase {
    /// Request matchers (`matchers`).
    Request,
    /// Response matchers (`response_matchers`).
    Response,
}

/// Outcome of a rule match.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum DecisionKind {
    /// A response is synthesised locally (static, deny, TXT replacement).
    Static,
    /// The query is forwarded to an upstream, or an upstream response is
    /// accepted as is.
    Forward,
    /// Processing continues in another pipeline.
    Jump,
    /// The rule matched but did not decide; evaluation continues with the
    /// next rule (for example log-only rules or `continue`).
    Continue,
}

/// Which kind of cached response answered a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum CacheHitKind {
    /// The entry is within its TTL.
    Fresh,
    /// The entry is past its TTL and served immediately (RFC 8767 with
    /// `serve_stale_client_timeout_ms = 0`).
    Stale,
    /// The entry is past its TTL and served because the upstream did not
    /// answer within `serve_stale_client_timeout_ms`.
    StaleClientTimeout,
    /// The entry is past its TTL and served because every upstream attempt
    /// failed.
    StaleUpstreamFailure,
}

/// A query is being sent to an upstream.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct UpstreamAttempt<'a> {
    /// Upstream address without the transport prefix
    /// (for example `1.1.1.1:53` or `dns.example/dns-query`).
    pub upstream: &'a str,
    /// Transport selected for this address.
    pub transport: Transport,
}

/// An upstream attempt completed.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct UpstreamResult<'a> {
    /// Upstream address without the transport prefix.
    pub upstream: &'a str,
    /// Transport selected for this address.
    pub transport: Transport,
    /// Result classification.
    pub outcome: UpstreamOutcome,
    /// Time spent on this attempt.
    pub latency: Duration,
    /// Error for [`UpstreamOutcome::Error`]; `None` otherwise.
    pub error: Option<&'a anyhow::Error>,
}

/// Classification of an upstream attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum UpstreamOutcome {
    /// A usable response was received.
    Success,
    /// A response was received but discarded (SERVFAIL/REFUSED while other
    /// upstreams of a concurrent set were still pending).
    Rejected,
    /// The attempt failed (timeout, transport error, task failure).
    Error,
}

/// A configuration became active.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct ConfigLoaded<'a> {
    /// Path the configuration was read from.
    pub path: &'a Path,
    /// Monotonic generation counter: `1` for the initial configuration,
    /// incremented by every successful reload.
    pub generation: u64,
    /// Raw configuration text as read from `path`. Observers that need a
    /// fingerprint derive it from this text.
    pub source: &'a str,
}

/// A hot reload failed and the previous configuration remains active.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct ConfigReloadFailed<'a> {
    /// Path of the rejected configuration.
    pub path: &'a Path,
    /// Human-readable error including its cause chain.
    pub error: &'a str,
}

/// Observer that ignores every event. Installing it is equivalent to
/// installing no observer.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopObserver;

impl EngineObserver for NoopObserver {}

/// Reference observer that emits every event as a `tracing` event at
/// `DEBUG` level under the `kixdns::observe` target, with the event kind in
/// the `event` field. Enable it with `--debug` or
/// `RUST_LOG=kixdns::observe=debug`.
#[derive(Debug, Default, Clone, Copy)]
pub struct TracingObserver;

const TRACE_TARGET: &str = "kixdns::observe";

impl EngineObserver for TracingObserver {
    fn request_started(&self, ctx: &RequestContext<'_>) {
        tracing::debug!(
            target: TRACE_TARGET,
            event = "request_started",
            request_id = ctx.request_id,
            listener = ctx.listener_label,
            client = %ctx.client,
            qname = ctx.qname,
            qtype = ?ctx.qtype,
            qclass = ?ctx.qclass,
            background_refresh = ctx.background_refresh,
            "request started"
        );
    }

    fn request_finished(&self, ctx: &RequestContext<'_>, outcome: &RequestOutcome) {
        tracing::debug!(
            target: TRACE_TARGET,
            event = "request_finished",
            request_id = ctx.request_id,
            status = ?outcome.status,
            latency_us = outcome.latency.as_micros() as u64,
            "request finished"
        );
    }

    fn pipeline_selected(&self, ctx: &RequestContext<'_>, pipeline: &str) {
        tracing::debug!(
            target: TRACE_TARGET,
            event = "pipeline_selected",
            request_id = ctx.request_id,
            pipeline,
            "pipeline selected"
        );
    }

    fn rule_matched(&self, ctx: &RequestContext<'_>, event: &RuleMatched<'_>) {
        tracing::debug!(
            target: TRACE_TARGET,
            event = "rule_matched",
            request_id = ctx.request_id,
            pipeline = event.pipeline,
            rule = event.rule,
            phase = ?event.phase,
            decision = ?event.decision,
            fast_path = event.fast_path,
            "rule matched"
        );
    }

    fn cache_lookup(&self, ctx: &RequestContext<'_>) {
        tracing::debug!(
            target: TRACE_TARGET,
            event = "cache_lookup",
            request_id = ctx.request_id,
            "cache lookup"
        );
    }

    fn cache_hit(&self, ctx: &RequestContext<'_>, kind: CacheHitKind) {
        tracing::debug!(
            target: TRACE_TARGET,
            event = "cache_hit",
            request_id = ctx.request_id,
            kind = ?kind,
            "cache hit"
        );
    }

    fn upstream_attempt(&self, ctx: &RequestContext<'_>, event: &UpstreamAttempt<'_>) {
        tracing::debug!(
            target: TRACE_TARGET,
            event = "upstream_attempt",
            request_id = ctx.request_id,
            upstream = event.upstream,
            transport = ?event.transport,
            "upstream attempt"
        );
    }

    fn upstream_result(&self, ctx: &RequestContext<'_>, event: &UpstreamResult<'_>) {
        tracing::debug!(
            target: TRACE_TARGET,
            event = "upstream_result",
            request_id = ctx.request_id,
            upstream = event.upstream,
            transport = ?event.transport,
            outcome = ?event.outcome,
            latency_us = event.latency.as_micros() as u64,
            error = event.error.map(tracing::field::display),
            "upstream result"
        );
    }

    fn config_loaded(&self, event: &ConfigLoaded<'_>) {
        tracing::debug!(
            target: TRACE_TARGET,
            event = "config_loaded",
            path = %event.path.display(),
            generation = event.generation,
            source_bytes = event.source.len(),
            "config loaded"
        );
    }

    fn config_reload_failed(&self, event: &ConfigReloadFailed<'_>) {
        tracing::debug!(
            target: TRACE_TARGET,
            event = "config_reload_failed",
            path = %event.path.display(),
            error = event.error,
            "config reload failed"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn built_in_observers_accept_every_event() {
        let ctx = RequestContext {
            request_id: 7,
            listener_label: "default",
            client: "127.0.0.1:53000".parse().unwrap(),
            qname: "example.com",
            qtype: RecordType::A,
            qclass: DNSClass::IN,
            background_refresh: false,
        };
        let error = anyhow::anyhow!("boom");
        let observers: [&dyn EngineObserver; 2] = [&NoopObserver, &TracingObserver];
        for observer in observers {
            observer.request_started(&ctx);
            observer.pipeline_selected(&ctx, "main");
            observer.rule_matched(
                &ctx,
                &RuleMatched {
                    pipeline: "main",
                    rule: "static",
                    phase: RulePhase::Request,
                    decision: DecisionKind::Static,
                    fast_path: true,
                },
            );
            observer.cache_lookup(&ctx);
            observer.cache_hit(&ctx, CacheHitKind::Fresh);
            observer.upstream_attempt(
                &ctx,
                &UpstreamAttempt {
                    upstream: "1.1.1.1:53",
                    transport: Transport::Udp,
                },
            );
            observer.upstream_result(
                &ctx,
                &UpstreamResult {
                    upstream: "1.1.1.1:53",
                    transport: Transport::Udp,
                    outcome: UpstreamOutcome::Error,
                    latency: Duration::from_millis(3),
                    error: Some(&error),
                },
            );
            observer.request_finished(
                &ctx,
                &RequestOutcome {
                    latency: Duration::from_millis(4),
                    status: RequestStatus::Completed,
                },
            );
            observer.config_loaded(&ConfigLoaded {
                path: Path::new("config/pipeline.json"),
                generation: 1,
                source: "{}",
            });
            observer.config_reload_failed(&ConfigReloadFailed {
                path: Path::new("config/pipeline.json"),
                error: "invalid json",
            });
        }
    }
}
