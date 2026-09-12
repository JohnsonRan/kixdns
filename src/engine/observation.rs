//! Crate-internal helpers for reporting [`crate::observe`] events from the
//! engine. Everything here is only reached after the engine has confirmed an
//! observer is installed, so it may allocate event structs freely.
//! 引擎内部上报观察者事件的辅助函数。仅在确认安装了观察者后才会执行。

use std::sync::Arc;
use std::time::Instant;

use crate::config::Action;
use crate::engine::rules::Decision;
use crate::observe::{
    DecisionKind, EngineObserver, RequestContext, RequestOutcome, RequestStatus, RuleMatched,
    RulePhase,
};

/// Observer and request context of the request being processed. The engine
/// checks its `observer` field once per request and threads this pair to
/// every reporting site, so those sites only test a local `Option`.
/// 正在处理的请求的观察者与上下文。引擎每个请求只检查一次 observer 字段，
/// 随后把这对引用传给各上报点，各处只需检查本地 Option。
pub(crate) type Observed<'a> = Option<(&'a dyn EngineObserver, &'a RequestContext<'a>)>;

/// Observer handle for one request. Reports `request_finished` when dropped,
/// so a request whose future is dropped early (listener timeout) is reported
/// as cancelled instead of vanishing.
/// 单个请求的观察者句柄。drop 时上报 request_finished，被提前丢弃的请求上报为取消。
pub(crate) struct ObservedRequest<'a> {
    pub observer: &'a dyn EngineObserver,
    pub ctx: RequestContext<'a>,
    start: Instant,
    status: RequestStatus,
}

impl<'a> ObservedRequest<'a> {
    pub fn new(observer: &'a dyn EngineObserver, ctx: RequestContext<'a>, start: Instant) -> Self {
        Self {
            observer,
            ctx,
            start,
            status: RequestStatus::Cancelled,
        }
    }

    pub fn set_status(&mut self, status: RequestStatus) {
        self.status = status;
    }
}

impl Drop for ObservedRequest<'_> {
    fn drop(&mut self) {
        self.observer.request_finished(
            &self.ctx,
            &RequestOutcome {
                latency: self.start.elapsed(),
                status: self.status,
            },
        );
    }
}

/// Kind of a request-phase decision.
pub(crate) fn decision_kind(decision: &Decision) -> DecisionKind {
    match decision {
        Decision::Static { .. } => DecisionKind::Static,
        Decision::Forward { .. } => DecisionKind::Forward,
        Decision::Jump { .. } => DecisionKind::Jump,
    }
}

/// Kind of decision a response-phase action list leads to. An empty list (or
/// log-only) keeps the upstream response, which counts as `Forward`.
/// 响应阶段动作列表导致的决策类型。空列表（或仅日志）表示沿用上游响应，计为 Forward。
pub(crate) fn response_decision_kind(actions: &[Action]) -> DecisionKind {
    for action in actions {
        match action {
            Action::Log { .. } => continue,
            Action::Continue => return DecisionKind::Continue,
            Action::JumpToPipeline { .. } => return DecisionKind::Jump,
            Action::Forward { .. } | Action::Allow => return DecisionKind::Forward,
            Action::StaticResponse { .. }
            | Action::StaticIpResponse { .. }
            | Action::StaticCnameResponse { .. }
            | Action::StaticTxtResponse { .. }
            | Action::Deny
            | Action::ReplaceTxtResponse { .. } => return DecisionKind::Static,
        }
    }
    DecisionKind::Forward
}

/// Report request-phase rule matches in evaluation order. Every rule but the
/// last continued; the last carries `deciding` when a rule produced the
/// decision, and `Continue` when the default upstream applied instead.
/// 按求值顺序上报请求阶段的规则命中：除最后一条外都是 Continue；最后一条在规则
/// 产生决策时携带 `deciding`，否则（走默认上游）为 Continue。
pub(crate) fn report_matched_rules(
    observer: &dyn EngineObserver,
    ctx: &RequestContext<'_>,
    pipeline: &str,
    rules: &[Arc<str>],
    deciding: Option<DecisionKind>,
    fast_path: bool,
) {
    let last = rules.len().saturating_sub(1);
    for (idx, rule) in rules.iter().enumerate() {
        let decision = if idx == last {
            deciding.unwrap_or(DecisionKind::Continue)
        } else {
            DecisionKind::Continue
        };
        observer.rule_matched(
            ctx,
            &RuleMatched {
                pipeline,
                rule,
                phase: RulePhase::Request,
                decision,
                fast_path,
            },
        );
    }
}
