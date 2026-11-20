"""Render a persisted RepairResult trace as a Decision / Action / Observation sequence."""

from __future__ import annotations

from .contracts import BaselineResult, RepairResult, StageVerdict, TraceEvent, ValidationResult

_STOP_EVENTS = {
    "budget_exhausted": "預算用盡，停止",
    "budget_violation": "模型預算違規，丟棄本輪候選並停止",
    "round_empty": "本輪沒有新候選（輪數用盡前會重試）",
}


def render_react_trace(result: RepairResult) -> str:
    """Return a human-readable trace: one numbered line per decision, tool call or observation."""

    validations = {item.candidate_id: item for item in result.validations}
    rows: list[tuple[str, str]] = []
    for event in result.trace:
        rows.extend(_rows_for(event, validations, result))

    width = len(str(len(rows)))
    lines = [f"run_id={result.run_id}  task_id={result.task_id}", ""]
    for number, (kind, text) in enumerate(rows, start=1):
        lines.append(f"{number:>{width}}  {kind:<12} {text}")
    return "\n".join(lines)


def _rows_for(
    event: TraceEvent, validations: dict[str, ValidationResult], run: RepairResult
) -> list[tuple[str, str]]:
    attrs = dict(event.attributes)
    name = event.event
    short = (event.candidate_id or "")[:8]

    if name == "run_started":
        return [("Input", f"使用者提供漏洞任務 {event.task_id}")]
    if name in ("baseline_ready", "baseline_unusable"):
        usable = name == "baseline_ready"
        cause = "" if usable or run.baseline is None else _failing_stage(run.baseline)
        return [
            ("Action", "Tool Call: Oracle.baseline → Podman 容器執行 build / regression / PoC"),
            ("Observation", f"baseline {'可用' if usable else '不可用'}：{event.message}{cause}"),
        ]
    if name == "localized":
        return [
            ("Action", "Localizer 定位可疑程式碼"),
            ("Observation", f"取得 {attrs.get('locations', '?')} 個位置"),
        ]
    if name == "relocalized":
        return [
            ("Decision", f"第 {attrs.get('round', '?')} 輪：依上一輪 PoC 輸出重新定位"),
            ("Observation", f"取得 {attrs.get('locations', '?')} 個位置"),
        ]
    if name == "provider_errors":
        return [("Observation", f"LLM 呼叫失敗（{attrs.get('count', '?')} 次）：{event.message}")]
    if name == "candidates_generated":
        return [
            ("Action", f"第 {attrs.get('round', '?')} 輪：Generator 呼叫 LLM 產生候選修補"),
            ("Observation", f"產生 {attrs.get('count', '?')} 個候選"),
        ]
    if name == "critic_pass":
        return [("Decision", f"Critic 預審通過候選 {short}，送往驗證")]
    if name == "critic_reject":
        return [("Decision", f"Critic 拒絕候選 {short}（不進容器）：{event.message}")]
    if name == "candidate_validated":
        result = validations.get(event.candidate_id or "")
        detail = _failing_stage(result) if result is not None else ""
        return [
            ("Action", f"Tool Call: Oracle.validate({short}) → Podman 容器驗證"),
            ("Observation", f"verdict={attrs.get('verdict', '?')}{detail}"),
        ]
    if name == "verified_fix_selected":
        return [("Decision", f"選用 verified_fix 候選 {short}")]
    if name in _STOP_EVENTS:
        reason = f"：{event.message}" if event.message else ""
        return [("Decision", f"{_STOP_EVENTS[name]}{reason}")]
    if name == "run_finished":
        chosen = attrs.get("chosen", "none")
        final = "無（未取得 verified_fix）" if chosen in ("none", "None", "") else chosen[:8]
        return [("Result", f"chosen={final}  elapsed={attrs.get('elapsed', '?')}s")]
    return [("Event", f"{name} {event.message}".strip())]


def _failing_stage(result: ValidationResult | BaselineResult) -> str:
    for stage in result.stages:
        if stage.verdict in (StageVerdict.FAIL, StageVerdict.TIMEOUT, StageVerdict.INFRA_ERROR):
            code = f"/{stage.reason_code}" if stage.reason_code else ""
            return f"  （{stage.stage} {stage.verdict.value}{code}）"
    return ""


__all__ = ["render_react_trace"]
