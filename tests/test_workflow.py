from auto_shark.analysis import AnalysisSummary
from auto_shark.body import BodyExtractionSummary
from auto_shark.workflow import BodyRunSummary, BodyTarget, WorkflowSummary, _task_id


def test_body_task_id_is_stable_and_selection_scoped() -> None:
    target = BodyTarget(1, "message", 10, "request", 100, 100, "request-uri:/a")
    assert _task_id("a" * 64, target) == _task_id("a" * 64, target)
    other = BodyTarget(1, "message", 10, "request", 100, 100, "request-uri:/b")
    assert _task_id("a" * 64, target) != _task_id("a" * 64, other)


def test_workflow_json_hides_body_details_by_default() -> None:
    analysis = AnalysisSummary("p", "a" * 64, "t", 1, 1, 1, 1, 0, 0, None, None)
    body = BodyExtractionSummary("p", 1, "request", "complete", 1, 1, False, "b", "p", "e")
    summary = WorkflowSummary(analysis, BodyRunSummary(1, 1, 0, 0, 1, (body,)), None)
    assert '"statuses": []' in summary.to_json()
    assert '"frame_number": 1' in summary.to_json(verbose_bodies=True)
