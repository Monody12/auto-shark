"""Threaded execution of bounded analysis stages and exports."""

from __future__ import annotations

import json
from typing import Optional

from PySide6.QtCore import QThread, Signal

from .services import AnalysisStage


def stage_summary_json(result: object) -> str:
    to_json = getattr(result, "to_json", None)
    if callable(to_json):
        return to_json()
    return json.dumps(result, ensure_ascii=False, sort_keys=True, default=str)


class StageWorker(QThread):
    """Run bounded stages sequentially with cooperative between-stage cancel.

    A failing stage is recorded and the remaining stages still run: partial
    results from the other analyzers are more useful to a CTF player than an
    aborted pipeline with empty pages. The final ``finished_run`` message
    lists both completed and failed stages so the UI can summarize them.
    """

    stage_started = Signal(str)
    stage_finished = Signal(str, str)
    stage_failed = Signal(str, str)
    finished_run = Signal(bool, str)

    def __init__(self, stages: list[AnalysisStage], parent=None) -> None:
        super().__init__(parent)
        self._stages = stages
        self._cancelled = False

    def cancel(self) -> None:
        self._cancelled = True

    @property
    def cancelled(self) -> bool:
        return self._cancelled

    def run(self) -> None:  # pragma: no cover - exercised through widget tests
        completed: list[str] = []
        failed: list[str] = []
        for stage in self._stages:
            if self._cancelled:
                self.finished_run.emit(
                    False,
                    "cancelled; completed stages: "
                    + (", ".join(completed) if completed else "none"),
                )
                return
            self.stage_started.emit(stage.title)
            try:
                summary = stage_summary_json(stage.run())
            except Exception as error:  # noqa: BLE001 - surfaced verbatim to the UI
                failed.append(f"{stage.key}: {error}")
                self.stage_failed.emit(stage.key, str(error))
                continue
            completed.append(stage.key)
            self.stage_finished.emit(stage.key, summary)
        message = "completed stages: " + (", ".join(completed) or "none")
        if failed:
            message += "; failed stages: " + "; ".join(failed)
        self.finished_run.emit(not failed, message)


class SingleRunWorker(QThread):
    """Run one bounded callable off the UI thread and report its JSON result."""

    succeeded = Signal(str)
    failed = Signal(str)

    def __init__(self, runnable, parent=None) -> None:
        super().__init__(parent)
        self._runnable = runnable

    def run(self) -> None:  # pragma: no cover - exercised through widget tests
        try:
            self.succeeded.emit(stage_summary_json(self._runnable()))
        except Exception as error:  # noqa: BLE001 - surfaced verbatim to the UI
            self.failed.emit(str(error))


def active_worker(worker: Optional[QThread]) -> bool:
    return worker is not None and worker.isRunning()
