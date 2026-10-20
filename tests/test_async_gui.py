"""Regressions for worker-thread -> GUI completion crash on Windows.

Requires PySide6; use QT_QPA_PLATFORM=offscreen in CI to avoid a desktop.
"""
import os
import time
from pathlib import Path

import pytest

SOURCE = Path(__file__).parents[1] / 'blackcube' / 'app.py'


def test_no_unowned_worker_lambda_opens_dialog():
    """Always runs, including the dependency-light Linux test environment."""
    source = SOURCE.read_text(encoding='utf-8')
    assert 'self._worker.success.connect(self._on_job_success, Qt.QueuedConnection)' in source
    assert 'self._worker.failure.connect(self._on_job_failure, Qt.QueuedConnection)' in source
    assert 'self._worker.progress.connect(self._progress_changed, Qt.QueuedConnection)' in source
    assert 'self._worker_thread.finished.connect(self._job_thread_finished, Qt.QueuedConnection)' in source
    assert '@Slot(object)\n    def _on_job_success' in source
    assert '@Slot(str)\n    def _on_job_failure' in source
    assert '@Slot()\n    def _report_job_result' in source
    assert 'report.setPlainText' in source
    assert 'QMessageBox.information(self, title, message)' not in source


def test_gui_job_completion_success_hash_and_failure(tmp_path, monkeypatch):
    os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')
    qt = pytest.importorskip('PySide6.QtWidgets')
    from blackcube.app import MainWindow
    from blackcube.vault import create_vault

    app = qt.QApplication.instance() or qt.QApplication([])
    window = MainWindow()
    window.home = tmp_path / 'vaults'
    window.session = create_vault('Async worker test', 'correct horse battery staple 2026', None, window.home)
    window._unlocked()
    window.show()

    def forbidden_modal(*args, **kwargs):
        pytest.fail('Worker result opened a modal dialog')

    monkeypatch.setattr(qt.QMessageBox, 'information', forbidden_modal)

    def wait_for_job():
        end = time.monotonic() + 10
        while time.monotonic() < end:
            app.processEvents()
            if not window._working and window._job_title == '':
                return
            time.sleep(0.005)
        pytest.fail('Background Qt job did not finish')

    window._run_job(lambda _: (1, []), 'Vault import results (check warnings)')
    wait_for_job()
    assert '1 file(s) processed' in window.import_summary.toPlainText()

    window._run_job(lambda _: 'MATCH — digest identical', 'Hash verification')
    wait_for_job()
    assert 'MATCH' in window.import_summary.toPlainText()

    def fail_job(_):
        raise ValueError('Expected test failure')

    window._run_job(fail_job, 'Hash verification')
    wait_for_job()
    assert 'Expected test failure' in window.import_summary.toPlainText()
    assert not window._working
    window.close()
    app.processEvents()
