"""Scrolling and minimal interface regression tests."""
import os
from pathlib import Path

import pytest

SOURCE = Path(__file__).parents[1] / "blackcube" / "app.py"


def test_files_panel_has_one_layout_and_a_scrolling_page():
    # Static checks remain meaningful on environments without Qt.
    source = SOURCE.read_text(encoding="utf-8")
    assert 'hero = HeroPanel()' in source
    assert 'hero_layout = QHBoxLayout(hero)' in source
    assert 'control_layout = QVBoxLayout(controls)' in source
    assert 'scroll = QScrollArea()' in source
    assert 'scroll.setWidgetResizable(True)' in source
    assert 'scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)' in source
    assert 'self.page_views[key] = scroll' in source
    assert 'self.pages.setCurrentWidget(self.page_views[key])' in source
    assert 'self.file_table.setMinimumHeight(280)' in source
    assert 'self.file_table.setMaximumHeight(440)' in source


def test_marketing_labels_are_gone():
    source = SOURCE.read_text(encoding="utf-8")
    for phrase in (
        "PRIVATE WORKSPACE", "LOCAL ONLY", "YOUR DATA. YOUR KEYS.",
        "OFFLINE  •  NO CLOUD", "ENCRYPTED FILE INDEX", "FILE PROTECTION",
        "NOTHING HERE. YET.",
    ):
        assert phrase not in source


def test_controls_visible_and_page_scrollable_at_small_window(tmp_path):
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    qt = pytest.importorskip("PySide6.QtWidgets")
    from blackcube.app import MainWindow
    from blackcube.vault import create_vault

    app = qt.QApplication.instance() or qt.QApplication([])
    window = MainWindow()
    window.home = tmp_path / "vaults"
    window.session = create_vault("Layout smoke test", "correct horse battery staple 2026", None, window.home)
    window.resize(850, 540)
    window._unlocked()
    window.show()
    app.processEvents()

    for caption in ("Add files", "Add folder", "Hash file", "Hash folder",
                    "Decrypt / Restore selected", "Verify against file", "Remove record"):
        matches = [b for b in window.findChildren(qt.QPushButton) if b.text() == caption]
        assert len(matches) == 1, caption
        assert matches[0].isVisible() and matches[0].height() > 15, caption

    scroll = window.page_views["Files"]
    assert isinstance(scroll, qt.QScrollArea)
    assert scroll.verticalScrollBar().maximum() > 0, "Files page must scroll on smaller windows"
    scroll.verticalScrollBar().setValue(scroll.verticalScrollBar().maximum())
    app.processEvents()
    assert scroll.verticalScrollBar().value() > 0
    window.close()
