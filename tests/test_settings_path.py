"""Settings panel must render and display the actual vault folder."""
import os
from pathlib import Path

import pytest

SOURCE = Path(__file__).parents[1] / "blackcube" / "app.py"


def test_settings_has_exactly_one_layout_static():
    source = SOURCE.read_text(encoding="utf-8")
    assert 'panel = QFrame()\n        panel.setObjectName("card")\n        form = QFormLayout(panel)' in source
    assert 'directory = str(self.session.directory.resolve())' in source
    assert 'open_storage.clicked.connect(self.open_vault_folder)' in source
    assert 'QDesktopServices.openUrl(QUrl.fromLocalFile(str(folder)))' in source


def test_settings_shows_actual_active_vault_and_open_button(tmp_path):
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    qt = pytest.importorskip("PySide6.QtWidgets")
    from blackcube.app import MainWindow
    from blackcube.vault import create_vault

    app = qt.QApplication.instance() or qt.QApplication([])
    window = MainWindow()
    window.home = tmp_path / "nonstandard" / "vaults"
    window.session = create_vault("Test1", "correct horse battery staple 2026", None, window.home)
    window._unlocked()
    window.navigate("Settings")
    window.show()
    app.processEvents()

    assert window.storage_path.isReadOnly()
    assert window.storage_path.text() == str(window.session.directory.resolve())
    matches = [b for b in window.findChildren(qt.QPushButton) if b.text() == "Open vault folder"]
    assert len(matches) == 1 and matches[0].isVisible()
    cards = [w for w in window.findChildren(qt.QFrame) if w.objectName() == "card"]
    assert any(isinstance(card.layout(), qt.QFormLayout) for card in cards)
    window.close()
