"""Brand and UI source regression checks; Qt smoke coverage when installed."""
import os
from pathlib import Path
import pytest

ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "blackcube" / "app.py").read_text(encoding="utf-8")


def test_assets_are_bundled_and_svg_is_three_cubes():
    assets = ROOT / "blackcube" / "assets"
    assert (assets / "blackcube.ico").stat().st_size > 1000
    assert (assets / "blackcube-mark-256.png").stat().st_size > 1000
    svg = (assets / "blackcube-mark.svg").read_text(encoding="utf-8")
    assert svg.count('<polygon points=') == 9  # three visible faces per cube
    assert 'viewBox="0 0 256 256"' in svg


def test_dark_native_windows_caption_and_file_page_controls():
    assert 'def apply_windows_dark_caption(' in SOURCE
    assert 'set_attr(20, 1)' in SOURCE
    assert 'set_attr(35, 0x000000)' in SOURCE
    assert 'set_attr(36, 0xFFFFFF)' in SOURCE
    assert 'self.setWindowIcon(QIcon(' in SOURCE
    assert '"Files & Encryption"' in SOURCE
    assert '"Delete source files after verification"' in SOURCE
    for caption in ('"Add files"', '"Add folder"', '"Hash file"',
                    '"Hash folder"', '"Decrypt / Restore selected"',
                    '"Verify against file"', '"Remove record"'):
        assert caption in SOURCE
    assert 'card.show()' in SOURCE
    assert 'self.file_table.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)' in SOURCE


def test_ui_packaged_visuals_and_selection(tmp_path):
    os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')
    qt = pytest.importorskip('PySide6.QtWidgets')
    from blackcube.app import MainWindow
    from blackcube.vault import create_vault

    app = qt.QApplication.instance() or qt.QApplication([])
    window = MainWindow()
    window.home = tmp_path / 'vaults'
    window.session = create_vault('UI test', 'correct horse battery staple 2026', None, window.home)
    src = tmp_path / 'test.txt'
    src.write_text('hello')
    window.session.import_path(src)
    window._unlocked()
    window.show()
    app.processEvents()

    assert window.windowIcon().isNull() is False
    assert window.file_table.columnCount() == 6
    assert window.file_table.rowCount() == 1
    from PySide6.QtCore import Qt
    assert window.file_table.item(0, 0).checkState() == Qt.Unchecked
    assert window.file_table.cellWidget(0, 5) is not None
    assert window.remove_originals.isChecked() is False
    assert window.operation_card.isHidden()
    window.close()
