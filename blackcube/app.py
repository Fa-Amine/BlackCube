"""BlackCube Qt desktop interface."""
from __future__ import annotations

import os
import sys
from pathlib import Path

from importlib.resources import files as resource_files

from PySide6.QtCore import QObject, QEvent, QThread, QTimer, Qt, Signal, Slot, QUrl
from PySide6.QtGui import QFont, QDesktopServices, QIcon, QPixmap, QPainter, QColor
from PySide6.QtWidgets import (
    QAbstractItemView, QApplication, QCheckBox, QComboBox, QDialog, QDialogButtonBox,
    QFileDialog, QFormLayout, QFrame, QGridLayout, QHBoxLayout, QHeaderView,
    QLabel, QLineEdit, QMainWindow, QMessageBox, QProgressBar, QPushButton, QInputDialog,
    QScrollArea, QSizePolicy, QStackedWidget, QTableWidget, QToolButton, QMenu,
    QTableWidgetItem, QTextEdit, QVBoxLayout, QWidget,
)

from .crypto import VaultError, HASHES, NEW_CIPHERS
from .portable import encrypt_standalone, decrypt_standalone, generate_portable_keyfile
from .recovery import create_backup, import_verified_backup, backup_unlock_mode, verify_backup
from .health import check_vault, quarantine_uncommitted
from .vault import (VaultSession, create_vault, default_home, generate_password,
                    list_vault_dirs, open_vault, _read_config)

STYLE = """
QWidget { color: #f3f3f3; background-color: #0b0c0e; font-family: 'Segoe UI', Arial; font-size: 13px; }
QMainWindow, QDialog { background-color: #0b0c0e; }
QLabel { background: transparent; }
QFrame#side { background-color: #101113; border-right: 1px solid #292a2d; }
QFrame#card { background-color: #131416; border: 1px solid #323337; border-radius: 11px; }
QFrame#hero { background-color: #111214; border: 1px solid #292b2f; border-radius: 13px; }
QWidget#heroControls { background: transparent; }
QFrame#operationCard { background-color: #17181b; border: 1px solid #36383a; border-radius: 9px; }
QFrame#tableCard { background-color: #111214; border: 1px solid #333437; border-radius: 10px; }
QLabel#brand { font-size: 19px; font-weight: 700; color: #ffffff; }
QLabel#heading { font-size: 26px; font-weight: 700; color: white; }
QLabel#section-heading { font-size: 15px; font-weight: 600; }
QLabel#subheading { color: #b7b9bd; font-size: 13px; }
QLabel#muted { color: #a5a7ab; font-size: 12px; }
QLabel#status { color: #aeb0b4; font-size: 12px; }
QPushButton { background-color: #27282a; border: 1px solid #494a4d; padding: 10px 13px; border-radius: 7px; font-weight: 500; min-height: 16px; }
QPushButton:hover { background-color: #343538; border-color: #77797c; }
QPushButton:pressed { background-color: #3d3e41; }
QPushButton:disabled { color: #707176; background-color: #1c1d1f; border-color: #303135; }
QPushButton#primary { background-color: #333437; color: #ffffff; border-color: #6a6c70; font-weight: 600; }
QPushButton#primary:hover { background-color: #44464a; }
QPushButton#nav { text-align: left; padding: 13px 15px; border: 0; border-radius: 7px; background-color: transparent; color: #c1c2c5; font-size: 14px; }
QPushButton#nav:hover { background-color: #252629; color: white; }
QPushButton#nav:checked { background-color: #313235; color: white; font-weight: 600; }
QLineEdit, QTextEdit, QComboBox, QSpinBox { background-color: #1b1c1f; border: 1px solid #3c3d40; border-radius: 7px; padding: 9px; selection-background-color: #6e7074; }
QLineEdit:focus, QTextEdit:focus, QComboBox:focus { border-color: #dadada; }
QCheckBox { spacing: 9px; background: transparent; }
QCheckBox::indicator { width: 17px; height: 17px; }
QTableWidget { border: 0; background-color: #111214; gridline-color: transparent; alternate-background-color: #151619; }
QTableWidget::item { padding: 6px; border-bottom: 1px solid #242527; }
QTableWidget::item:selected { background-color: #323438; color: white; }
QHeaderView::section { background-color: #202124; color: #d3d4d6; padding: 10px 6px; font-weight: 600; border: none; border-bottom: 1px solid #38393c; }
QToolButton#rowMenu { background-color: transparent; color: #c5c5c5; border: 0; font-size: 16px; padding: 5px; }
QToolButton#rowMenu:hover { background-color: #333437; border-radius: 5px; }
QMenu { background-color: #212225; color: white; border: 1px solid #55565a; padding: 5px; }
QMenu::item { padding: 7px 25px; }
QMenu::item:selected { background-color: #404145; }
QTextEdit#operation-report { border: 0; background: transparent; color: #c5c7cb; padding: 0; }
QProgressBar { border: 1px solid #35363c; border-radius: 4px; height: 8px; background-color: #25262a; text-align: center; color: transparent; }
QProgressBar::chunk { background-color: #dedee0; border-radius: 3px; }
QScrollArea, QScrollArea > QWidget > QWidget { border: none; }
QScrollBar:vertical { width: 10px; background-color: #111214; margin: 0; }
QScrollBar::handle:vertical { background-color: #45474a; min-height: 36px; border-radius: 4px; margin: 2px; }
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }
QToolTip { background-color: #292a2e; color: #fff; border: 1px solid #555; }
"""


def label(text: str, style: str | None = None) -> QLabel:
    w = QLabel(text)
    w.setWordWrap(True)
    if style:
        w.setObjectName(style)
    return w


def button(text: str, primary=False) -> QPushButton:
    w = QPushButton(text)
    w.setCursor(Qt.PointingHandCursor)
    if primary:
        w.setObjectName("primary")
    return w


def card(layout=None) -> QFrame:
    c = QFrame()
    c.setObjectName("card")
    c.setLayout(layout or QVBoxLayout())
    return c


def clear_layout(layout):
    while layout.count():
        child = layout.takeAt(0)
        if child.widget():
            child.widget().deleteLater()
        elif child.layout():
            clear_layout(child.layout())


def table(columns: list[str]) -> QTableWidget:
    w = QTableWidget(0, len(columns))
    w.setHorizontalHeaderLabels(columns)
    w.setAlternatingRowColors(True)
    w.setSelectionBehavior(QTableWidget.SelectRows)
    w.setSelectionMode(QTableWidget.SingleSelection)
    w.setEditTriggers(QTableWidget.NoEditTriggers)
    w.verticalHeader().hide()
    w.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
    w.verticalHeader().setDefaultSectionSize(45)
    return w


def brand_asset(filename: str) -> Path:
    """Find logo assets in source installs and PyInstaller one-file builds."""
    # PyInstaller unpacks --add-data files under _MEIPASS. A package-local
    # lookup also works in both regular source and recent PyInstaller builds.
    candidates = [Path(__file__).resolve().parent / "assets" / filename]
    if getattr(sys, "_MEIPASS", None):
        candidates.append(Path(sys._MEIPASS) / "blackcube" / "assets" / filename)
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    return Path(str(resource_files("blackcube").joinpath("assets", filename)))


def configure_windows_app_id() -> None:
    """Assign a stable Windows taskbar identity before creating QApplication."""
    if sys.platform != "win32":
        return
    try:
        import ctypes
        # A stable explicit AppUserModelID prevents generic Python grouping.
        # For a packaged exe, the shell/taskbar uses this ID and the exe icon.
        shell = ctypes.windll.shell32
        shell.SetCurrentProcessExplicitAppUserModelID.argtypes = [ctypes.c_wchar_p]
        shell.SetCurrentProcessExplicitAppUserModelID.restype = ctypes.c_long
        shell.SetCurrentProcessExplicitAppUserModelID("BlackCube.Desktop")
    except (OSError, AttributeError, ValueError):
        # Unsupported Windows environments should still launch BlackCube.
        pass


def apply_windows_dark_caption(window: QMainWindow) -> None:
    """Dark Windows 10/11 native titlebar, preserving system snap/resize behavior."""
    if sys.platform != "win32":
        return
    try:
        import ctypes
        from ctypes import wintypes
        hwnd = wintypes.HWND(int(window.winId()))
        dwm = ctypes.windll.dwmapi
        def set_attr(attr, value):
            data = ctypes.c_int(value)
            dwm.DwmSetWindowAttribute(hwnd, attr, ctypes.byref(data), ctypes.sizeof(data))
        # 20 is the modern DWMWA_USE_IMMERSIVE_DARK_MODE; 19 on older builds.
        set_attr(20, 1)
        set_attr(19, 1)
        # COLORREF is 0x00BBGGRR. Black caption, white caption text.
        set_attr(35, 0x000000)
        set_attr(36, 0xFFFFFF)
        set_attr(34, 0x202020)
    except (OSError, ValueError, AttributeError):
        # Older Windows builds can simply retain the native titlebar.
        pass


class HeroPanel(QFrame):
    """Single passive watermark; it never obstructs the active controls."""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("hero")
        self._mark = QPixmap(str(brand_asset("blackcube-mark-512.png")))

    def paintEvent(self, event):
        super().paintEvent(event)
        if not self._mark.isNull() and self.width() >= 840:
            painter = QPainter(self)
            painter.setOpacity(0.095)
            size = min(225, self.height() - 32)
            painter.drawPixmap(self.width() - size - 29, (self.height() - size) // 2,
                               self._mark.scaled(size, size, Qt.KeepAspectRatio,
                                                 Qt.SmoothTransformation))
            painter.end()


class CreateDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("New encrypted project")
        self.setMinimumWidth(430)
        content = QVBoxLayout(self)
        content.setSpacing(15)
        content.addWidget(label("New vault", "section-heading"))
        content.addWidget(label("Each vault has its own encryption key.", "subheading"))
        form = QFormLayout()
        self.name = QLineEdit()
        self.name.setPlaceholderText("e.g. Research archive")
        self.password = QLineEdit()
        self.password.setEchoMode(QLineEdit.Password)
        self.password.setPlaceholderText("At least 12 characters")
        self.confirm = QLineEdit()
        self.confirm.setEchoMode(QLineEdit.Password)
        self.location = QLineEdit(str(default_home()))
        location_btn = button("Browse...")
        def pick_location():
            folder = QFileDialog.getExistingDirectory(self, "Choose vault storage location")
            if folder:
                self.location.setText(folder)
        location_btn.clicked.connect(pick_location)
        location_row = QHBoxLayout()
        location_row.addWidget(self.location, 1)
        location_row.addWidget(location_btn)
        self.profile = QComboBox()
        self.profile.addItems(["ML-KEM-768 (recommended)", "ML-KEM-512", "ML-KEM-1024", "Classical AES only"])
        form.addRow("Project name", self.name)
        form.addRow("Master passphrase", self.password)
        form.addRow("Confirm", self.confirm)
        form.addRow("Post-quantum keys", self.profile)
        form.addRow("Vault storage folder", location_row)
        content.addLayout(form)
        content.addWidget(label("Keep a safe backup of your vault folder and passphrase. There is no password recovery.", "subheading"))
        actions = QDialogButtonBox(QDialogButtonBox.Cancel | QDialogButtonBox.Ok)
        actions.button(QDialogButtonBox.Ok).setText("Create encrypted vault")
        actions.accepted.connect(self.accept)
        actions.rejected.connect(self.reject)
        content.addWidget(actions)

    def accept(self):
        if len(self.password.text()) < 12 or self.password.text() != self.confirm.text() or not self.name.text().strip():
            QMessageBox.warning(self, "Check details", "Add a project name and matching passphrases of at least 12 characters.")
            return
        super().accept()

    def selected_location(self):
        return Path(self.location.text()).expanduser()

    def selected_profile(self):
        return {0: "ML-KEM-768", 1: "ML-KEM-512", 2: "ML-KEM-1024", 3: None}[self.profile.currentIndex()]


class AccountDialog(QDialog):
    def __init__(self, parent=None, row=None):
        super().__init__(parent)
        self.setWindowTitle("Encrypted account entry")
        self.setMinimumWidth(470)
        layout = QVBoxLayout(self)
        layout.addWidget(label("Account details", "section-heading"))
        form = QFormLayout()
        self.title = QLineEdit(row["title"] if row else "")
        self.username = QLineEdit(row["username"] if row else "")
        self.url = QLineEdit(row.get("url", "") if row else "")
        self.password = QLineEdit(row["password"] if row else "")
        self.password.setEchoMode(QLineEdit.Password)
        self.notes = QTextEdit(row.get("notes", "") if row else "")
        self.notes.setMaximumHeight(90)
        pwd_row = QHBoxLayout()
        pwd_row.addWidget(self.password)
        generate = button("Generate")
        generate.clicked.connect(lambda: self.password.setText(generate_password(24)))
        pwd_row.addWidget(generate)
        show = QCheckBox("Show password")
        show.toggled.connect(lambda checked: self.password.setEchoMode(
            QLineEdit.Normal if checked else QLineEdit.Password))
        form.addRow("Name", self.title)
        form.addRow("Login / email", self.username)
        form.addRow("Website", self.url)
        form.addRow("Password", pwd_row)
        form.addRow("", show)
        form.addRow("Notes", self.notes)
        layout.addLayout(form)
        actions = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        actions.accepted.connect(self.accept)
        actions.rejected.connect(self.reject)
        layout.addWidget(actions)

    def accept(self):
        if not self.title.text().strip() or not self.password.text():
            QMessageBox.warning(self, "Missing fields", "Account name and password are required.")
            return
        super().accept()


class JobWorker(QObject):
    success = Signal(object)
    failure = Signal(str)
    progress = Signal(int, int, str)
    finished = Signal()

    def __init__(self, action):
        super().__init__()
        self.action = action

    @Slot()
    def run(self):
        try:
            result = self.action(self.progress.emit)
            self.success.emit(result)
        except Exception as exc:
            # UI displays error only; no keys/passphrases in logs.
            self.failure.emit(str(exc))
        finally:
            self.finished.emit()


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("BlackCube")
        self.resize(1350, 850)
        self.setMinimumSize(820, 540)
        self.setWindowIcon(QIcon(str(brand_asset("blackcube.ico"))))
        self.session: VaultSession | None = None
        self._working = False
        self._worker_thread = None
        self._worker = None
        self._job_title = ""
        self._job_result = None
        self._job_failure = None
        self._busy_controls = []
        self._job_return_page = "Files"
        self.home = default_home()
        self._known_homes = {self.home.resolve()}
        self._locations_file = self.home.parent / "locations.json"
        self._load_known_homes()
        self._navigation = {}
        self._session_notice_registered = False
        self._lock_after_job = False

        root = QWidget()
        self.setCentralWidget(root)
        shell = QHBoxLayout(root)
        shell.setSpacing(0)
        shell.setContentsMargins(0, 0, 0, 0)
        sidebar = QFrame()
        sidebar.setObjectName("side")
        sidebar.setFixedWidth(230)
        nav = QVBoxLayout(sidebar)
        nav.setContentsMargins(18, 22, 18, 20)
        nav.setSpacing(9)
        brand_row = QHBoxLayout()
        self.brand_icon = QLabel()
        self.brand_icon.setPixmap(QPixmap(str(brand_asset("blackcube-mark-64.png"))).scaled(
            38, 38, Qt.KeepAspectRatio, Qt.SmoothTransformation))
        self.brand_icon.setFixedSize(42, 42)
        brand_row.addWidget(self.brand_icon)
        brand_row.addWidget(label("BlackCube", "brand"), 1)
        nav.addLayout(brand_row)
        nav.addSpacing(37)
        for page, display in (("Projects", "Vaults"), ("Files", "Files"),
                              ("Standalone", "Standalone encryption"),
                              ("Accounts", "Passwords"), ("Integrity", "Integrity"),
                              ("Settings", "Settings")):
            w = QPushButton(display)
            w.setObjectName("nav")
            w.setCheckable(True)
            w.clicked.connect(lambda _, p=page: self.navigate(p))
            nav.addWidget(w)
            self._navigation[page] = w
        nav.addStretch()
        nav.addWidget(label("Current vault", "muted"))
        self.active_name = label("Locked", "subheading")
        nav.addWidget(self.active_name)
        self.lock_btn = button("Lock vault")
        self.lock_btn.clicked.connect(self.lock)
        self.lock_btn.setEnabled(False)
        nav.addWidget(self.lock_btn)
        shell.addWidget(sidebar)

        body = QWidget()
        body_layout = QVBoxLayout(body)
        body_layout.setContentsMargins(26, 15, 24, 18)
        body_layout.setSpacing(12)
        top = QHBoxLayout()
        top.addStretch()
        self.status = label("Ready", "status")
        top.addWidget(self.status)
        body_layout.addLayout(top)
        self.pages = QStackedWidget()
        body_layout.addWidget(self.pages, 1)
        self.page_widgets = {}
        self.page_views = {}
        for key in self._navigation:
            # Each view has a dedicated vertical scrollbar. The original
            # stacked pages were non-scrolling and clipped controls and tables
            # below the Windows taskbar on smaller displays.
            content = QWidget()
            content.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)
            scroll = QScrollArea()
            scroll.setWidgetResizable(True)
            scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
            scroll.setFrameShape(QFrame.NoFrame)
            scroll.setWidget(content)
            self.page_widgets[key] = content
            self.page_views[key] = scroll
            self.pages.addWidget(scroll)
        shell.addWidget(body, 1)

        self.auto_lock = QTimer(self)
        self.auto_lock.setSingleShot(True)
        from PySide6.QtCore import QSettings
        self._user_settings = QSettings("BlackCube", "BlackCube")
        lock_minutes = self._user_settings.value("auto_lock_minutes", 5, type=int)
        if lock_minutes not in (1, 5, 10, 30):
            lock_minutes = 5
        self.auto_lock.setInterval(lock_minutes * 60 * 1000)
        self.auto_lock.timeout.connect(self.lock)
        QApplication.instance().installEventFilter(self)
        self.navigate("Projects")
        if os.name == "nt":
            QTimer.singleShot(0, self._register_windows_session_notifications)

    def _register_windows_session_notifications(self):
        """Ask Windows to deliver lock/disconnect events to the main window."""
        if os.name != "nt":
            return
        try:
            import ctypes
            self._session_notice_registered = bool(ctypes.windll.wtsapi32.WTSRegisterSessionNotification(
                int(self.winId()), 0))
        except (OSError, AttributeError, ValueError):
            self._session_notice_registered = False

    def nativeEvent(self, event_type, message):
        if os.name == "nt":
            try:
                import ctypes
                from ctypes import wintypes
                msg = ctypes.cast(int(message), ctypes.POINTER(wintypes.MSG)).contents
                if msg.message == 0x02B1 and msg.wParam in (0x7, 0x2, 0x4):
                    QTimer.singleShot(0, self._lock_for_system_event)
                elif msg.message == 0x0218 and msg.wParam == 0x0004:
                    QTimer.singleShot(0, self._lock_for_system_event)
            except (OSError, AttributeError, ValueError, TypeError):
                pass
        return super().nativeEvent(event_type, message)

    def _lock_for_system_event(self):
        if self._working:
            # Workers cannot be abruptly killed without risking data loss.
            self._lock_after_job = True
            self.status.setText("Windows locked — vault will lock after operation")
        elif self.session:
            self.lock()

    def eventFilter(self, obj, event):
        if self.session and event.type() in (QEvent.KeyPress, QEvent.MouseButtonPress):
            self.auto_lock.start()
        return super().eventFilter(obj, event)

    def _layout(self, key):
        container = self.page_widgets[key]
        if container.layout():
            clear_layout(container.layout())
            return container.layout()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(0, 8, 10, 16)
        layout.setSpacing(15)
        return layout

    def navigate(self, key):
        if self._working:
            return
        if key not in ("Projects", "Standalone") and not self.session:
            QMessageBox.information(self, "Unlock a vault", "Create or unlock a vault first.")
            key = "Projects"
        for name, w in self._navigation.items():
            w.setChecked(name == key)
        if key == "Projects":
            self.show_projects()
        elif key == "Files":
            self.show_files()
        elif key == "Standalone":
            self.show_standalone()
        elif key == "Accounts":
            self.show_accounts()
        elif key == "Integrity":
            self.show_integrity()
        elif key == "Settings":
            self.show_settings()
        self.pages.setCurrentWidget(self.page_views[key])
        self.page_views[key].verticalScrollBar().setValue(0)

    def _header(self, layout, title, subtitle, action=None):
        header = QHBoxLayout()
        text = QVBoxLayout()
        text.addWidget(label(title, "heading"))
        if subtitle:
            text.addWidget(label(subtitle, "subheading"))
        header.addLayout(text)
        header.addStretch()
        if action:
            header.addWidget(action)
        layout.addLayout(header)

    def show_projects(self):
        layout = self._layout("Projects")
        new_btn = button("New vault", primary=True)
        new_btn.clicked.connect(self.create_dialog)
        self._header(layout, "Vaults", "Create or open an encrypted vault.", new_btn)
        tools = QHBoxLayout()
        add_existing = button("Register vault folder")
        add_existing.clicked.connect(self.register_vault_location)
        tools.addWidget(add_existing)
        backup_restore = button("Import encrypted vault backup")
        backup_restore.clicked.connect(self.restore_vault_backup)
        tools.addWidget(backup_restore)
        tools.addStretch()
        layout.addLayout(tools)
        if self.session:
            banner = card()
            banner.layout().setContentsMargins(22, 22, 22, 22)
            banner.layout().addWidget(label("Current vault", "section-heading"))
            banner.layout().addWidget(label(self.session.name, "heading"))
            banner.layout().addWidget(label(f"{len(self.session.entries)} files · {len(self.session.accounts)} saved accounts", "subheading"))
            go = button("View files", primary=True)
            go.clicked.connect(lambda: self.navigate("Files"))
            banner.layout().addWidget(go, alignment=Qt.AlignLeft)
            layout.addWidget(banner)
        layout.addWidget(label("Saved vaults", "section-heading"))
        content_layout = QVBoxLayout()
        content_layout.setSpacing(10)
        vaults = sorted({folder for home in self._known_homes for folder in list_vault_dirs(home)})
        if not vaults:
            empty = card()
            empty.layout().setContentsMargins(26, 25, 26, 25)
            empty.layout().addWidget(label("No vaults yet", "section-heading"))
            empty.layout().addWidget(label("Create a vault to store encrypted files and passwords.", "subheading"))
            content_layout.addWidget(empty)
        for folder in vaults:
            item = QFrame()
            item.setObjectName("card")
            r = QHBoxLayout(item)
            r.setContentsMargins(20, 17, 20, 17)
            info = QVBoxLayout()
            unlocked = self.session and self.session.directory == folder
            info.addWidget(label(self.session.name if unlocked else "Vault " + folder.name[:8]))
            info.addWidget(label("Unlocked" if unlocked else "Locked", "subheading"))
            r.addLayout(info, 1)
            unlock_btn = button("Open" if unlocked else "Unlock")
            unlock_btn.clicked.connect(lambda _, p=folder: self.open_dialog(p))
            r.addWidget(unlock_btn)
            content_layout.addWidget(item)
        layout.addLayout(content_layout)
        layout.addStretch()

    def create_dialog(self):
        d = CreateDialog(self)
        if d.exec() != QDialog.Accepted:
            return
        try:
            selected_home = d.selected_location()
            self.session = create_vault(d.name.text(), d.password.text(), d.selected_profile(), selected_home)
            self._register_home(selected_home)
            self._unlocked()
        except Exception as exc:
            self._error("Could not create vault", str(exc))

    def _credentials_dialog(self, title: str, directory: Path | None = None,
                            mode_override: str | None = None) -> tuple[str | None, Path | None] | None:
        """Build a credential prompt respecting the stored mandatory-factor policy."""
        config = _read_config(directory) if directory else (self.session.config if self.session else {})
        mode = mode_override or config.get("unlock_mode", "either")
        dialog = QDialog(self)
        dialog.setWindowTitle(title)
        dialog.setMinimumWidth(480)
        layout = QVBoxLayout(dialog)
        layout.addWidget(label("Vault authentication", "section-heading"))
        descriptions = {"either": "Enter your passphrase or use your recovery key file.",
                        "passphrase": "Enter the vault passphrase.",
                        "keyfile": "Select the generated key file. A passphrase cannot unlock this vault.",
                        "both": "Both your passphrase AND generated key file are required."}
        layout.addWidget(label(descriptions.get(mode, "Unsupported vault authentication policy"), "subheading"))
        if mode not in descriptions:
            raise VaultError("Unsupported authentication policy")
        selector = QComboBox()
        selector.addItems(["Master passphrase", "Key file (.bckey)"])
        if mode == "either":
            layout.addWidget(selector)
        password = QLineEdit()
        password.setPlaceholderText("Master passphrase")
        password.setEchoMode(QLineEdit.Password)
        layout.addWidget(password)
        key_row = QHBoxLayout()
        key_path = QLineEdit()
        key_path.setPlaceholderText("Choose the .bckey file")
        browse = button("Browse…")
        def choose_key():
            selected, _ = QFileDialog.getOpenFileName(dialog, "Choose generated key file",
                                                    "", "BlackCube key files (*.bckey);;All files (*)")
            if selected:
                key_path.setText(selected)
        browse.clicked.connect(choose_key)
        key_row.addWidget(key_path, 1)
        key_row.addWidget(browse)
        layout.addLayout(key_row)
        def switch():
            show_password = mode in ("passphrase", "both") or (mode == "either" and selector.currentIndex() == 0)
            show_key = mode in ("keyfile", "both") or (mode == "either" and selector.currentIndex() == 1)
            password.setVisible(show_password)
            key_path.setVisible(show_key)
            browse.setVisible(show_key)
        selector.currentIndexChanged.connect(switch)
        switch()
        actions = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        actions.accepted.connect(dialog.accept)
        actions.rejected.connect(dialog.reject)
        layout.addWidget(actions)
        if dialog.exec() != QDialog.Accepted:
            return None
        wants_pass = mode in ("passphrase", "both") or (mode == "either" and selector.currentIndex() == 0)
        wants_file = mode in ("keyfile", "both") or (mode == "either" and selector.currentIndex() == 1)
        if wants_pass and not password.text():
            raise VaultError("Enter your master passphrase")
        if wants_file and not key_path.text():
            raise VaultError("Select your generated key file")
        return (password.text() if wants_pass else None,
                Path(key_path.text()) if wants_file else None)

    def open_dialog(self, folder: Path):
        if self.session and self.session.directory == folder:
            self.navigate("Files")
            return
        try:
            credential = self._credentials_dialog("Unlock vault", folder)
            if credential is None:
                return
            password, key_file = credential
            self.session = open_vault(folder, password=password, key_file=key_file)
            self._unlocked()
        except Exception as exc:
            self._error("Unlock failed", str(exc))

    def _unlocked(self):
        self.lock_btn.setEnabled(True)
        self.active_name.setText(self.session.name)
        self.auto_lock.start()
        self.navigate("Files")

    def lock(self):
        if self._working:
            self.auto_lock.start()
            return
        self.auto_lock.stop()
        self.session = None
        self.lock_btn.setEnabled(False)
        self.active_name.setText("Locked")
        self.navigate("Projects")

    def show_files(self):
        layout = self._layout("Files")
        layout.setSpacing(14)
        self._header(layout, "Files & Encryption",
                     "Encrypt, restore, and verify files in the active vault.")

        hero = HeroPanel()
        hero_layout = QHBoxLayout(hero)
        hero_layout.setContentsMargins(22, 18, 18, 18)
        hero_layout.setSpacing(14)
        controls = QWidget()
        controls.setObjectName("heroControls")
        controls.setMaximumWidth(790)
        control_layout = QVBoxLayout(controls)
        control_layout.setContentsMargins(0, 0, 0, 0)
        control_layout.setSpacing(13)

        params = QHBoxLayout()
        params.setSpacing(17)
        encryption = QVBoxLayout()
        encryption.setSpacing(6)
        encryption.addWidget(label("Encryption mode", "muted"))
        self.mode = QComboBox()
        self.mode.addItems(["AES-256-GCM", "ChaCha20-Poly1305", "AES-192-GCM", "AES-128-GCM"])
        if self.session.profile:
            self.mode.addItem("Hybrid " + self.session.profile + " + X25519")
        encryption.addWidget(self.mode)
        params.addLayout(encryption, 1)

        digest = QVBoxLayout()
        digest.setSpacing(6)
        digest.addWidget(label("Digest algorithm", "muted"))
        self.hash_mode = QComboBox()
        self.hash_mode.addItems(list(HASHES))
        digest.addWidget(self.hash_mode)
        params.addLayout(digest, 1)
        control_layout.addLayout(params)

        actions = QGridLayout()
        actions.setHorizontalSpacing(9)
        actions.setVerticalSpacing(8)
        encrypt_file_btn = button("Add files", primary=True)
        encrypt_file_btn.clicked.connect(lambda: self.start_import(False, False))
        encrypt_folder_btn = button("Add folder")
        encrypt_folder_btn.clicked.connect(lambda: self.start_import(True, False))
        hash_file_btn = button("Hash file")
        hash_file_btn.clicked.connect(lambda: self.start_import(False, True))
        hash_folder_btn = button("Hash folder")
        hash_folder_btn.clicked.connect(lambda: self.start_import(True, True))
        import_buttons = (encrypt_file_btn, encrypt_folder_btn, hash_file_btn, hash_folder_btn)
        for index, control in enumerate(import_buttons):
            actions.addWidget(control, 0, index)
            actions.setColumnStretch(index, 1)
        control_layout.addLayout(actions)
        self.remove_originals = QCheckBox("Delete source files after verification")
        self.remove_originals.setChecked(False)
        self.remove_originals.setToolTip(
            "Only after encrypted readback verification. Not secure erasure. Keep independent backups.")
        control_layout.addWidget(self.remove_originals)
        hero_layout.addWidget(controls, 1)
        layout.addWidget(hero)

        self.operation_card = QFrame()
        self.operation_card.setObjectName("operationCard")
        report_layout = QHBoxLayout(self.operation_card)
        report_layout.setContentsMargins(20, 13, 20, 13)
        report_icon = QLabel("✓")
        report_icon.setStyleSheet("font-size: 19px; color: #dedede;")
        report_icon.setFixedWidth(26)
        report_layout.addWidget(report_icon)
        self.import_summary = QTextEdit()
        self.import_summary.setObjectName("operation-report")
        self.import_summary.setReadOnly(True)
        self.import_summary.setFrameShape(QFrame.NoFrame)
        self.import_summary.setMinimumHeight(47)
        self.import_summary.setMaximumHeight(100)
        report_layout.addWidget(self.import_summary, 1)
        self.operation_card.hide()
        layout.addWidget(self.operation_card)

        index_card = QFrame()
        index_card.setObjectName("tableCard")
        index_layout = QVBoxLayout(index_card)
        index_layout.setContentsMargins(0, 0, 0, 0)
        index_layout.setSpacing(0)
        self.file_table = table(["", "Path", "Protection", "Size", "Added", ""])
        self.file_table.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self.file_table.verticalHeader().setDefaultSectionSize(40)
        self.file_table.setMinimumHeight(280)
        self.file_table.setMaximumHeight(440)
        self.file_table.setShowGrid(False)
        file_header = self.file_table.horizontalHeader()
        file_header.setSectionResizeMode(0, QHeaderView.Fixed)
        file_header.setSectionResizeMode(1, QHeaderView.Stretch)
        file_header.setSectionResizeMode(2, QHeaderView.ResizeToContents)
        file_header.setSectionResizeMode(3, QHeaderView.ResizeToContents)
        file_header.setSectionResizeMode(4, QHeaderView.ResizeToContents)
        file_header.setSectionResizeMode(5, QHeaderView.Fixed)
        self.file_table.setColumnWidth(0, 42)
        self.file_table.setColumnWidth(5, 40)
        self.file_table.setHorizontalScrollMode(QTableWidget.ScrollPerPixel)
        self.file_table.setWordWrap(False)
        self.file_ids = []
        for entry in self.session.entries:
            row = self.file_table.rowCount()
            self.file_table.insertRow(row)
            entry_id = entry["id"]
            self.file_ids.append(entry_id)
            check = QTableWidgetItem("")
            check.setFlags(Qt.ItemIsEnabled | Qt.ItemIsSelectable | Qt.ItemIsUserCheckable)
            check.setCheckState(Qt.Unchecked)
            self.file_table.setItem(row, 0, check)
            values = (entry["path"], entry["mode"],
                      self._fmt_bytes(entry["bytes"]), entry["added_at"][:16].replace("T", " "))
            for offset, value in enumerate(values, start=1):
                item = QTableWidgetItem(str(value))
                if offset == 1:
                    item.setToolTip(str(value))
                self.file_table.setItem(row, offset, item)
            menu_button = QToolButton()
            menu_button.setObjectName("rowMenu")
            menu_button.setText("⋯")
            menu_button.setToolTip("File actions")
            menu_button.setPopupMode(QToolButton.ToolButtonPopupMode.InstantPopup)
            menu = QMenu(menu_button)
            for caption, method in (("Restore", "restore_selected"),
                                    ("Verify", "verify_selected"),
                                    ("Remove", "remove_selected")):
                action = menu.addAction(caption)
                action.triggered.connect(
                    lambda _=False, ident=entry_id, meth=method:
                        self._run_row_action(ident, meth))
            menu_button.setMenu(menu)
            self.file_table.setCellWidget(row, 5, menu_button)
        index_layout.addWidget(self.file_table)

        footer = QWidget()
        footer_row = QHBoxLayout(footer)
        footer_row.setContentsMargins(15, 10, 12, 10)
        footer_row.setSpacing(9)
        footer_row.addWidget(label(f"{len(self.file_ids)} files in index", "muted"))
        footer_row.addStretch(1)
        self._busy_controls = list(import_buttons) + [self.remove_originals]
        for text, handler in (("Decrypt / Restore selected", self.restore_selected),
                              ("Verify against file", self.verify_selected),
                              ("Remove record", self.remove_selected)):
            control = button(text)
            control.clicked.connect(handler)
            footer_row.addWidget(control)
            self._busy_controls.append(control)
        index_layout.addWidget(footer)
        layout.addWidget(index_card)

        self.progress = QProgressBar()
        self.progress.setValue(0)
        self.progress.hide()
        layout.addWidget(self.progress)
        self.operation_status = label("Ready", "status")
        layout.addWidget(self.operation_status)
        layout.addStretch(1)

    def _run_row_action(self, entry_id: str, method: str) -> None:
        if self._working:
            return
        for row in range(self.file_table.rowCount()):
            self.file_table.item(row, 0).setCheckState(Qt.Unchecked)
            if self.file_ids[row] == entry_id:
                self.file_table.clearSelection()
                self.file_table.selectRow(row)
        getattr(self, method)()

    def selected_file_ids(self) -> list[str]:
        checked = [self.file_ids[row] for row in range(self.file_table.rowCount())
                   if self.file_table.item(row, 0).checkState() == Qt.Checked]
        if checked:
            return checked
        return [self.file_ids[row.row()] for row in
                self.file_table.selectionModel().selectedRows()]

    @staticmethod
    def _fmt_bytes(value):
        value = float(value)
        for unit in ("B", "KB", "MB", "GB", "TB"):
            if value < 1024 or unit == "TB":
                return f"{value:.1f} {unit}"
            value /= 1024

    def selected_file_id(self):
        ids = self.selected_file_ids()
        if not ids:
            QMessageBox.information(self, "Select a file", "Select a row or tick its checkbox first.")
            return None
        if len(ids) != 1:
            QMessageBox.information(self, "Select one file", "Choose exactly one file for this action.")
            return None
        return ids[0]

    def _run_job(self, action, success_message):
        if self._working:
            return
        self._working = True
        self._job_title = success_message
        self._job_result = None
        self._job_failure = None
        self.status.setText("Processing…")
        for control in self._busy_controls:
            control.setEnabled(False)
        if hasattr(self, "operation_card"):
            self.operation_card.hide()
        if hasattr(self, "progress"):
            self.progress.setValue(0)
            self.progress.show()
        self._worker_thread = QThread(self)
        self._worker = JobWorker(action)
        self._worker.moveToThread(self._worker_thread)
        self._worker_thread.started.connect(self._worker.run)
        # GUI callbacks MUST be QObject slots with a queued connection to
        # their GUI-thread receiver. Plain Python lambdas here can execute on
        # the worker thread, causing fatal native Qt crashes on Windows.
        self._worker.progress.connect(self._progress_changed, Qt.QueuedConnection)
        self._worker.success.connect(self._on_job_success, Qt.QueuedConnection)
        self._worker.failure.connect(self._on_job_failure, Qt.QueuedConnection)
        self._worker.finished.connect(self._worker_thread.quit)
        self._worker.finished.connect(self._worker.deleteLater)
        self._worker_thread.finished.connect(self._job_thread_finished, Qt.QueuedConnection)
        self._worker_thread.finished.connect(self._worker_thread.deleteLater)
        self._worker_thread.start()

    @Slot(int, int, str)
    def _progress_changed(self, index, total, name):
        if hasattr(self, "progress"):
            self.progress.setValue(round(index * 100 / max(total, 1)))
            self.operation_status.setText(f"{index}/{total}  •  {name}")

    @Slot(object)
    def _on_job_success(self, result):
        # Store the outcome, but never present it while QThread is active.
        self._job_result = result

    @Slot(str)
    def _on_job_failure(self, message):
        self._job_failure = message

    @Slot()
    def _job_thread_finished(self):
        # QThread.finished means the worker really stopped. Only now refresh
        # widgets or display completion messages, avoiding nested modal event
        # loops while thread cleanup is pending.
        self._worker = None
        self._worker_thread = None
        self._working = False
        if self._lock_after_job:
            self._lock_after_job = False
            self.lock()
            return
        self._busy_controls = []
        self.status.setText("Ready")
        self.auto_lock.start()
        destination = self._job_return_page
        self._job_return_page = "Files"
        self.navigate(destination)
        QTimer.singleShot(0, self._report_job_result)

    @Slot()
    def _report_job_result(self):
        failure = self._job_failure
        result = self._job_result
        title = self._job_title
        self._job_failure = None
        self._job_result = None
        self._job_title = ""
        if self._navigation.get("Standalone") and self._navigation["Standalone"].isChecked():
            report = self.standalone_summary
            card = self.standalone_card
        elif self._navigation["Files"].isChecked():
            report = self.import_summary
            card = self.operation_card
        else:
            if failure:
                QMessageBox.warning(self, "Operation failed", failure)
            else:
                QMessageBox.information(self, "Operation finished", str(result))
            return
        if failure:
            report.setPlainText("Operation failed\n" + failure)
            card.show()
            self.operation_status.setText("Operation failed")
            return
        if result is None:
            report.setPlainText("Operation failed\nNo result was returned by the worker.")
            card.show()
            self.operation_status.setText("Operation failed")
            return
        if isinstance(result, tuple):
            count, warnings = result
            message = f"{count} file(s) processed."
            if warnings:
                message += "\n\nWarnings or skipped files:\n" + "\n".join(warnings[:12])
                if len(warnings) > 12:
                    message += f"\n... and {len(warnings) - 12} more."
        else:
            message = str(result)
        # All job outcomes use a non-modal panel. That includes hash comparison
        # and restore, not just import; they share the same worker code path.
        report.setPlainText(f"{title}\n{message}")
        card.show()
        self.operation_status.setText("Operation complete")

    def closeEvent(self, event):
        if os.name == "nt" and self._session_notice_registered:
            try:
                import ctypes
                ctypes.windll.wtsapi32.WTSUnRegisterSessionNotification(int(self.winId()))
            except (OSError, AttributeError, ValueError):
                pass
            self._session_notice_registered = False
        if self._working:
            event.ignore()
            self.operation_status.setText("Please wait for encryption to finish before closing BlackCube.")
            return
        super().closeEvent(event)

    def start_import(self, folder: bool, hash_only: bool):
        if folder:
            selected = QFileDialog.getExistingDirectory(self, "Choose a folder to add to the vault")
            paths = [Path(selected)] if selected else []
        else:
            selected, _ = QFileDialog.getOpenFileNames(self, "Choose files to add to the vault")
            paths = [Path(item) for item in selected]
        if not paths:
            return
        mode = self.mode.currentText()
        if mode.startswith("Hybrid "):
            mode = "Hybrid " + self.session.profile
        selected_hash = self.hash_mode.currentText()
        removing = self.remove_originals.isChecked() and not hash_only
        if removing:
            confirmation = QMessageBox(self)
            confirmation.setIcon(QMessageBox.Warning)
            confirmation.setWindowTitle("Confirm deletion of originals")
            confirmation.setText("SOURCE FILES WILL BE DELETED AFTER VERIFIED ENCRYPTION")
            confirmation.setInformativeText(
                "Each source file is deleted only if encryption, saving the encrypted "
                "vault index, authenticated decryption readback and digest checks succeed. "
                "This is ordinary deletion, NOT secure erasure: recovery tools, backups "
                "and cloud sync may retain copies. Some files may be processed even if "
                "later files fail. Make an independent backup first.")
            confirmation.setStandardButtons(QMessageBox.Yes | QMessageBox.Cancel)
            confirmation.setDefaultButton(QMessageBox.Cancel)
            if confirmation.exec() != QMessageBox.Yes:
                return
        session = self.session
        self._job_return_page = "Files"
        self._run_job(lambda progress: session.import_files(
            paths, mode, selected_hash, hash_only, progress, removing),
            "Import results")

    def restore_selected(self):
        ids = self.selected_file_ids()
        if not ids:
            QMessageBox.information(self, "Select files", "Select one or more encrypted files first.")
            return
        try:
            credential = self._credentials_dialog("Authenticate to restore files")
            if credential is None:
                return
            self.session.verify_unlock(*credential)
        except Exception as exc:
            self._error("Authentication failed", str(exc))
            return
        path = QFileDialog.getExistingDirectory(self, "Choose a restore destination")
        if not path:
            return
        session = self.session
        def restore_batch(progress):
            successful = 0
            problems = []
            for index, entry_id in enumerate(ids, 1):
                try:
                    session.restore(entry_id, Path(path))
                    successful += 1
                except Exception as exc:
                    problems.append(f"File {index}: {exc}")
                progress(index, len(ids), f"Restoring {index}/{len(ids)}")
            return successful, problems
        self._job_return_page = "Files"
        self._run_job(restore_batch, "Restore results")

    def verify_selected(self):
        entry_id = self.selected_file_id()
        if not entry_id:
            return
        path, _ = QFileDialog.getOpenFileName(self, "Select a file to check against stored digest")
        if not path:
            return
        session = self.session
        self._job_return_page = "Files"
        self._run_job(lambda _: ("MATCH — digest identical" if session.verify_hash(entry_id, Path(path))
                                 else "MISMATCH — contents differ"), "Hash verification")

    def remove_selected(self):
        ids = self.selected_file_ids()
        if not ids:
            QMessageBox.information(self, "Select files", "Select one or more file records first.")
            return
        if QMessageBox.question(
            self, "Delete encrypted files",
            f"Permanently delete {len(ids)} selected encrypted record(s) from this vault?\n"
            "If the originals were removed, this may delete the last copy."
        ) != QMessageBox.Yes:
            return
        try:
            for entry_id in ids:
                self.session.remove_entry(entry_id)
            self.navigate("Files")
        except Exception as exc:
            self._error("Removal failed", str(exc))
            self.navigate("Files")

    def show_accounts(self):
        layout = self._layout("Accounts")
        add = button("Add account", primary=True)
        add.clicked.connect(self.add_account)
        self._header(layout, "Passwords", "Account credentials stored in this vault.", add)
        self.account_search = QLineEdit()
        self.account_search.setPlaceholderText("Search accounts, usernames or websites")
        self.account_search.textChanged.connect(self.filter_accounts)
        layout.addWidget(self.account_search)
        stored = self.session.accounts
        passwords = [entry["password"] for entry in stored]
        reused = sum(passwords.count(value) > 1 for value in set(passwords))
        weak = sum(len(value) < 12 for value in passwords)
        layout.addWidget(label(f"{len(stored)} accounts  •  {reused} reused password groups  •  {weak} short passwords", "muted"))
        tools = QHBoxLayout()
        tools.addWidget(label("Saved accounts", "section-heading"))
        tools.addStretch()
        for txt, handler in (("Edit", self.edit_account), ("Copy password", self.copy_password),
                             ("Delete", self.delete_account)):
            w = button(txt)
            w.clicked.connect(handler)
            tools.addWidget(w)
        layout.addLayout(tools)
        self.account_table = table(["Account", "Username / email", "Website", "Updated"])
        self.account_ids = []
        for entry in self.session.accounts:
            idx = self.account_table.rowCount()
            self.account_table.insertRow(idx)
            self.account_ids.append(entry["id"])
            for col, value in enumerate((entry["title"], entry["username"], entry["url"],
                                         entry["updated_at"][:10])):
                self.account_table.setItem(idx, col, QTableWidgetItem(value))
        layout.addWidget(self.account_table, 1)
        layout.addWidget(label("Passwords are not displayed in this table. Clipboard copies auto-clear after 20 seconds when unchanged.", "subheading"))

    def filter_accounts(self, query):
        q = query.casefold()
        for i, row in enumerate(self.session.accounts):
            fields = (row["title"], row["username"], row.get("url", ""))
            self.account_table.setRowHidden(i, not any(q in v.casefold() for v in fields))

    def selected_account(self):
        rows = self.account_table.selectionModel().selectedRows()
        if not rows:
            QMessageBox.information(self, "Select account", "Select a saved account first.")
            return None
        account_id = self.account_ids[rows[0].row()]
        return next((a for a in self.session.accounts if a["id"] == account_id), None)

    def add_account(self):
        d = AccountDialog(self)
        if d.exec() != QDialog.Accepted:
            return
        try:
            self.session.save_account(d.title.text(), d.username.text(), d.password.text(),
                                      d.url.text(), d.notes.toPlainText())
            self.navigate("Accounts")
        except Exception as exc:
            self._error("Save failed", str(exc))

    def edit_account(self):
        row = self.selected_account()
        if not row:
            return
        d = AccountDialog(self, row)
        if d.exec() != QDialog.Accepted:
            return
        try:
            self.session.save_account(d.title.text(), d.username.text(), d.password.text(),
                                      d.url.text(), d.notes.toPlainText(), row["id"])
            self.navigate("Accounts")
        except Exception as exc:
            self._error("Save failed", str(exc))

    def copy_password(self):
        row = self.selected_account()
        if not row:
            return
        secret = row["password"]
        clipboard = QApplication.clipboard()
        clipboard.setText(secret)
        # Clearing if unchanged avoids erasing newer user clipboard content.
        QTimer.singleShot(20000, lambda: clipboard.clear() if clipboard.text() == secret else None)
        QMessageBox.information(self, "Copied", "Password copied. Clipboard will clear after 20 seconds if unchanged.")

    def delete_account(self):
        row = self.selected_account()
        if not row:
            return
        if QMessageBox.question(self, "Delete credentials", "Remove this account from the encrypted vault?") != QMessageBox.Yes:
            return
        try:
            self.session.delete_account(row["id"])
            self.navigate("Accounts")
        except Exception as exc:
            self._error("Delete failed", str(exc))

    def show_integrity(self):
        layout = self._layout("Integrity")
        self._header(layout, "Integrity", "Compare stored hashes with local files.")
        note = card()
        note.layout().setContentsMargins(22, 22, 22, 22)
        note.layout().addWidget(label("SHA-2, SHA-3, and BLAKE2", "section-heading"))
        note.layout().addWidget(label("Use Hash file or Hash folder on the Files page to create a checksum record. Select it and click Verify to compare a file later.", "subheading"))
        start = button("Go to files", primary=True)
        start.clicked.connect(lambda: self.navigate("Files"))
        note.layout().addWidget(start, alignment=Qt.AlignLeft)
        layout.addWidget(note)
        hashes = [x for x in self.session.entries if x["type"] == "hash"]
        layout.addWidget(label(f"{len(hashes)} hash records", "section-heading"))
        t = table(["Source path", "Algorithm", "Digest"])
        for row, entry in enumerate(hashes):
            t.insertRow(row)
            for column, value in enumerate((entry["path"], entry["hash_algorithm"], entry["digest"])):
                t.setItem(row, column, QTableWidgetItem(value))
        layout.addWidget(t, 1)

    def show_settings(self):
        layout = self._layout("Settings")
        self._header(layout, "Settings", "Vault configuration and access credentials.")
        # QFormLayout must be the panel's ONLY layout. card() already attaches
        # a QVBoxLayout, so constructing QFormLayout(card()) silently fails
        # on Qt and leaves the entire Settings panel empty.
        panel = QFrame()
        panel.setObjectName("card")
        form = QFormLayout(panel)
        form.setContentsMargins(24, 24, 24, 24)
        form.setSpacing(14)
        form.addRow("Project", label(self.session.name))
        form.addRow("Identifier", label(self.session.vault_id))
        form.addRow("Post-quantum profile", label(self.session.profile or "Disabled"))
        form.addRow("Encrypted files", label("AES-GCM or ChaCha20-Poly1305; per-file keys"))
        form.addRow("Passphrase KDF", label("Argon2id (64 MiB, 3 iterations, 2 lanes)"))
        duration = QComboBox()
        for minutes in (1, 5, 10, 30):
            duration.addItem(f"{minutes} minute(s)", minutes)
        current_minutes = self.auto_lock.interval() // 60000
        duration.setCurrentIndex((1, 5, 10, 30).index(current_minutes))
        duration.currentIndexChanged.connect(lambda _: self.update_auto_lock(duration.currentData()))
        form.addRow("Auto-lock inactivity", duration)
        # Read the actual unlocked vault directory, never a hard-coded
        # default: this also works with imported/custom vault locations.
        directory = str(self.session.directory.resolve())
        self.storage_path = QLineEdit(directory)
        self.storage_path.setReadOnly(True)
        self.storage_path.setToolTip(directory)
        form.addRow("Vault location", self.storage_path)
        open_storage = button("Open vault folder")
        open_storage.clicked.connect(self.open_vault_folder)
        form.addRow("", open_storage)
        form.addRow("Required unlock method", label({"either": "Passphrase OR alternate key file (legacy)",
            "passphrase": "Passphrase only", "keyfile": "Generated key file only",
            "both": "Passphrase AND generated key file"}.get(self.session.unlock_mode, "Unknown")))
        form.addRow("Alternate key file", label("Configured" if self.session.config.get("keyfile_wrap") else "Not configured"))
        add_keyfile = button("Create alternate recovery key file")
        add_keyfile.setEnabled(self.session.unlock_mode == "either" and not bool(self.session.config.get("keyfile_wrap")))
        add_keyfile.clicked.connect(self.create_key_file)
        form.addRow("", add_keyfile)
        both_factors = button("Require passphrase + generated key file")
        both_factors.setEnabled(self.session.unlock_mode in ("either", "passphrase"))
        both_factors.clicked.connect(lambda: self.enable_strict_keyfile("both"))
        form.addRow("Secure access", both_factors)
        only_file = button("Require generated key file only")
        only_file.setEnabled(self.session.unlock_mode in ("either", "passphrase"))
        only_file.clicked.connect(lambda: self.enable_strict_keyfile("keyfile"))
        form.addRow("", only_file)
        password_only = button("Switch to passphrase-only access")
        password_only.clicked.connect(self.enable_passphrase_only)
        form.addRow("", password_only)
        form.addRow("Biometric authentication", label("Windows Hello integration not yet implemented"))
        backup = button("Create verified encrypted vault backup")
        backup.clicked.connect(self.create_vault_backup)
        form.addRow("Backup", backup)
        health = button("Check vault integrity")
        health.clicked.connect(self.run_vault_health)
        form.addRow("Health", health)
        recovery = button("Quarantine interrupted import files")
        recovery.clicked.connect(self.quarantine_vault_staging)
        form.addRow("Crash recovery", recovery)
        rotate = button("Replace recovery key file")
        rotate.setEnabled(self.session.unlock_mode == "either")
        rotate.clicked.connect(self.replace_recovery_key)
        form.addRow("Key files", rotate)
        disable = button("Disable recovery key file")
        disable.setEnabled(self.session.unlock_mode == "either" and bool(self.session.config.get("keyfile_wrap")))
        disable.clicked.connect(self.disable_recovery_key)
        form.addRow("", disable)
        change = button("Change master passphrase")
        change.setEnabled(self.session.unlock_mode != "keyfile")
        change.clicked.connect(self.change_password)
        form.addRow("", change)
        layout.addWidget(panel)
        layout.addWidget(label("Security notes", "section-heading"))
        layout.addWidget(label("This software is experimental and unaudited. File deletion is not secure erasure. Verify backups and restores, and store recovery key files separately from vault data. Windows Hello is not supported yet.", "subheading"))
        layout.addStretch()

    def enable_strict_keyfile(self, mode: str):
        if mode not in ("both", "keyfile") or not self.session:
            return
        prompt = ("This will require BOTH your passphrase and a new generated key file. "
                  if mode == "both" else
                  "This will remove passphrase access and require ONLY a new generated key file. ")
        prompt += ("A lost key file may permanently lock you out. Old backups may still "
                   "accept old credentials. Verify recovery and keep separate offline copies. Continue?")
        if QMessageBox.warning(self, "Change vault access", prompt,
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No) != QMessageBox.Yes:
            return
        pwd, ok = QInputDialog.getText(self, "Authorize access change", "Current master passphrase:", QLineEdit.Password)
        if not ok or not pwd:
            return
        filename, _ = QFileDialog.getSaveFileName(self, "Save NEW generated key file OUTSIDE the vault",
                                                  "blackcube-access.bckey", "BlackCube keys (*.bckey)")
        if not filename:
            return
        try:
            if mode == "both":
                self.session.require_two_factors(pwd, Path(filename))
            else:
                self.session.require_keyfile_only(pwd, Path(filename))
            QMessageBox.information(self, "Access updated",
                "The required unlock policy was changed. Keep the new key file safe, "
                "lock and unlock your vault, and test recovery with disposable files.")
            self.navigate("Settings")
        except Exception as exc:
            self._error("Could not change vault access", str(exc))

    def enable_passphrase_only(self):
        if not self.session:
            return
        try:
            credentials = self._credentials_dialog("Authorize access change")
            if credentials is None:
                return
            pw, ok = QInputDialog.getText(self, "New master passphrase", "New passphrase (12+ characters):", QLineEdit.Password)
            if not ok or not pw:
                return
            confirmation, ok = QInputDialog.getText(self, "Confirm master passphrase", "Repeat the new passphrase:", QLineEdit.Password)
            if not ok or confirmation != pw:
                raise VaultError("Passphrases do not match")
            self.session.require_passphrase_only(pw, current_passphrase=credentials[0], current_key_file=credentials[1])
            self.navigate("Settings")
        except Exception as exc:
            self._error("Could not change vault access", str(exc))

    def update_auto_lock(self, minutes):
        minutes = int(minutes)
        if minutes not in (1, 5, 10, 30):
            return
        self._user_settings.setValue("auto_lock_minutes", minutes)
        self.auto_lock.setInterval(minutes * 60000)
        if self.session:
            self.auto_lock.start()

    def _load_known_homes(self):
        import json
        try:
            data = json.loads(self._locations_file.read_text(encoding="utf-8"))
            for value in data.get("homes", []):
                home = Path(value)
                if home.is_dir():
                    self._known_homes.add(home.resolve())
        except (OSError, ValueError, TypeError):
            pass

    def _register_home(self, folder: Path):
        import json
        folder = Path(folder).resolve()
        self._known_homes.add(folder)
        self._locations_file.parent.mkdir(parents=True, exist_ok=True)
        self._locations_file.write_text(json.dumps({"homes": sorted(map(str, self._known_homes))}),
                                       encoding="utf-8")

    def register_vault_location(self):
        chosen = QFileDialog.getExistingDirectory(self, "Select the folder containing vault.json")
        if not chosen:
            return
        folder = Path(chosen)
        if not (folder / "vault.json").is_file():
            self._error("Not a vault", "The selected folder has no vault.json")
            return
        self._register_home(folder.parent)
        self.navigate("Projects")

    def restore_vault_backup(self):
        selected, _ = QFileDialog.getOpenFileName(self, "Choose vault backup", "",
                                                  "BlackCube backup (*.zip);;All files (*)")
        if not selected:
            return
        home = QFileDialog.getExistingDirectory(self, "Choose a folder for recovered vaults")
        if not home:
            return
        try:
            mode = backup_unlock_mode(Path(selected))
            credential = self._credentials_dialog("Verify and restore encrypted backup", mode_override=mode)
            if credential is None:
                return
            self._register_home(Path(home))
            self._job_return_page = "Projects"
            password, key = credential
            self._run_job(lambda _: import_verified_backup(Path(selected), Path(home),
                password=password, key_file=key), "Backup authenticated and restored")
        except Exception as exc:
            self._error("Restore failed", str(exc))

    def create_vault_backup(self):
        chosen, _ = QFileDialog.getSaveFileName(self, "Save encrypted vault backup", "blackcube-vault.zip",
                                                "ZIP backups (*.zip)")
        if not chosen:
            return
        session = self.session
        self._job_return_page = "Settings"
        self._run_job(lambda _: create_backup(session, Path(chosen)), "Backup created")

    def run_vault_health(self):
        session = self.session
        self._job_return_page = "Settings"
        self._run_job(lambda _: check_vault(session), "Health report")

    def quarantine_vault_staging(self):
        if self._working:
            return
        if QMessageBox.warning(self, "Non-destructive interrupted-import recovery",
            "Only run this when no other BlackCube instance is accessing this vault. "
            "Unreferenced encrypted objects and temporary staging files will be moved "
            "to a quarantine subfolder, never deleted. Proceed?",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No) != QMessageBox.Yes:
            return
        session = self.session
        self._job_return_page = "Settings"
        self._run_job(lambda _: quarantine_uncommitted(session), "Interrupted imports quarantined")

    def replace_recovery_key(self):
        pwd, ok = QInputDialog.getText(self, "Authorize credential replacement",
                                        "Master passphrase:", QLineEdit.Password)
        if not ok or not pwd:
            return
        chosen, _ = QFileDialog.getSaveFileName(self, "Save NEW recovery key file", "recovery-new.bckey",
                                                 "Key files (*.bckey)")
        if not chosen:
            return
        try:
            self.session.replace_keyfile(pwd, Path(chosen))
            QMessageBox.information(self, "Recovery key updated",
                "The new key unlocks this copy of the vault. Old backups may still be unlocked using older keys; this is NOT master-key rotation.")
            self.navigate("Settings")
        except Exception as exc:
            self._error("Key replacement failed", str(exc))

    def disable_recovery_key(self):
        pwd, ok = QInputDialog.getText(self, "Disable key-file unlock",
                                        "Master passphrase:", QLineEdit.Password)
        if not ok or not pwd:
            return
        try:
            self.session.disable_keyfile(pwd)
            self.navigate("Settings")
        except Exception as exc:
            self._error("Key disable failed", str(exc))

    def _standalone_credentials(self, encrypting):
        d = QDialog(self)
        d.setWindowTitle("Standalone archive authentication")
        d.setMinimumWidth(430)
        l = QVBoxLayout(d)
        method = QComboBox()
        method.addItems(["Passphrase", "Standalone 32-byte key file"])
        l.addWidget(method)
        pwd = QLineEdit()
        pwd.setEchoMode(QLineEdit.Password)
        pwd.setPlaceholderText("At least 12 characters")
        l.addWidget(pwd)
        confirmation = QLineEdit()
        confirmation.setEchoMode(QLineEdit.Password)
        confirmation.setPlaceholderText("Confirm passphrase")
        l.addWidget(confirmation)
        key_path = QLineEdit()
        row = QHBoxLayout()
        row.addWidget(key_path)
        browse = button("Browse")
        browse.clicked.connect(lambda: key_path.setText(QFileDialog.getOpenFileName(
            d, "Choose standalone key file", "", "All files (*)")[0]))
        row.addWidget(browse)
        l.addLayout(row)
        def update():
            use_key = method.currentIndex() == 1
            pwd.setVisible(not use_key)
            confirmation.setVisible(not use_key and encrypting)
            key_path.setVisible(use_key)
            browse.setVisible(use_key)
        method.currentIndexChanged.connect(update)
        update()
        controls = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        controls.accepted.connect(d.accept)
        controls.rejected.connect(d.reject)
        l.addWidget(controls)
        if d.exec() != QDialog.Accepted:
            return None
        if method.currentIndex() == 1:
            if not key_path.text():
                raise VaultError("Select a standalone key file")
            return {'key_file': Path(key_path.text())}
        if len(pwd.text()) < 12 or encrypting and pwd.text() != confirmation.text():
            raise VaultError("Enter a passphrase of at least 12 characters and confirm it")
        return {'passphrase': pwd.text()}

    def show_standalone(self):
        layout = self._layout("Standalone")
        self._header(layout, "Standalone encryption",
                     "Create .cubefile archives beside files or folders. No vault required.")
        panel = card()
        panel.layout().setSpacing(13)
        panel.layout().setContentsMargins(22, 22, 22, 22)
        panel.layout().addWidget(label("Source file and folder encryption", "section-heading"))
        self.portable_cipher = QComboBox()
        self.portable_cipher.addItems(["AES-256-GCM", "AES-192-GCM", "AES-128-GCM"])
        panel.layout().addWidget(label("Portable encryption algorithm", "muted"))
        panel.layout().addWidget(self.portable_cipher)
        panel.layout().addWidget(label(
            "Encrypted output: folder1/ → folder1.cubefile, in the same directory. "
            "Folders remain untouched by default. Standalone files use AES-256-GCM and Argon2id.", "subheading"))
        row = QHBoxLayout()
        for caption, handler in (("Encrypt file", lambda: self.standalone_encrypt(False)),
                                 ("Encrypt folder", lambda: self.standalone_encrypt(True)),
                                 ("Decrypt .cubefile", self.standalone_decrypt),
                                 ("Create key file", self.create_standalone_key)):
            w = button(caption)
            row.addWidget(w)
            w.clicked.connect(handler)
        panel.layout().addLayout(row)
        self.portable_remove = QCheckBox("Remove original FILE only, after verification (folders always retained)")
        self.portable_remove.setChecked(False)
        panel.layout().addWidget(self.portable_remove)
        layout.addWidget(panel)
        self.standalone_card = card()
        self.standalone_summary = QTextEdit()
        self.standalone_summary.setReadOnly(True)
        self.standalone_summary.setMaximumHeight(120)
        self.standalone_card.layout().addWidget(self.standalone_summary)
        self.standalone_card.hide()
        layout.addWidget(self.standalone_card)
        self.progress = QProgressBar()
        self.progress.hide()
        layout.addWidget(self.progress)
        self.operation_status = label("Ready", "status")
        layout.addWidget(self.operation_status)
        layout.addStretch()

    def standalone_encrypt(self, folder: bool):
        if folder:
            path = QFileDialog.getExistingDirectory(self, "Choose a folder to encrypt")
        else:
            path, _ = QFileDialog.getOpenFileName(self, "Choose a file to encrypt")
        if not path:
            return
        remove = self.portable_remove.isChecked() and not folder
        if remove and QMessageBox.warning(self, "Confirm source deletion",
                "Delete the original file only after successful verified encryption? This is NOT secure erasure.",
                QMessageBox.Yes | QMessageBox.Cancel, QMessageBox.Cancel) != QMessageBox.Yes:
            return
        try:
            credentials = self._standalone_credentials(True)
            if credentials is None:
                return
            self._job_return_page = "Standalone"
            selected_cipher = self.portable_cipher.currentText()
            self._run_job(lambda _: encrypt_standalone(Path(path), **credentials,
                                  remove_original=remove, cipher=selected_cipher),
                          "Standalone encryption finished")
        except Exception as exc:
            self._error("Encryption failed", str(exc))

    def standalone_decrypt(self):
        path, _ = QFileDialog.getOpenFileName(self, "Choose .cubefile archive", "",
                                              "BlackCube archives (*.cubefile)")
        if not path:
            return
        root = QFileDialog.getExistingDirectory(self, "Choose restore destination")
        if not root:
            return
        try:
            credentials = self._standalone_credentials(False)
            if credentials is None:
                return
            self._job_return_page = "Standalone"
            self._run_job(lambda _: decrypt_standalone(Path(path), Path(root), **credentials),
                          "Standalone restore finished")
        except Exception as exc:
            self._error("Restore failed", str(exc))

    def create_standalone_key(self):
        filename, _ = QFileDialog.getSaveFileName(self, "Choose NEW standalone key-file location",
                                                  "blackcube-standalone.cube-key")
        if filename:
            try:
                generate_portable_keyfile(Path(filename))
                QMessageBox.information(self, "Key file created",
                    "Keep this key separate from encrypted files. Losing it makes encrypted archives unrecoverable.")
            except Exception as exc:
                self._error("Key generation failed", str(exc))

    def open_vault_folder(self):
        """Open the actual unlocked vault directory in the OS file manager."""
        if self.session is None:
            return
        folder = self.session.directory.resolve()
        if not folder.is_dir():
            QMessageBox.warning(self, "Folder not found", f"Vault directory does not exist: {folder}")
            return
        if not QDesktopServices.openUrl(QUrl.fromLocalFile(str(folder))):
            QMessageBox.warning(self, "Could not open folder", f"Open this folder in File Explorer: {folder}")

    def create_key_file(self):
        if self.session.config.get("keyfile_wrap"):
            return
        password, ok = None, False
        from PySide6.QtWidgets import QInputDialog
        password, ok = QInputDialog.getText(self, "Authorize key-file creation",
                                            "Current master passphrase:", QLineEdit.Password)
        if not ok or not password:
            return
        filename, _ = QFileDialog.getSaveFileName(self,
            "Save alternate recovery key OUTSIDE the vault", "blackcube-recovery.bckey",
            "BlackCube key files (*.bckey)")
        if not filename:
            return
        try:
            self.session.add_keyfile(password, Path(filename))
            QMessageBox.information(self, "Recovery key created",
                "Keep the key file separately and protect it carefully. Anyone who obtains "
                "this file AND your encrypted vault can decrypt all vault contents. "
                "The passphrase continues to work too.")
            self.navigate("Settings")
        except Exception as exc:
            self._error("Could not create key file", str(exc))

    def change_password(self):
        d = QDialog(self)
        d.setWindowTitle("Update master passphrase")
        l = QFormLayout(d)
        old = QLineEdit()
        new = QLineEdit()
        confirm = QLineEdit()
        for w in (old, new, confirm):
            w.setEchoMode(QLineEdit.Password)
        l.addRow("Current passphrase", old)
        l.addRow("New passphrase", new)
        l.addRow("Confirm", confirm)
        actions = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        l.addWidget(actions)
        actions.accepted.connect(d.accept)
        actions.rejected.connect(d.reject)
        if d.exec() != QDialog.Accepted:
            return
        if new.text() != confirm.text():
            self._error("Mismatch", "New passphrases do not match")
            return
        try:
            key_file = None
            if self.session.unlock_mode == "both":
                selected, _ = QFileDialog.getOpenFileName(self, "Current mandatory key file", "", "Key files (*.bckey)")
                if not selected:
                    return
                key_file = Path(selected)
            self.session.change_passphrase(old.text(), new.text(), key_file)
            QMessageBox.information(self, "Updated", "Master passphrase changed. Back up your vault folder.")
        except Exception as exc:
            self._error("Passphrase change failed", str(exc))

    def _error(self, title, message):
        QMessageBox.critical(self, title, message)


def main():
    # AppUserModelID must be registered before Qt creates any native window.
    configure_windows_app_id()
    app = QApplication(sys.argv)
    app.setApplicationName("BlackCube")
    app.setOrganizationName("BlackCube")
    # Qt's application-wide icon is used for taskbar and modal dialog windows.
    app.setWindowIcon(QIcon(str(brand_asset("blackcube.ico"))))
    app.setStyle("Fusion")
    app.setStyleSheet(STYLE)
    font = QFont("Segoe UI", 10)
    app.setFont(font)
    window = MainWindow()
    window.show()
    apply_windows_dark_caption(window)
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
