#!/usr/bin/env python3
# Payload Studio — msfvenom GUI
# Author: 0x00ctrl

import re
import shlex
import shutil
import subprocess
import sys
from pathlib import Path

from PySide6.QtCore import QObject, QRunnable, QThreadPool, Qt, Signal
from PySide6.QtGui import QFont
from PySide6.QtWidgets import (
    QApplication,
    QComboBox,
    QFileDialog,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QSplitter,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)


APP_STYLE = """
QWidget {
    background: #0c1220;
    color: #e7edf7;
    font-family: "Inter", "Segoe UI", sans-serif;
    font-size: 13px;
}
QMainWindow, QScrollArea {
    background: #0c1220;
    border: none;
}
QScrollArea > QWidget > QWidget {
    background: #0c1220;
}
QFrame#sidebar {
    background: #101a2c;
    border-right: 1px solid #26344b;
}
QFrame#card {
    background: #141f32;
    border: 1px solid #293850;
    border-radius: 12px;
}
QFrame#card QLabel {
    background: transparent;
}
QLabel#title {
    font-size: 23px;
    font-weight: 700;
    color: #f8fafc;
}
QLabel#brand {
    font-size: 19px;
    font-weight: 700;
    color: #f8fafc;
}
QLabel#section {
    font-size: 15px;
    font-weight: 700;
    color: #f8fafc;
}
QLabel#muted {
    color: #a4b3c9;
}
QLabel#eyebrow {
    color: #8ea2bd;
    font-size: 11px;
    font-weight: 700;
}
QPushButton {
    background: #223149;
    color: #e9f0fb;
    border: 1px solid #354862;
    border-radius: 8px;
    padding: 8px 12px;
    font-weight: 600;
}
QPushButton:hover {
    background: #2c405d;
    border-color: #587499;
}
QPushButton:pressed {
    background: #18283e;
}
QPushButton:disabled {
    color: #8190a5;
    background: #1a2638;
    border-color: #28384e;
}
QPushButton#primary {
    background: #6d5dfc;
    border-color: #8174ff;
    color: white;
    padding: 10px 16px;
}
QPushButton#primary:hover {
    background: #8173ff;
}
QPushButton#primary:disabled {
    background: #343766;
    border-color: #414777;
    color: #aab1c9;
}
QPushButton#choice {
    text-align: left;
    padding: 9px 12px;
}
QPushButton#choice:checked {
    background: #343d80;
    border: 1px solid #a29bff;
    color: #ffffff;
}
QLineEdit, QComboBox, QListWidget, QTextEdit {
    background: #0d1727;
    color: #e7edf7;
    border: 1px solid #35465f;
    border-radius: 8px;
    padding: 8px;
    selection-background-color: #6054cc;
    selection-color: white;
}
QLineEdit:focus, QComboBox:focus, QListWidget:focus, QTextEdit:focus {
    border: 1px solid #9c91ff;
}
QLineEdit::placeholder {
    color: #8494aa;
}
QComboBox::drop-down {
    border: none;
    width: 26px;
}
QComboBox QAbstractItemView {
    background: #142035;
    color: #e7edf7;
    selection-background-color: #5149ad;
    border: 1px solid #35465f;
}
QListWidget::item {
    padding: 8px;
    border-radius: 5px;
}
QListWidget::item:selected {
    background: #5149ad;
    color: white;
}
QListWidget::item:hover:!selected {
    background: #23334c;
}
QScrollBar:vertical {
    background: #101a2c;
    width: 12px;
    margin: 2px;
}
QScrollBar::handle:vertical {
    background: #526782;
    min-height: 35px;
    border-radius: 4px;
}
QScrollBar::handle:vertical:hover {
    background: #7189a8;
}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
    height: 0;
}
QSplitter::handle {
    background: #26344b;
    width: 1px;
}
"""

PLATFORM_LABELS = {
    "windows": "Windows",
    "linux": "Linux",
    "osx": "macOS",
    "android": "Android",
    "apple_ios": "iOS",
    "bsd": "BSD",
    "solaris": "Solaris",
    "java": "Java",
    "php": "PHP",
    "python": "Python",
    "multi": "Multi-platform",
}

ARCH_NAMES = {
    "x86", "x64", "arm", "armle", "armbe", "aarch64",
    "mips", "mipsle", "mipsbe", "mips64", "mips64le",
    "ppc", "ppc64", "sparc", "sparc64", "riscv32",
    "riscv64", "zarch", "cmd",
}

FORMAT_SUGGESTIONS = {
    "windows": ["exe", "dll", "raw"],
    "linux": ["elf", "raw"],
    "osx": ["macho", "raw"],
    "android": ["raw"],
}

FILTER_KEYS = ("platform", "arch", "family", "transport")


def classify_payload(name):
    """
    Infer navigation groups from module names.

    These groups are hints, not authoritative metadata. Every parsed
    payload remains available in the exact-payload list.
    """
    parts = name.split("/")
    platform = parts[0] if parts else "other"
    rest = parts[1:]

    if rest and rest[0].lower() in ARCH_NAMES:
        arch = rest.pop(0)
    else:
        arch = "unspecified"

    leaf = rest[-1] if rest else name

    if len(rest) > 1:
        family = rest[0]
    else:
        match = re.search(r"_(reverse|bind)(?:_|$)", leaf)
        family = leaf[:match.start()] if match else leaf

    match = re.search(r"(reverse|bind)(?:_[A-Za-z0-9]+)*", leaf)
    transport = match.group(0) if match else "other / none"

    return platform, arch, family or "other", transport


def parse_modules(text):
    names = []
    for line in text.splitlines():
        parts = line.strip().split()
        if parts and "/" in parts[0] and re.fullmatch(
            r"[A-Za-z0-9_./-]+", parts[0]
        ):
            names.append(parts[0])
    return sorted(set(names), key=str.lower)


def parse_formats(text):
    values = []
    in_section = False

    for line in text.splitlines():
        stripped = line.strip()
        lower = stripped.lower()

        if "format" in lower and (
            "executable" in lower or "transform" in lower
        ):
            in_section = True
            continue

        if not in_section or not stripped:
            continue

        if set(stripped) <= {"-", " "}:
            continue

        candidates = (
            stripped.split(",")
            if "," in stripped
            else [stripped.split()[0]]
        )

        for candidate in candidates:
            candidate = candidate.strip()
            if re.fullmatch(r"[A-Za-z0-9_+-]+", candidate):
                values.append(candidate)

    return sorted(set(values), key=str.lower)


def run_command(command, timeout=120):
    return subprocess.run(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        errors="replace",
        timeout=timeout,
        check=False,
    )


class WorkerSignals(QObject):
    finished = Signal(object)
    failed = Signal(str)


class Worker(QRunnable):
    def __init__(self, function, *args):
        super().__init__()
        self.function = function
        self.args = args
        self.signals = WorkerSignals()

    def run(self):
        try:
            result = self.function(*self.args)
        except Exception as exc:
            self.signals.failed.emit(str(exc))
        else:
            self.signals.finished.emit(result)


def load_catalog_worker(executable):
    catalog = {}
    errors = []

    for name in ("payloads", "encoders", "formats"):
        try:
            result = run_command([executable, "-l", name])

            if result.returncode:
                errors.append(
                    f"{name}: exited with code {result.returncode}\n"
                    f"{result.stdout}"
                )
                continue

            parser = parse_formats if name == "formats" else parse_modules
            catalog[name] = parser(result.stdout)

            if not catalog[name]:
                errors.append(
                    f"Could not parse {name}. "
                    "You can still enter values manually."
                )

        except (OSError, subprocess.TimeoutExpired) as exc:
            errors.append(f"{name}: {exc}")

    return catalog, errors


def command_worker(command, timeout):
    result = run_command(command, timeout)
    return result.returncode, result.stdout


def make_label(text, name=None):
    label = QLabel(text)
    if name:
        label.setObjectName(name)
    label.setWordWrap(True)
    return label


def make_card():
    frame = QFrame()
    frame.setObjectName("card")
    layout = QVBoxLayout(frame)
    layout.setContentsMargins(18, 18, 18, 18)
    layout.setSpacing(10)
    return frame, layout


def clear_layout(layout):
    while layout.count():
        item = layout.takeAt(0)
        widget = item.widget()
        child_layout = item.layout()

        if widget:
            widget.deleteLater()
        elif child_layout:
            clear_layout(child_layout)


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("Payload Studio — 0x00ctrl")
        self.resize(1280, 850)
        self.setMinimumSize(900, 650)

        self.pool = QThreadPool.globalInstance()
        self.workers = set()

        self.loading = False
        self.generating = False

        self.payloads = []
        self.encoders = []
        self.formats = []
        self.records = {}

        self.selection = {key: None for key in FILTER_KEYS}

        self.build_ui()
        self.connect_signals()
        self.update_preview()
        self.load_catalog()

    def build_ui(self):
        root = QWidget()
        self.setCentralWidget(root)

        outer = QHBoxLayout(root)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)

        sidebar = QFrame()
        sidebar.setObjectName("sidebar")
        sidebar.setFixedWidth(240)

        side = QVBoxLayout(sidebar)
        side.setContentsMargins(20, 24, 20, 20)
        side.setSpacing(12)

        side.addWidget(make_label("◈  Payload Studio", "brand"))
        side.addWidget(make_label("msfvenom GUI", "muted"))
        side.addSpacing(18)

        side.addWidget(make_label("WORKSPACE", "eyebrow"))
        side.addWidget(make_label("01  Choose a platform"))
        side.addWidget(make_label("02  Narrow the catalog"))
        side.addWidget(make_label("03  Select a payload"))
        side.addWidget(make_label("04  Configure output"))

        side.addSpacing(20)
        side.addWidget(make_label("MSFVENOM PATH", "eyebrow"))

        self.executable = QLineEdit(
            shutil.which("msfvenom") or "msfvenom"
        )
        self.executable.setPlaceholderText("Path to msfvenom")
        side.addWidget(self.executable)

        path_row = QHBoxLayout()
        self.browse_executable_button = QPushButton("Browse")
        self.refresh_button = QPushButton("Refresh")
        path_row.addWidget(self.browse_executable_button)
        path_row.addWidget(self.refresh_button)
        side.addLayout(path_row)

        side.addStretch()
        side.addWidget(make_label("Built by 0x00ctrl", "muted"))

        outer.addWidget(sidebar)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(
            Qt.ScrollBarPolicy.ScrollBarAlwaysOff
        )
        outer.addWidget(scroll, 1)

        content = QWidget()
        scroll.setWidget(content)

        page = QVBoxLayout(content)
        page.setContentsMargins(28, 26, 28, 28)
        page.setSpacing(16)

        title_row = QHBoxLayout()
        heading = QVBoxLayout()
        heading.addWidget(make_label("Payload builder", "title"))
        heading.addWidget(
            make_label(
                "Explore your installed catalog and build a command.",
                "muted",
            )
        )
        title_row.addLayout(heading)
        title_row.addStretch()

        self.status = make_label("Loading catalog…", "muted")
        title_row.addWidget(self.status)
        page.addLayout(title_row)

        # Platform card
        platform_card, platform_layout = make_card()
        platform_layout.addWidget(make_label("01  Platform", "section"))
        platform_layout.addWidget(
            make_label(
                "Choose a platform from the installed payload catalog.",
                "muted",
            )
        )
        self.platform_grid = QGridLayout()
        self.platform_grid.setSpacing(8)
        platform_layout.addLayout(self.platform_grid)
        page.addWidget(platform_card)

        # Navigation card
        filters_card, filters_layout = make_card()
        filters_layout.addWidget(
            make_label("02  Narrow your selection", "section")
        )
        filters_layout.addWidget(
            make_label(
                "Choose a category or select All to skip a step.",
                "muted",
            )
        )

        self.filter_grids = {}
        for key, label in (
            ("arch", "ARCHITECTURE"),
            ("family", "PAYLOAD FAMILY"),
            ("transport", "TRANSPORT"),
        ):
            filters_layout.addSpacing(4)
            filters_layout.addWidget(make_label(label, "eyebrow"))
            grid = QGridLayout()
            grid.setSpacing(8)
            self.filter_grids[key] = grid
            filters_layout.addLayout(grid)

        page.addWidget(filters_card)

        # Payload selection and settings
        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.setChildrenCollapsible(False)

        payload_card, payload_layout = make_card()
        payload_layout.addWidget(
            make_label("03  Exact payload", "section")
        )
        payload_layout.addWidget(
            make_label(
                "Search the matching modules or enter a name manually.",
                "muted",
            )
        )

        self.search = QLineEdit()
        self.search.setPlaceholderText("Search payloads…")
        payload_layout.addWidget(self.search)

        self.payload_count = make_label("Choose a platform", "muted")
        payload_layout.addWidget(self.payload_count)

        self.payload_list = QListWidget()
        self.payload_list.setMinimumHeight(220)
        payload_layout.addWidget(self.payload_list)

        self.payload = QLineEdit()
        self.payload.setPlaceholderText("Selected payload")
        payload_layout.addWidget(self.payload)

        self.inspect_button = QPushButton("Inspect payload options")
        payload_layout.addWidget(self.inspect_button)

        splitter.addWidget(payload_card)

        config_card, config_layout = make_card()
        config_layout.addWidget(
            make_label("04  Configuration", "section")
        )
        config_layout.addWidget(
            make_label(
                "Inspect the payload to see its required options.",
                "muted",
            )
        )

        self.lhost = QLineEdit()
        self.lhost.setPlaceholderText("Host or IP address")
        self.add_field(config_layout, "LHOST", self.lhost)

        self.lport = QLineEdit("4444")
        self.lport.setPlaceholderText("Optional")
        self.add_field(config_layout, "LPORT", self.lport)

        self.format_box = QComboBox()
        self.format_box.setEditable(True)
        self.format_box.setInsertPolicy(
            QComboBox.InsertPolicy.NoInsert
        )
        self.format_box.lineEdit().setPlaceholderText("Choose or type a format")
        self.add_field(config_layout, "OUTPUT FORMAT", self.format_box)

        self.encoder_box = QComboBox()
        self.encoder_box.setEditable(True)
        self.encoder_box.setInsertPolicy(
            QComboBox.InsertPolicy.NoInsert
        )
        self.encoder_box.lineEdit().setPlaceholderText("Optional")
        self.add_field(config_layout, "ENCODER", self.encoder_box)

        self.extra = QLineEdit()
        self.extra.setPlaceholderText("Optional, e.g. NAME=value")
        self.add_field(config_layout, "EXTRA ARGUMENTS", self.extra)

        self.output = QLineEdit()
        self.output.setPlaceholderText("Choose an output file")
        self.add_field(config_layout, "OUTPUT FILE", self.output)

        self.output_button = QPushButton("Choose output file")
        config_layout.addWidget(self.output_button)
        config_layout.addStretch()

        splitter.addWidget(config_card)
        splitter.setSizes([570, 430])
        page.addWidget(splitter)

        action_row = QHBoxLayout()
        self.generate_button = QPushButton("Generate payload")
        self.generate_button.setObjectName("primary")
        self.copy_button = QPushButton("Copy command")
        self.clear_button = QPushButton("Clear log")

        action_row.addWidget(self.generate_button)
        action_row.addWidget(self.copy_button)
        action_row.addWidget(self.clear_button)
        action_row.addStretch()
        page.addLayout(action_row)

        preview_card, preview_layout = make_card()
        preview_layout.addWidget(
            make_label("Command preview", "section")
        )
        self.preview = QTextEdit()
        self.preview.setReadOnly(True)
        self.preview.setMaximumHeight(90)
        self.preview.setFont(QFont("Monospace", 10))
        preview_layout.addWidget(self.preview)
        page.addWidget(preview_card)

        log_card, log_layout = make_card()
        log_layout.addWidget(make_label("Activity log", "section"))
        self.log = QTextEdit()
        self.log.setReadOnly(True)
        self.log.setMinimumHeight(180)
        self.log.setFont(QFont("Monospace", 10))
        log_layout.addWidget(self.log)
        page.addWidget(log_card)

        page.addStretch()

    @staticmethod
    def add_field(layout, title, widget):
        layout.addWidget(make_label(title, "eyebrow"))
        layout.addWidget(widget)

    def connect_signals(self):
        self.browse_executable_button.clicked.connect(
            self.browse_executable
        )
        self.refresh_button.clicked.connect(self.load_catalog)
        self.output_button.clicked.connect(self.browse_output)
        self.inspect_button.clicked.connect(self.inspect_payload)
        self.generate_button.clicked.connect(self.generate)
        self.copy_button.clicked.connect(self.copy_command)
        self.clear_button.clicked.connect(self.log.clear)

        self.search.textChanged.connect(self.refresh_payload_list)
        self.payload_list.currentTextChanged.connect(
            self.payload.setText
        )

        for widget in (
            self.executable, self.payload, self.lhost,
            self.lport, self.extra, self.output,
        ):
            widget.textChanged.connect(self.update_preview)

        self.format_box.currentTextChanged.connect(self.update_preview)
        self.encoder_box.currentTextChanged.connect(self.update_preview)

    def start_worker(self, function, args, finished, failed):
        worker = Worker(function, *args)
        self.workers.add(worker)

        def on_finished(result):
            self.workers.discard(worker)
            finished(result)

        def on_failed(error):
            self.workers.discard(worker)
            failed(error)

        worker.signals.finished.connect(on_finished)
        worker.signals.failed.connect(on_failed)
        self.pool.start(worker)

    def executable_path(self):
        value = self.executable.text().strip()
        found = shutil.which(value) if value else None
        if not found:
            raise ValueError(
                "msfvenom was not found. Select its path in the sidebar."
            )
        return found

    def browse_executable(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Select msfvenom"
        )
        if path:
            self.executable.setText(path)
            self.load_catalog()

    def browse_output(self):
        path, _ = QFileDialog.getSaveFileName(
            self, "Choose output file"
        )
        if path:
            self.output.setText(path)

    def load_catalog(self):
        if self.loading:
            return

        try:
            executable = self.executable_path()
        except ValueError as exc:
            self.status.setText("msfvenom not found")
            self.append_log(str(exc))
            return

        self.loading = True
        self.refresh_button.setEnabled(False)
        self.status.setText("Loading catalog…")

        self.start_worker(
            load_catalog_worker,
            (executable,),
            self.catalog_loaded,
            self.catalog_failed,
        )

    def catalog_loaded(self, result):
        catalog, errors = result

        self.loading = False
        self.refresh_button.setEnabled(True)

        self.payloads = catalog.get("payloads", [])
        self.encoders = catalog.get("encoders", [])
        self.formats = catalog.get("formats", [])

        self.records = {
            name: classify_payload(name)
            for name in self.payloads
        }

        self.selection = {key: None for key in FILTER_KEYS}

        self.set_combo_values(self.encoder_box, self.encoders)
        self.set_combo_values(self.format_box, self.formats)
        self.render_navigation()

        self.status.setText(
            "Catalog loaded" if not errors else "Catalog incomplete"
        )
        self.append_log(
            f"Loaded {len(self.payloads)} payloads, "
            f"{len(self.encoders)} encoders, "
            f"{len(self.formats)} formats."
        )

        for error in errors:
            self.append_log(error)

    def catalog_failed(self, error):
        self.loading = False
        self.refresh_button.setEnabled(True)
        self.status.setText("Catalog failed")
        self.append_log(error)

    @staticmethod
    def set_combo_values(combo, values):
        current = combo.currentText()
        combo.blockSignals(True)
        combo.clear()
        combo.addItem("")
        combo.addItems(values)
        combo.setCurrentText(current)
        combo.blockSignals(False)

    def matching(self, through=None):
        names = []

        for name, record in self.records.items():
            accepted = True

            for index, key in enumerate(FILTER_KEYS):
                if through is not None and index >= through:
                    break

                selected = self.selection[key]
                if selected not in (None, "*") and record[index] != selected:
                    accepted = False
                    break

            if accepted:
                names.append(name)

        return names

    def render_choice_grid(self, grid, values, selected, callback,
                           platform=False):
        clear_layout(grid)

        if not values:
            grid.addWidget(make_label("Choose a platform first.", "muted"))
            return

        columns = 4
        for index, value in enumerate(values):
            if value == "*":
                label = "All"
            elif platform:
                label = PLATFORM_LABELS.get(value, value)
            else:
                label = value

            button = QPushButton(label)
            button.setObjectName("choice")
            button.setCheckable(True)
            button.setChecked(value == selected)
            button.setSizePolicy(
                QSizePolicy.Policy.Expanding,
                QSizePolicy.Policy.Fixed,
            )
            button.clicked.connect(
                lambda checked=False, current=value: callback(current)
            )
            grid.addWidget(button, index // columns, index % columns)

        for column in range(columns):
            grid.setColumnStretch(column, 1)

    def render_navigation(self):
        platforms = sorted(
            {record[0] for record in self.records.values()},
            key=str.lower,
        )

        self.render_choice_grid(
            self.platform_grid,
            platforms,
            self.selection["platform"],
            lambda value: self.choose_filter("platform", value),
            platform=True,
        )

        for index, key in enumerate(FILTER_KEYS[1:], start=1):
            if self.selection["platform"] is None:
                values = []
            else:
                names = self.matching(through=index)
                values = ["*"] + sorted(
                    {self.records[name][index] for name in names},
                    key=str.lower,
                )

            self.render_choice_grid(
                self.filter_grids[key],
                values,
                self.selection[key],
                lambda value, current=key: self.choose_filter(
                    current, value
                ),
            )

        self.refresh_payload_list()

    def choose_filter(self, key, value):
        index = FILTER_KEYS.index(key)
        self.selection[key] = value

        for later in FILTER_KEYS[index + 1:]:
            self.selection[later] = None

        self.payload.clear()
        self.search.clear()

        if key == "platform":
            suggestions = FORMAT_SUGGESTIONS.get(value, [])
            values = suggestions + [
                item for item in self.formats
                if item not in suggestions
            ]
            self.set_combo_values(self.format_box, values)
            self.format_box.setCurrentText(
                suggestions[0] if suggestions else ""
            )

        self.render_navigation()

    def refresh_payload_list(self):
        self.payload_list.blockSignals(True)
        self.payload_list.clear()

        if self.selection["platform"] is None:
            self.payload_count.setText("Choose a platform")
            self.payload_list.blockSignals(False)
            return

        query = self.search.text().strip().lower()
        names = [
            name for name in self.matching()
            if query in name.lower()
        ]

        self.payload_list.addItems(names)
        self.payload_count.setText(f"{len(names)} matching payloads")
        self.payload_list.blockSignals(False)

    def build_command(self):
        command = [
            self.executable.text().strip() or "msfvenom",
            "-p", self.payload.text().strip(),
            "-f", self.format_box.currentText().strip(),
        ]

        encoder = self.encoder_box.currentText().strip()
        if encoder:
            command.extend(["-e", encoder])

        for name, widget in (
            ("LHOST", self.lhost),
            ("LPORT", self.lport),
        ):
            value = widget.text().strip()
            if value:
                command.append(f"{name}={value}")

        extra = self.extra.text().strip()
        if extra:
            command.extend(shlex.split(extra))

        command.extend(["-o", self.output.text().strip()])
        return command

    def update_preview(self):
        try:
            text = shlex.join(self.build_command())
        except ValueError as exc:
            text = f"Check extra arguments: {exc}"

        self.preview.setPlainText(text)

    def copy_command(self):
        try:
            text = shlex.join(self.build_command())
        except ValueError as exc:
            QMessageBox.warning(self, "Invalid arguments", str(exc))
            return

        QApplication.clipboard().setText(text)
        self.status.setText("Command copied")

    def append_log(self, text):
        self.log.moveCursor(self.log.textCursor().MoveOperation.End)
        self.log.insertPlainText(text.rstrip() + "\n")
        self.log.ensureCursorVisible()

    def inspect_payload(self):
        payload = self.payload.text().strip()
        if not payload:
            QMessageBox.warning(
                self, "Missing payload", "Select a payload first."
            )
            return

        try:
            executable = self.executable_path()
        except ValueError as exc:
            QMessageBox.warning(self, "msfvenom not found", str(exc))
            return

        self.append_log(f"\n--- Options for {payload} ---")

        self.start_worker(
            command_worker,
            ([executable, "-p", payload, "--list-options"], 120),
            self.inspect_finished,
            lambda error: self.append_log(f"Inspection failed: {error}"),
        )

    def inspect_finished(self, result):
        code, output = result
        self.append_log(output)
        if code:
            self.append_log(f"Inspection exited with code {code}.")

    def generate(self):
        if self.generating:
            return

        try:
            executable = self.executable_path()
            command = self.build_command()
        except ValueError as exc:
            QMessageBox.warning(self, "Cannot generate", str(exc))
            return

        for value, label in (
            (self.payload.text().strip(), "Payload"),
            (self.format_box.currentText().strip(), "Output format"),
            (self.output.text().strip(), "Output file"),
        ):
            if not value:
                QMessageBox.warning(
                    self, "Missing field", f"{label} is required."
                )
                return

        port = self.lport.text().strip()
        if port and (
            not port.isdigit() or not 1 <= int(port) <= 65535
        ):
            QMessageBox.warning(
                self, "Invalid port",
                "LPORT must be between 1 and 65535.",
            )
            return

        output = Path(self.output.text().strip()).expanduser()
        if not output.parent.is_dir():
            QMessageBox.warning(
                self, "Invalid output",
                "The output directory does not exist.",
            )
            return

        if output.exists():
            answer = QMessageBox.question(
                self,
                "Overwrite file?",
                f"This file already exists:\n\n{output}\n\nOverwrite it?",
                QMessageBox.StandardButton.Yes
                | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No,
            )
            if answer != QMessageBox.StandardButton.Yes:
                return

        command[0] = executable
        command[-1] = str(output)

        self.generating = True
        self.generate_button.setEnabled(False)
        self.status.setText("Generating…")
        self.append_log(f"\n$ {shlex.join(command)}")

        self.start_worker(
            command_worker,
            (command, 300),
            self.generation_finished,
            self.generation_failed,
        )

    def generation_finished(self, result):
        code, output = result
        self.generating = False
        self.generate_button.setEnabled(True)
        self.append_log(output)

        if code == 0:
            self.status.setText("Completed")
            self.append_log("Completed successfully.")
        else:
            self.status.setText("Failed")
            self.append_log(f"Exited with code {code}.")

    def generation_failed(self, error):
        self.generating = False
        self.generate_button.setEnabled(True)
        self.status.setText("Failed")
        self.append_log(f"Generation failed: {error}")


if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    app.setStyleSheet(APP_STYLE)

    window = MainWindow()
    window.show()

    sys.exit(app.exec())
