"""Small runtime language layer for the optional Qt client.

The core and CLI remain locale-neutral.  The GUI selects Simplified Chinese
only for a Chinese system locale and deliberately falls back to English for
every other or unknown locale.
"""

from __future__ import annotations

import locale
import os
import sys
from contextlib import suppress
from typing import Optional

SUPPORTED_LANGUAGES = ("en", "zh")

_ZH: dict[str, str] = {
    "&File": "文件(&F)",
    "&Edit": "编辑(&E)",
    "&Analysis": "分析(&A)",
    "&Open capture…": "打开抓包(&O)…",
    "Open &project…": "打开项目(&P)…",
    "&New project from capture…": "从抓包新建项目(&N)…",
    "E&xit": "退出(&X)",
    "&Settings…": "设置(&S)…",
    "&Run full analysis": "运行完整分析(&R)",
    "&Cancel running analysis": "取消正在运行的分析(&C)",
    "&Refresh page": "刷新页面(&F)",
    "Overview": "概览",
    "HTTP": "HTTP",
    "Streams": "TCP 流",
    "Telnet": "Telnet",
    "Findings": "发现",
    "Timeline": "时间线",
    "Manual queue": "人工队列",
    "Notes": "笔记",
    "Export": "导出",
    "No project open": "未打开项目",
    "No project open — use File > Open project.": "未打开项目，请使用“文件 > 打开项目”。",
    "Report JSON (bounded preview of report/v1):": "报告 JSON（report/v1 的有界预览）：",
    "URI filter:": "URI 过滤：",
    "exact URI or empty": "精确 URI，留空表示不过滤",
    "Apply": "应用",
    "Previous": "上一页",
    "Next": "下一页",
    "Previous candidates": "上一页候选",
    "Next candidates": "下一页候选",
    "Candidates:": "候选：",
    "Findings:": "发现：",
    "Event kind:": "事件类型：",
    "optional, e.g. file-write": "可选，例如 file-write",
    "Include duplicates": "包含重复项",
    "State:": "状态：",
    "all": "全部",
    "Change state of selected…": "修改选中任务状态…",
    "Add note / review mark:": "添加笔记 / 复核标记：",
    "Add note": "添加笔记",
    "Apply review mark": "应用复核标记",
    "Update selected note body": "更新选中笔记内容",
    "Include bounded evidence directory": "包含有界证据目录",
    "Choose directory and export bundle…": "选择目录并导出分析包…",
    "Last export result:": "最近一次导出结果：",
    "Auto-Shark settings": "Auto-Shark 设置",
    "Auto-Shark analysis": "Auto-Shark 分析",
    "Auto-Shark export": "Auto-Shark 导出",
    "Browse…": "浏览…",
    "Probe": "探测",
    "Probe remote node": "探测远程节点",
    "Probe result": "探测结果",
    "TShark executable": "TShark 可执行文件",
    "Legacy TLS RSA private key (optional)": "旧版 TLS RSA 私钥（可选）",
    "Choose TLS RSA private key": "选择 TLS RSA 私钥",
    "Cannot load TLS RSA private key: ": "无法加载 TLS RSA 私钥：",
    "Recover SMTP messages and MIME attachments": "恢复 SMTP 邮件和 MIME 附件",
    "Remote host (optional)": "远程主机（可选）",
    "ssh executable": "ssh 可执行文件",
    "sftp executable": "sftp 可执行文件",
    "Remote working root": "远程工作目录",
    "Remote paths to probe": "待探测的远程路径",
    "New project from capture": "从抓包新建项目",
    "Capture file": "抓包文件",
    "Project directory": "项目目录",
    "Choose capture": "选择抓包文件",
    "Choose project directory": "选择项目目录",
    "Choose tshark executable": "选择 tshark 可执行文件",
    "Open capture": "打开抓包",
    "Open Auto-Shark project": "打开 Auto-Shark 项目",
    "Choose a new or empty export directory": "选择新的或空的导出目录",
    "Capture and project paths are required.": "必须填写抓包路径和项目路径。",
    "Subject kind": "主体类型",
    "Subject ID": "主体 ID",
    "Note body": "笔记内容",
    "Review mark": "复核标记",
    "Change manual task state": "修改人工任务状态",
    "New state": "新状态",
    "Preparing analysis…": "准备分析…",
    "Running: ": "正在运行：",
    "Cancel": "取消",
    "Exporting bounded bundle…": "正在导出有界分析包…",
    "Metric": "指标",
    "Value": "值",
    "Frame": "帧",
    "Method": "方法",
    "Host": "主机",
    "URI": "URI",
    "Status": "状态",
    "Code": "状态码",
    "Parameter": "参数",
    "Source": "来源",
    "Conversation": "会话",
    "Endpoints": "端点",
    "Direction": "方向",
    "Output bytes": "输出字节",
    "Current": "当前状态",
    "Client bytes": "客户端字节",
    "Server bytes": "服务端字节",
    "Records": "记录数",
    "Rank": "排名",
    "Kind": "类型",
    "Confidence": "置信度",
    "Subject": "主体",
    "Frame start": "起始帧",
    "Target": "目标",
    "Group": "分组",
    "Priority": "优先级",
    "State": "状态",
    "Signals": "信号数",
    "Note ID": "笔记 ID",
    "Body": "内容",
    "Cannot open project: ": "无法打开项目：",
    "Cannot create project: ": "无法创建项目：",
    "Cannot save settings: ": "无法保存设置：",
    "Open a project first.": "请先打开一个项目。",
    "Select a note first.": "请先选择一条笔记。",
    "Select a task first.": "请先选择一个任务。",
    "Enter the new body first.": "请先输入新的内容。",
    "Subject ID and body are required.": "主体 ID 和内容不能为空。",
    "Subject ID is required.": "主体 ID 不能为空。",
    "Enter a TShark path first.": "请先填写 TShark 路径。",
    "Enter a remote host first.": "请先填写远程主机。",
    "error: ssh and sftp clients not found": "错误：未找到 ssh 和 sftp 客户端",
    "error: ": "错误：",
    "Export finished.": "导出完成。",
    "Ready to export a bounded offline bundle.": "可以导出有界离线分析包。",
    "Overview ready.": "概览已就绪。",
    "Showing": "显示",
    "of": "共",
    "at offset": "偏移",
    " — more available": "，还有更多结果",
    "(duplicates included)": "（包含重复项）",
    "coverage: ": "覆盖状态：",
    "truncated collections: ": "已截断集合：",
    "unreviewed": "未复核",
    "needs_review": "需要复核",
    "excluded": "已排除",
    "key_evidence": "关键证据",
    "open": "开放",
    "in-progress": "进行中",
    "resolved": "已解决",
    "dismissed": "已忽略",
    "candidate": "候选",
    "finding": "发现",
    "artifact": "文件产物",
    "behavior-event": "行为事件",
    "manual-task": "人工任务",
    "evidence": "证据",
    "Capture SHA-256": "抓包 SHA-256",
    "Capture bytes": "抓包字节数",
    "Database schema": "数据库架构",
    "Capture": "抓包",
    "error: the GUI requires the optional 'gui' extra (PySide6):": (
        "错误：GUI 需要可选的“gui”依赖（PySide6）："
    ),
    "install it with: uv sync --extra gui  or  pip install auto-shark[gui]": (
        "请使用以下命令安装：uv sync --extra gui 或 pip install auto-shark[gui]"
    ),
    "error: no usable display for the GUI": "错误：GUI 没有可用的显示环境",
    "error: the GUI could not start": "错误：GUI 启动失败",
    "Use the command-line interface instead: auto-shark --help": (
        "请改用命令行界面：auto-shark --help"
    ),
    "Extract HTTP metadata, bodies, and transforms": "提取 HTTP 元数据、正文和转换结果",
    "Correlate FTP control and data transfers": "关联 FTP 控制连接和数据传输",
    "Apply transforms and carve static files": "应用转换并提取静态文件",
    "Rank known-format and sensitive-field candidates": "排列已知格式和敏感字段候选",
    "Run unknown-candidate, SQL-injection, and WebShell detectors": (
        "运行未知候选、SQL 注入和 WebShell 检测器"
    ),
    "Build capture summary and manual queue": "生成抓包摘要和人工队列",
    "Triage encoded DNS labels and recover validated files": (
        "分析编码型 DNS 标签并恢复已验证文件"
    ),
    "Inspect TCP urgent-pointer side channels": "检查 TCP 紧急指针隐蔽信道",
    "Triage USB HID input report series": "分析 USB HID 输入报告序列",
    "Reconstruct supported RTP audio and preserve VoIP hints": (
        "重建受支持的 RTP 音频并保留 VoIP 线索"
    ),
}


def _is_chinese(value: Optional[str]) -> bool:
    if not value:
        return False
    normalized = value.strip().lower().replace("_", "-")
    return normalized == "zh" or normalized.startswith("zh-")


def _windows_locale() -> Optional[str]:
    if sys.platform != "win32":
        return None
    try:
        import ctypes

        buffer = ctypes.create_unicode_buffer(85)
        length = ctypes.windll.kernel32.GetUserDefaultLocaleName(buffer, len(buffer))
        return buffer.value if length else None
    except (AttributeError, OSError, TypeError):
        return None


def detect_language() -> str:
    """Return ``zh`` for Chinese OS locales and ``en`` for everything else."""
    override = os.environ.get("AUTO_SHARK_LANGUAGE")
    if override:
        return "zh" if _is_chinese(override) else "en"
    candidates = [
        _windows_locale(),
        os.environ.get("LC_ALL"),
        os.environ.get("LANG"),
        os.environ.get("LANGUAGE"),
    ]
    with suppress(ValueError, TypeError):
        candidates.append(locale.getlocale()[0])
    return "zh" if any(_is_chinese(value) for value in candidates) else "en"


def translate(text: str, language: Optional[str] = None) -> str:
    """Translate a UI string; unknown strings intentionally stay unchanged."""
    if (language or detect_language()) != "zh":
        return text
    return _ZH.get(text, text)


def apply_widget_translations(root: object, language: Optional[str] = None) -> None:
    """Translate already-built Qt widgets without importing Qt in CLI paths."""
    if (language or detect_language()) != "zh":
        return
    from PySide6.QtGui import QAction
    from PySide6.QtWidgets import (
        QAbstractButton,
        QComboBox,
        QDialog,
        QLabel,
        QLineEdit,
        QListWidget,
        QMenu,
        QTableWidget,
        QWidget,
    )

    widgets = [root, *root.findChildren(QWidget)]  # type: ignore[attr-defined]
    for widget in widgets:
        if isinstance(widget, QAbstractButton):
            widget.setText(translate(widget.text(), "zh"))
        if isinstance(widget, QLabel):
            widget.setText(translate(widget.text(), "zh"))
        if isinstance(widget, QLineEdit):
            widget.setPlaceholderText(translate(widget.placeholderText(), "zh"))
        if isinstance(widget, QComboBox):
            for index in range(widget.count()):
                widget.setItemText(index, translate(widget.itemText(index), "zh"))
        if isinstance(widget, QListWidget):
            for index in range(widget.count()):
                item = widget.item(index)
                item.setText(translate(item.text(), "zh"))
        if isinstance(widget, QTableWidget):
            for index in range(widget.columnCount()):
                header = widget.horizontalHeaderItem(index)
                if header is not None:
                    header.setText(translate(header.text(), "zh"))
        if isinstance(widget, QDialog):
            widget.setWindowTitle(translate(widget.windowTitle(), "zh"))
    for action in root.findChildren(QAction):  # type: ignore[attr-defined]
        action.setText(translate(action.text(), "zh"))
    for menu in root.findChildren(QMenu):  # type: ignore[attr-defined]
        menu.setTitle(translate(menu.title(), "zh"))
