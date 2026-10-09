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
    "&Re-run full analysis": "重新运行完整分析(&R)",
    "Drop a .pcap / .pcapng file here to analyze it": (
        "把 .pcap / .pcapng 文件拖到这里，立即开始分析"
    ),
    "…or use File > Open capture. Analysis starts automatically.": (
        "…也可以用“文件 > 打开抓包”。分析会自动开始。"
    ),
    "TShark ready: ": "TShark 就绪：",
    "TShark was not found — install Wireshark or set the path in Settings.": (
        "未找到 TShark——请安装 Wireshark，或在“设置”中指定路径。"
    ),
    "Overview": "解题向导",
    "Files": "文件",
    "Flag format (regex):": "Flag 格式（正则）：",
    "Rescan": "重新扫描",
    "Search everywhere:": "全局搜索：",
    "keyword, e.g. flag / password / PK": "关键字，如 flag / password / PK",
    "Search": "搜索",
    "Search results": "搜索结果",
    "matches": "命中",
    "blobs scanned": "已扫描数据块",
    "Variant": "变体",
    "Offset": "偏移",
    "Context": "上下文",
    "Protocol hierarchy: ": "协议分级：",
    "Challenge types:": "题型判定：",
    "Type": "题型",
    "Evidence": "证据",
    "Suggestion": "建议",
    "Next steps:": "下一步：",
    "Exam points:": "考点：",
    "Operation log:": "操作记录：",
    "Technical details": "技术细节",
    "How to use": "怎么用",
    "&Help": "帮助(&H)",
    "&How to use": "怎么用(&H)",
    "Export analysis bundle…": "导出分析包…",

    "Name": "名称",
    "Media type": "媒体类型",
    "Magic": "文件头",
    "Bytes": "字节",
    "SHA-256": "SHA-256",
    "Stream": "流",
    "Frames": "帧范围",
    "Flag": "Flag",
    "Exam point": "考点",
    "What to look at": "看哪里",
    "Next action": "建议",
    "What happened": "发生了什么",
    "known-flag": "已知 Flag 格式",
    "sensitive-field": "敏感字段",
    "unknown-token": "疑似 Flag",
    "credential": "凭据",
    "SQL injection": "SQL 注入",
    "WebShell": "WebShell",
    "USB keyboard": "USB 键盘",
    "HTTP status/body mismatch": "HTTP 状态/正文矛盾",
    "Typed keys:": "键盘输入：",
    "HTTP error status contradicts response body": "HTTP 错误状态与响应正文矛盾",
    "Static WebShell activity": "静态 WebShell 行为",
    "USB HID boot-keyboard-like endpoint": "USB HID 键盘端点",
    "Password-protected archive": "加密压缩包",
    "Repaired zeroed PCAP global header": "已修复被清空的 PCAP 文件头",
    "Not a packet capture; nested files inside": "这不是抓包文件，里面嵌套了压缩包/图片",
    (
        "Search the same capture for a password (HTTP, Telnet, FTP, USB keys), "
        "then open the archive outside Auto-Shark."
    ): "先在同一份流量里找密码（HTTP / Telnet / FTP / USB 按键），再在 Auto-Shark 外打开压缩包。",
    (
        "Continue on the repaired copy. The HTTP body in this challenge pattern "
        "often carries the flag after the header is restored."
    ): "继续看修复后的副本。这类题的 HTTP 正文里经常直接带着 flag。",
    (
        "Open the carved zip/rar/images from the Files page outside Auto-Shark. "
        "Encrypted archives need a password found in the same challenge."
    ): "到“文件”页导出嵌套的 zip/rar/图片，在 Auto-Shark 外打开。加密包要先在同一题里找到密码。",
    "Review the finding evidence links.": "到发现页查看该条证据。",
    (
        "Follow the operation timeline: uploads, directory listings, "
        "file writes/reads, and encoded command traffic."
    ): "按操作记录看上传、列目录、读写文件和编码命令。",
    "Review key-down/release edges and correlate held keys with other USB devices.": (
        "把按键序列拼起来；Shift 会把 [ ] - 变成 { } _。"
    ),
    "Reconstruct TFTP uploads and downloads": "重建 TFTP 上传和下载",
    "Reconstruct and inspect generic TCP data streams": "重建并检查通用 TCP 数据流",
    "Inspect ICMP echo side channels and printable TTL oracles": (
        "检查 ICMP 回显隐蔽信道和可打印 TTL 旁路"
    ),
    "file-write": "写文件",
    "file-read": "读文件",
    "command-exec": "命令执行",
    "Flag candidates (double-click to copy):": "Flag 候选（双击复制）：",
    "No challenge type recognized yet. Standard checklist:": (
        "暂未识别出题型，按通用五步清单排查："
    ),
    "Open in Explorer": "在资源管理器中打开",
    "View content": "查看内容",
    "View request body": "查看请求内容",
    "View response body": "查看响应内容",
    "Select a file first.": "请先选择一个文件。",
    "Select a row first.": "请先选择一行。",
    "Copied: ": "已复制：",
    "error: file missing": "错误：文件不存在",
    "No stored body for this message (absent or not extracted).": (
        "该报文没有已存储的正文（缺失或未提取）。"
    ),
    "No stored stream content (run tcp-text/telnet stages first).": (
        "该流没有已存储的内容（请先运行 tcp-text / telnet 阶段）。"
    ),
    "No Telnet preview stored (run the telnet stage first).": (
        "没有 Telnet 预览（请先运行 telnet 阶段）。"
    ),
    "No extracted files yet. They appear after the scan stage "
    "(run the full analysis first).": (
        "暂无提取文件。文件会在 scan 阶段（完整分析）后出现在这里。"
    ),
    "Re-rank candidates with the new flag format": "用新的 flag 格式重新排列候选",
    "Re-run detectors": "重新运行检测器",
    "&Cancel running analysis": "取消正在运行的分析(&C)",
    "&Refresh page": "刷新页面(&F)",
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
    "Check": "检测",
    "Check result": "检测结果",
    "Usable: yes": "可用：是",
    "Usable: no": "可用：否",
    "Capabilities:": "能力：",
    "Click Check after choosing tshark.exe. Need Wireshark 4.0 or newer.": (
        "选好 tshark.exe 后点“检测”。需要 Wireshark 4.0 或更高版本。"
    ),
    (
        "Local CTF analysis only needs TShark (it comes with Wireshark 4). "
        "The remote Linux node is an optional extra for image/stego tools; "
        "ordinary traffic challenges do not use it."
    ): (
        "本地做流量题只需要 TShark（Wireshark 4 自带）。"
        "下面的远程 Linux 节点是给图片隐写等额外工具用的，普通流量题不用填。"
    ),
    "Show advanced: remote Linux node (optional)": "显示高级选项：远程 Linux 节点（可选）",
    (
        "Optional Linux helper for extra tools (zsteg, binwalk, …). "
        "Local traffic challenges do not need this. Protocol is SSH + SFTP only. "
        "Host is user@IP or user@domain, for example ctf@192.168.1.10. "
        "Port defaults to 22. Passwords are not supported — use an OpenSSH "
        "private key or ssh-agent. Probe tests the connection; saving only "
        "stores the settings. Main analysis still runs locally with TShark."
    ): (
        "这是可选的 Linux 增强节点，用来跑 zsteg / binwalk 等额外工具。"
        "本地流量题不用填。协议只有 SSH + SFTP。"
        "主机填 user@IP 或 user@域名，例如 ctf@192.168.1.10。"
        "端口默认 22。不支持密码登录，请用 OpenSSH 私钥或 ssh-agent。"
        "点“探测远程节点”测试连通；保存只是记下设置。主分析仍在本地用 TShark。"
    ),
    "SSH user@host": "SSH 用户@主机",
    "SSH port": "SSH 端口",
    "SSH private key": "SSH 私钥",
    "Optional private key; empty uses ssh-agent / default keys": (
        "可选私钥；留空则使用 ssh-agent 或默认密钥"
    ),
    "Leave empty to auto-detect OpenSSH": "留空则自动检测 OpenSSH",
    "Choose SSH private key": "选择 SSH 私钥",
    (
        "This TShark is too old (found {found}, need ≥ 4.0). "
        "Install Wireshark 4, or in Settings choose the tshark.exe from a portable "
        "Wireshark 4."
    ): (
        "这个 tshark 版本过低（当前 {found}，需要 ≥ 4.0）。"
        "请安装 Wireshark 4，或在设置中选择便携版里的 tshark.exe。"
    ),
    "Probe remote node": "探测远程节点",
    "Probe result": "探测结果",
    "TShark executable": "TShark 可执行文件",
    "Legacy TLS RSA private key (optional)": "旧版 TLS RSA 私钥（可选）",
    "TLS keylog file (optional)": "TLS keylog 文件（可选）",
    "Choose TLS keylog file": "选择 TLS keylog 文件",
    "Cannot load TLS keylog file: ": "无法加载 TLS keylog 文件：",
    "Auto-detected TLS keylog: ": "自动检测到 TLS keylog：",
    "Choose TLS RSA private key": "选择 TLS RSA 私钥",
    "Cannot load TLS RSA private key: ": "无法加载 TLS RSA 私钥：",
    "Recover SMTP messages and MIME attachments": "恢复 SMTP 邮件和 MIME 附件",
    "Index directional Telnet dialogues": "索引 Telnet 双向对话",
    "Analysis finished.": "分析完成。",
    "Analysis finished; the following stages were skipped:\n": (
        "分析完成，以下阶段被跳过：\n"
    ),
    "Skipped stages do not block the remaining results.": (
        "被跳过的阶段不影响其余分析结果。"
    ),
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
    "How to use Auto-Shark": "怎么用 Auto-Shark",
    (
        "1. Drag a .pcap / .pcapng onto the window (or File > Open capture). "
        "Analysis starts automatically.\n"
        "2. Read the solve wizard: protocol mix, challenge type, and flag "
        "candidates. Double-click a suggestion to jump to the evidence.\n"
        "3. Double-click a flag candidate to copy it. If the contest uses a "
        "custom wrapper, enter that regex and press Rescan.\n"
        "4. Files lists exported objects. HTTP and TCP streams follow the "
        "conversation. Telnet appears only when that traffic exists.\n"
        "5. Findings lists flags, exam points, and the reconstructed "
        "operation log. Tick Technical details for the raw JSON.\n"
        "Search everywhere is the strings | grep replacement "
        "(plain text, hex, and Base64)."
    ): (
        "1. 把 .pcap / .pcapng 拖进窗口（或用“文件 > 打开抓包”）。分析会自动开始。\n"
        "2. 先看解题向导：协议构成、题型判定、Flag 候选。双击一条建议即可跳到证据。\n"
        "3. 双击 Flag 候选即可复制。比赛若有自定义外壳，填入正则后点“重新扫描”。\n"
        "4. “文件”是导出对象；HTTP / TCP 流用来跟会话。只有出现 Telnet 流量时才会显示该页。\n"
        "5. “发现”列出 Flag、考点和还原出的操作记录。需要原始 JSON 时再勾选“技术细节”。\n"
        "“全局搜索”相当于 strings | grep，同时覆盖明文、十六进制和 Base64。"
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
