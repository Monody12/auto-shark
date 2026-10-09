"""Challenge-type wizard for CTF players.

Composes the already-indexed read models into the decision funnel a player
follows by hand: protocol hierarchy, a challenge-type verdict with evidence
and a one-click destination, ranked flag candidates, and an honest fallback
checklist when nothing fires. Pure logic over the project database so the
GUI stays thin and the rules stay unit-testable.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from .m4_queries import query_findings
from .project import read_flag_format
from .queries import query_streams, query_summary, query_transactions
from .reporting import collect_report

FALLBACK_STEPS = (
    ("1. 纵览全局", "协议分级看主体：HTTP→Web 方向；USB→键鼠还原；DNS→外带数据。"),
    ("2. 导出对象", "把传输的文件全部导出（文件页），图片/压缩包常藏 flag。"),
    ("3. 关键字盲搜", "在 HTTP/流页搜 flag、password、admin，及编码形式 666c6167 / ZmxhZ3s。"),
    ("4. 追踪流", "对可疑会话查看内容（各页“查看内容”），红蓝分向看上下文。"),
    ("5. 自动化提取", "DNS 拼接、ICMP、USB 键码等批量场景用 tshark 字段导出+脚本。"),
)

_WIZARD_SCHEMA = "auto-shark.wizard/v1"
_TRANSACTION_SCAN_LIMIT = 1000


@dataclass(frozen=True)
class WizardSuggestion:
    """One challenge-type verdict: what was seen and where to look next."""

    kind: str
    title: str
    evidence: str
    detail: str
    action: str  # GUI destination: files/http/streams/telnet/findings/timeline
    weight: int = 0


def _payload(result: object) -> dict:
    if isinstance(result, dict):
        return result
    return json.loads(result.to_json())  # type: ignore[attr-defined]


# Link/network/transport labels exist on nearly every frame and drown the
# application-layer protocols a player actually scans for.
_NOISE_PROTOCOL_LABELS = frozenset(
    {"eth", "ethertype", "ip", "ipv6", "tcp", "udp", "arp", "lldp", "frame"}
)


def _protocol_hierarchy(summary: dict) -> list[dict]:
    protocols = list(summary.get("protocols") or [])
    # The per-frame link-layer label (eth) approximates the frame total,
    # matching how a player reads Wireshark's protocol hierarchy percentages.
    total = max((int(item.get("frame_count") or 0) for item in protocols), default=0) or 1
    ranked = sorted(
        protocols,
        key=lambda item: (
            str(item.get("protocol_label")) in _NOISE_PROTOCOL_LABELS,
            -int(item.get("frame_count") or 0),
        ),
    )
    hierarchy = []
    for item in ranked[:8]:
        frames = int(item.get("frame_count") or 0)
        hierarchy.append(
            {
                "label": str(item.get("protocol_label")),
                "frames": frames,
                "share": round(frames * 100.0 / total, 1),
            }
        )
    return hierarchy


def _http_suggestions(root: Path, summary: dict) -> list[WizardSuggestion]:
    try:
        page = _payload(query_transactions(root, offset=0, limit=_TRANSACTION_SCAN_LIMIT))
    except (OSError, ValueError, KeyError):
        return []
    items = list(page.get("items") or [])
    suggestions: list[WizardSuggestion] = []
    posts = []
    codes: dict[str, int] = {}
    for item in items:
        request = item.get("request") or {}
        response = item.get("response") or {}
        method = str(request.get("method") or "").upper()
        uri = str(request.get("uri") or "")
        if method == "POST":
            posts.append((request, uri))
        code = response.get("code")
        if code:
            codes[str(code)] = codes.get(str(code), 0) + 1
    upload_posts = [
        (request, uri)
        for request, uri in posts
        if re.search(r"upload|file|shell|cmd|pass|login", uri, re.IGNORECASE)
    ]
    if upload_posts:
        request, uri = upload_posts[0]
        suggestions.append(
            WizardSuggestion(
                kind="http-upload",
                title="HTTP 文件上传流量",
                evidence=(
                    f"POST {uri}（帧 {request.get('frame')}），"
                    f"共 {len(upload_posts)} 个可疑上传请求"
                ),
                detail="上传的图片/压缩包常藏 flag：去“文件”页看导出对象，"
                "或回 HTTP 页跟流看 multipart 正文。",
                action="files",
                weight=90,
            )
        )
    not_found = codes.get("404", 0)
    ok = codes.get("200", 0)
    if not_found >= 20 and ok > 0:
        suggestions.append(
            WizardSuggestion(
                kind="directory-bruteforce",
                title="目录爆破流量",
                evidence=f"{not_found}×404 / {ok}×200（共 {len(items)} 个 HTTP 事务）",
                detail="重点看 200/403 的请求：命令执行、备份文件、怪文件名"
                "通常就藏在爆破命中的几条里。",
                action="http",
                weight=70,
            )
        )
    if not items and any(
        str(entry.get("protocol_label")) == "http"
        for entry in list(summary.get("protocols") or [])
    ):
        suggestions.append(
            WizardSuggestion(
                kind="http-analysis-missing",
                title="HTTP 分析未运行",
                evidence="捕获中存在 http 协议，但未索引到任何 HTTP 事务",
                detail="基础分析失败或未完成。请用“分析 → 重新运行完整分析”重跑；"
                "若仍失败，请在“编辑 → 设置”检查 TShark 路径与版本（需要 4.x+）。",
                action="http",
                weight=99,
            )
        )
    return suggestions


def _finding_suggestions(root: Path) -> list[WizardSuggestion]:
    try:
        page = _payload(
            query_findings(
                root,
                candidate_limit=50,
                candidate_offset=0,
                finding_offset=0,
                finding_limit=50,
            )
        )
    except (OSError, ValueError, KeyError):
        return []
    suggestions: list[WizardSuggestion] = []
    detectors = {}
    for finding in list(page.get("findings") or []):
        detector = str(finding.get("detector") or "")
        detectors[detector] = detectors.get(detector, 0) + 1
    for detector, count in detectors.items():
        if "sql" in detector:
            suggestions.append(
                WizardSuggestion(
                    kind="sql-injection",
                    title="SQL 注入流量",
                    evidence=f"{count} 条注入相关发现",
                    detail="盲注题：去 HTTP 页提取 http.request.uri 序列，"
                    "按二分/布尔边界还原被注入出来的数据。",
                    action="http",
                    weight=85,
                )
            )
        elif "webshell" in detector or "shell" in detector:
            suggestions.append(
                WizardSuggestion(
                    kind="webshell",
                    title="WebShell 通信（如菜刀/蚁剑）",
                    evidence=f"{count} 条 WebShell 行为发现",
                    detail="去“发现”页的操作记录看命令执行序列；POST 参数里的 base64 "
                    "通常已在候选里解码。",
                    action="findings",
                    weight=88,
                )
            )
        elif "ognl" in detector or "struts" in detector:
            suggestions.append(
                WizardSuggestion(
                    kind="ognl-rce",
                    title="Struts/OGNL 命令执行",
                    evidence=f"{count} 条 OGNL 相关发现",
                    detail="去“发现”页的操作记录看执行的命令与回显，flag 常在回显正文里。",
                    action="findings",
                    weight=86,
                )
            )
        elif detector == "pcap-header-repair":
            suggestions.append(
                WizardSuggestion(
                    kind="pcap-header-repair",
                    title="抓包文件头被清空，已自动修复",
                    evidence=f"{count} 条文件头修复记录",
                    detail="原文件头 24 字节全是 0，已在项目内生成修复副本。"
                    "残缺 TCP 上的 HTTP 正文 TShark 可能解不出；"
                    "去“发现”页看文件内搜到的 flag。",
                    action="findings",
                    weight=92,
                )
            )
        elif detector == "password-protected-archive":
            suggestions.append(
                WizardSuggestion(
                    kind="password-protected-archive",
                    title="加密压缩包",
                    evidence=f"{count} 个带密码的 zip/rar",
                    detail="Auto-Shark 不会爆破。去“文件”页导出，再在同一份流量里"
                    "找密码（HTTP / Telnet / FTP / USB 按键），然后在站外打开。",
                    action="files",
                    weight=84,
                )
            )
        elif detector == "nested-container":
            suggestions.append(
                WizardSuggestion(
                    kind="nested-container",
                    title="这不是抓包，里面嵌套了文件",
                    evidence=f"{count} 个非 pcap 容器",
                    detail="打开的是 MP3/图片/压缩包。嵌套的 zip/rar/图片已放到“文件”页；"
                    "加密包先找密码，再在 Auto-Shark 外打开。",
                    action="files",
                    weight=93,
                )
            )
    return suggestions


def _protocol_suggestions(summary: dict) -> list[WizardSuggestion]:
    counts = {
        str(item.get("protocol_label")): int(item.get("frame_count") or 0)
        for item in list(summary.get("protocols") or [])
    }
    suggestions: list[WizardSuggestion] = []
    if counts.get("usb") or counts.get("usbhid"):
        suggestions.append(
            WizardSuggestion(
                kind="usb-hid",
                title="USB 外设流量（键鼠还原）",
                evidence=f"usb 帧 {counts.get('usb') or counts.get('usbhid')}",
                detail="键盘题：去“发现”页看按键序列；鼠标轨迹题需要把坐标连线。",
                action="findings",
                weight=80,
            )
        )
    if counts.get("telnet"):
        suggestions.append(
            WizardSuggestion(
                kind="telnet-credentials",
                title="Telnet 远程登录",
                evidence=f"telnet 帧 {counts['telnet']}",
                detail="登录凭据/命令回显通常直接明文在对话里，去 Telnet 页"
                "“查看内容”。",
                action="telnet",
                weight=78,
            )
        )
    if counts.get("ftp") or counts.get("ftp-data"):
        suggestions.append(
            WizardSuggestion(
                kind="ftp-transfer",
                title="FTP 文件传输",
                evidence=f"ftp 帧 {counts.get('ftp') or counts.get('ftp-data')}",
                detail="传输的文件已重建：去“文件”页；凭据在控制流明文里，"
                "去 TCP 流页跟流。",
                action="files",
                weight=76,
            )
        )
    if counts.get("dns"):
        # Rank with the same noise demotion the hierarchy view uses: raw
        # frame-count ordering puts eth/ip/tcp first and would hide DNS on
        # HTTP challenges that merely have background DNS lookups.
        dns_ranked = sorted(
            list(summary.get("protocols") or []),
            key=lambda item: (
                str(item.get("protocol_label")) in _NOISE_PROTOCOL_LABELS,
                -int(item.get("frame_count") or 0),
            ),
        )
        top_labels = [str(item.get("protocol_label")) for item in dns_ranked[:3]]
        dns_share = counts["dns"] * 100.0 // max(
            (int(item.get("frame_count") or 0) for item in summary.get("protocols") or []),
            default=1,
        )
        dns_significant = ("dns" in top_labels and dns_share >= 30) or (
            counts["dns"] >= 100 and dns_share >= 10
        )
        if dns_significant:
            suggestions.append(
                WizardSuggestion(
                    kind="dns-tunnel",
                    title="DNS 查询流量占比异常",
                    evidence=f"dns 帧 {counts['dns']}，位于协议前列",
                    detail="疑似 DNS 外带/隧道：查询名前缀的 hex/base32/base64 "
                    "分段已在分析阶段拼接，去“发现”页看解码候选与恢复的文件。",
                    action="findings",
                    weight=82,
                )
            )
    if counts.get("icmp"):
        suggestions.append(
            WizardSuggestion(
                kind="icmp-channel",
                title="ICMP 隐蔽信道",
                evidence=f"icmp 帧 {counts['icmp']}",
                detail="data 载荷已按帧序拼接（候选里找拼接结果）；"
                "TTL 逐字符旁信道也已检查，见“发现”页。",
                action="findings",
                weight=72,
            )
        )
    return suggestions


def _stream_suggestions(root: Path, summary: dict) -> list[WizardSuggestion]:
    """Point at reconstructed TCP payloads when there is no HTTP/Telnet to follow."""

    labels = {
        str(item.get("protocol_label"))
        for item in list(summary.get("protocols") or [])
    }
    if "http" in labels or "telnet" in labels or "ftp" in labels:
        return []
    try:
        page = _payload(query_streams(root, offset=0, limit=32))
    except (OSError, ValueError, KeyError):
        return []
    items = list(page.get("items") or [])
    payloads = []
    for item in items:
        bytes_info = item.get("bytes") or {}
        output = int(bytes_info.get("output") or item.get("output_bytes") or 0)
        if output > 0:
            payloads.append((item, output))
    if not payloads:
        return []
    largest = max(output for _item, output in payloads)
    stream = payloads[0][0]
    stream_index = stream.get("stream_index")
    return [
        WizardSuggestion(
            kind="tcp-payload",
            title="非标准 TCP 载荷",
            evidence=(
                f"{len(payloads)} 条已重建 TCP 流"
                + (f"（stream {stream_index}）" if stream_index is not None else "")
                + f"，最大 {largest} 字节"
            ),
            detail="没有 HTTP/Telnet。去“TCP 流”页查看内容，逐包拼接或跟流"
            "常能直接看到 FLAG: / 明文。",
            action="streams",
            weight=66,
        )
    ]


_ASSESSMENT_PLAYER: dict[str, tuple[str, str, str, int]] = {
    # kind -> (title, detail, action, weight)
    "http-status-body-contradiction": (
        "HTTP 状态与正文矛盾",
        "响应码和正文对不上，去 HTTP 页核对该事务。",
        "http",
        55,
    ),
    "tftp-file-transfer": (
        "TFTP 文件传输",
        "上传/下载已重建，去“文件”页打开产物。",
        "files",
        68,
    ),
    "smtp-mime-attachment": (
        "SMTP 邮件附件",
        "还原的附件在“文件”页，按 MIME 来源核对。",
        "files",
        67,
    ),
    "icmp-ttl-oracle": (
        "ICMP TTL 旁信道",
        "TTL 拼出的 ASCII 在发现页候选里。",
        "findings",
        70,
    ),
    "image-analysis": (
        "图片分析",
        "去“文件”页打开图片产物，看隐写/附加数据。",
        "files",
        62,
    ),
    "pcap-header-repair": (
        "抓包文件头被清空，已自动修复",
        "原文件头 24 字节全是 0，已在项目内生成修复副本。去“发现”页看文件内搜到的 flag。",
        "findings",
        92,
    ),
    "password-protected-archive": (
        "加密压缩包",
        "文件页的 zip/rar 带密码，Auto-Shark 不会爆破。先在同一份流量里找密码。",
        "files",
        84,
    ),
    "nested-container": (
        "这不是抓包，里面嵌套了文件",
        "嵌套的 zip/rar/图片已放到“文件”页；加密包先找密码再在站外打开。",
        "files",
        93,
    ),
}

# Already covered by _finding_suggestions / _protocol_suggestions.
_ASSESSMENT_SKIP = frozenset(
    {
        "sql-injection",
        "webshell-activity",
        "web-command-execution",
        "usb-hid-triage",
    }
)


def _assessment_suggestions(report: dict) -> list[WizardSuggestion]:
    assessment = report.get("assessment") or {}
    suggestions: list[WizardSuggestion] = []
    for behavior in list(assessment.get("behaviors") or []):
        kind = str(behavior.get("kind") or "")
        hint = str(behavior.get("hint") or "")
        count = behavior.get("count", 0)
        if not hint:
            continue
        if kind in _ASSESSMENT_SKIP:
            continue
        if kind == "dns-encoded-labels":
            suggestions.append(
                WizardSuggestion(
                    "dns-labels", "DNS 编码标签分组", f"{count} 组编码标签", hint, "findings", 84
                )
            )
        elif kind == "voip-traffic":
            suggestions.append(
                WizardSuggestion("voip", "VoIP 语音流量", f"rtp 帧 {count}", hint, "files", 74)
            )
        elif kind == "snmp-traffic":
            suggestions.append(
                WizardSuggestion(
                    "snmp",
                    "SNMP 流量",
                    f"snmp 帧 {count}",
                    "变量绑定字符串已拼接为可扫描证据（含 community/OctetString），"
                    "flag 若外带在 SNMP 值里会直接出现在候选中。",
                    "findings",
                    60,
                )
            )
        elif kind in _ASSESSMENT_PLAYER:
            title, detail, action, weight = _ASSESSMENT_PLAYER[kind]
            suggestions.append(
                WizardSuggestion(kind, title, f"{count} 条相关发现", detail, action, weight)
            )
        else:
            suggestions.append(
                WizardSuggestion(
                    kind,
                    "需要人工核验的发现",
                    f"{count} 条",
                    "去“发现”页看证据链接，对照考点决定下一步。",
                    "findings",
                    50,
                )
            )
    return suggestions


def _flag_candidates(root: Path, pattern: Optional[str]) -> list[dict]:
    try:
        page = _payload(
            query_findings(
                root, candidate_limit=50, candidate_offset=0, finding_offset=0, finding_limit=1
            )
        )
    except (OSError, ValueError, KeyError):
        return []
    compiled = None
    if pattern:
        try:
            compiled = re.compile(pattern, re.IGNORECASE)
        except re.error:
            compiled = None
    candidates = []
    for item in list(page.get("candidates") or []):
        value = str(item.get("normalized_value") or item.get("raw_value") or "")
        user_match = bool(compiled and compiled.search(value))
        candidates.append(
            {
                "value": value,
                "kind": item.get("kind"),
                "rank_score": item.get("rank_score"),
                "confidence": item.get("confidence"),
                "user_format_match": user_match,
            }
        )
    candidates.sort(
        key=lambda item: (not item["user_format_match"], -int(item["rank_score"] or 0))
    )
    return candidates[:20]


def build_wizard(project_root: Path) -> dict:
    """Compose the wizard payload for one analyzed project."""

    root = Path(project_root)
    try:
        summary = _payload(query_summary(root, protocol_limit=1000, conversation_limit=1))
    except (OSError, ValueError, KeyError):
        summary = {}
    try:
        report = _payload(collect_report(root))
    except (OSError, ValueError, KeyError):
        report = {}
    flag_format = read_flag_format(root)

    suggestions: list[WizardSuggestion] = []
    suggestions.extend(_http_suggestions(root, summary))
    suggestions.extend(_finding_suggestions(root))
    suggestions.extend(_protocol_suggestions(summary))
    suggestions.extend(_stream_suggestions(root, summary))
    suggestions.extend(_assessment_suggestions(report))
    overview_early = dict(report.get("overview") or {})
    recovered = int(overview_early.get("artifacts") or 0)
    if recovered:
        suggestions.append(
            WizardSuggestion(
                kind="recovered-files",
                title="已还原文件",
                evidence=f"{recovered} 个文件",
                detail="去“文件”页打开图片/压缩包。图片题常要自己看图或 OCR；"
                "加密包先在流量里找密码。",
                action="files",
                weight=64,
            )
        )
    seen: set[str] = set()
    unique: list[WizardSuggestion] = []
    for suggestion in sorted(suggestions, key=lambda item: -item.weight):
        if suggestion.kind in seen:
            continue
        seen.add(suggestion.kind)
        unique.append(suggestion)

    coverage = dict(report.get("coverage") or {})
    overview = dict(report.get("overview") or {})
    artifact_count = int(overview.get("artifacts") or 0)
    if not artifact_count:
        # No carved/exported artifacts: uploads are still inspectable as the
        # request body on the HTTP page, so route there instead of an empty
        # Files page.
        rerouted: list[WizardSuggestion] = []
        for suggestion in unique:
            if suggestion.kind == "http-upload":
                fields = dict(vars(suggestion))
                fields["action"] = "http"
                rerouted.append(WizardSuggestion(**fields))
            else:
                rerouted.append(suggestion)
        unique = rerouted
    else:
        # Recovered files beat raw candidates: when the DNS/TFTP/FTP pipeline
        # already rebuilt an artifact, send the player straight to it.
        rerouted = []
        for suggestion in unique:
            if suggestion.kind in ("dns-tunnel", "dns-labels", "ftp-transfer", "voip"):
                fields = dict(vars(suggestion))
                fields["action"] = "files"
                rerouted.append(WizardSuggestion(**fields))
            else:
                rerouted.append(suggestion)
        unique = rerouted
    return {
        "schema_version": _WIZARD_SCHEMA,
        "flag_format": flag_format,
        "protocol_hierarchy": _protocol_hierarchy(summary),
        "suggestions": [vars(item) for item in unique[:8]],
        "flag_candidates": _flag_candidates(root, flag_format),
        "fallback_steps": [{"title": title, "detail": detail} for title, detail in FALLBACK_STEPS],
        "coverage": coverage,
        "artifact_count": artifact_count,
    }
