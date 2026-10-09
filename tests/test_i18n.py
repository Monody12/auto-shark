import subprocess
import sys

from auto_shark.engines.tshark import TSHARK_TOO_OLD_TEMPLATE
from auto_shark.gui.i18n import detect_language, translate


def test_language_override_selects_chinese_or_english(monkeypatch) -> None:
    monkeypatch.setenv("AUTO_SHARK_LANGUAGE", "zh-CN")
    assert detect_language() == "zh"
    assert translate("Overview") == "解题向导"

    monkeypatch.setenv("AUTO_SHARK_LANGUAGE", "en-US")
    assert detect_language() == "en"
    assert translate("Overview") == "Overview"


def test_chinese_locale_is_detected_and_unknown_strings_fall_back(monkeypatch) -> None:
    monkeypatch.setenv("AUTO_SHARK_LANGUAGE", "zh_Hans_CN")
    assert detect_language() == "zh"
    assert translate("a raw evidence value") == "a raw evidence value"


def test_runtime_error_and_stage_strings_have_chinese_translations() -> None:
    assert translate("error: no usable display for the GUI", "zh") == "错误：GUI 没有可用的显示环境"
    assert (
        translate("Inspect TCP urgent-pointer side channels", "zh")
        == "检查 TCP 紧急指针隐蔽信道"
    )
    assert translate("&Edit", "zh") == "编辑(&E)"
    assert translate("Type", "zh") == "题型"
    assert translate("Evidence", "zh") == "证据"
    assert translate("Suggestion", "zh") == "建议"
    assert translate("Exam points:", "zh") == "考点："
    assert translate("Next steps:", "zh") == "下一步："
    assert translate("Technical details", "zh") == "技术细节"
    assert translate("Export analysis bundle…", "zh") == "导出分析包…"
    assert translate("USB HID boot-keyboard-like endpoint", "zh") == "USB HID 键盘端点"
    assert translate("Static WebShell activity", "zh") == "静态 WebShell 行为"
    assert translate("Typed keys:", "zh") == "键盘输入："
    assert translate("Password-protected archive", "zh") == "加密压缩包"
    assert translate("Repaired zeroed PCAP global header", "zh") == "已修复被清空的 PCAP 文件头"
    assert translate("Not a packet capture; nested files inside", "zh") == (
        "这不是抓包文件，里面嵌套了压缩包/图片"
    )
    assert translate("Check", "zh") == "检测"
    assert translate("Show advanced: remote Linux node (optional)", "zh") == (
        "显示高级选项：远程 Linux 节点（可选）"
    )
    assert translate("SSH user@host", "zh") == "SSH 用户@主机"
    assert "不支持密码" in translate(
        "Optional Linux helper for extra tools (zsteg, binwalk, …). "
        "Local traffic challenges do not need this. Protocol is SSH + SFTP only. "
        "Host is user@IP or user@domain, for example ctf@192.168.1.10. "
        "Port defaults to 22. Passwords are not supported — use an OpenSSH "
        "private key or ssh-agent. Probe tests the connection; saving only "
        "stores the settings. Main analysis still runs locally with TShark.",
        "zh",
    )
    assert "版本过低" in translate(TSHARK_TOO_OLD_TEMPLATE, "zh")
    assert "{found}" in translate(TSHARK_TOO_OLD_TEMPLATE, "zh")


def test_i18n_module_does_not_import_qt() -> None:
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            "import sys; import auto_shark.gui.i18n; "
            "print(any(name == 'PySide6' or name.startswith('PySide6.') for name in sys.modules))",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0
    assert result.stdout.strip() == "False"
