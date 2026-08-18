import subprocess
import sys

from auto_shark.gui.i18n import detect_language, translate


def test_language_override_selects_chinese_or_english(monkeypatch) -> None:
    monkeypatch.setenv("AUTO_SHARK_LANGUAGE", "zh-CN")
    assert detect_language() == "zh"
    assert translate("Overview") == "概览"

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
