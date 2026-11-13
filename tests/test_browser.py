from pathlib import Path

from websec_lab.browser import discover_browsers


def test_explicit_browser_path_is_discovered(tmp_path: Path) -> None:
    executable = tmp_path / "browser.exe"
    executable.touch()

    browsers = discover_browsers(
        {
            "WEBSEC_CHROME_PATH": str(executable),
            "ProgramFiles": str(tmp_path / "missing-program-files"),
            "ProgramFiles(x86)": str(tmp_path / "missing-program-files-x86"),
        }
    )

    assert len(browsers) == 1
    assert browsers[0].channel == "chrome"
    assert browsers[0].executable_path == executable.resolve()
    assert browsers[0].source == "WEBSEC_CHROME_PATH"


def test_duplicate_explicit_and_default_paths_are_deduplicated(tmp_path: Path) -> None:
    chrome = tmp_path / "Google/Chrome/Application/chrome.exe"
    chrome.parent.mkdir(parents=True)
    chrome.touch()

    browsers = discover_browsers(
        {
            "WEBSEC_CHROME_PATH": str(chrome),
            "ProgramFiles": str(tmp_path),
            "ProgramFiles(x86)": str(tmp_path / "missing"),
        }
    )

    assert len(browsers) == 1
    assert browsers[0].source == "WEBSEC_CHROME_PATH"


def test_missing_browser_paths_are_ignored(tmp_path: Path) -> None:
    browsers = discover_browsers(
        {
            "ProgramFiles": str(tmp_path / "missing-a"),
            "ProgramFiles(x86)": str(tmp_path / "missing-b"),
        }
    )

    assert browsers == []
