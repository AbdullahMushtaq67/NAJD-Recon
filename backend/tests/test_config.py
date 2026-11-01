from pathlib import Path

from app.config import Settings


def test_finds_standard_windows_nmap_install_when_not_on_path(tmp_path, monkeypatch):
    nmap = tmp_path / "Nmap" / "nmap.exe"
    nmap.parent.mkdir()
    nmap.touch()
    monkeypatch.setattr("app.config.shutil.which", lambda _: None)
    monkeypatch.setattr("app.config.sys.platform", "win32")
    monkeypatch.setenv("PROGRAMFILES(X86)", str(tmp_path))

    settings = Settings(_env_file=None)

    assert settings.nmap_path == str(nmap)
    assert Path(settings.nmap_path).is_file()
