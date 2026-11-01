from importlib import resources

import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.main import create_app


@pytest.fixture
def lab_xml() -> str:
    return resources.files("app.demo").joinpath("lab_apache_vulners.xml").read_text()


@pytest.fixture
def settings(tmp_path) -> Settings:
    return Settings(
        _env_file=None,
        database_path=str(tmp_path / "test.db"),
        allowed_targets="127.0.0.1,172.28.0.0/24,localhost",
        demo_mode=True,
        nvd_enabled=False,
        kev_enabled=False,
        epss_enabled=False,
        rate_limit_scans=3,
    )


@pytest.fixture
def client(settings):
    with TestClient(create_app(settings)) as c:
        yield c
