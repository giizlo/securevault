import os
import tempfile

os.environ["APP_ENV"] = "test"
os.environ["DATABASE_URL"] = f"sqlite:///{tempfile.mkdtemp()}/test.db"

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app.db import Base, SessionLocal, engine  # noqa: E402
from app.main import app  # noqa: E402
from app.ratelimit import reset_all  # noqa: E402
from client.zk_client import ZKClient  # noqa: E402


@pytest.fixture(autouse=True)
def fresh_db():
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    reset_all()
    yield


@pytest.fixture
def http():
    return TestClient(app)


@pytest.fixture
def db():
    with SessionLocal() as s:
        yield s


@pytest.fixture
def alice(http):
    c = ZKClient(http, "alice@example.com", "correct horse battery staple")
    assert c.register().status_code == 201
    assert c.login().status_code == 200
    return c
