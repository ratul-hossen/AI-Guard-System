import pytest

from aiguard.rules import Rules


@pytest.fixture
def rules():
    return Rules([".env", ".env.*", "*.pem", "secrets", "*.pdf"])


@pytest.mark.parametrize("path", [
    "/.env", "/app/.env", "/.env.local",
    "/secrets/key.txt", "/a/b/report.pdf", "/certs/server.pem",
    "secrets/sub/deep.txt", "nested/folder/.env.production"
])
def test_denied(rules, path):
    assert rules.is_denied(path)


@pytest.mark.parametrize("path", [
    "/", "/src/app.py", "/README.md", "/environment.md", "/docs/pdf_notes.txt",
    "public/index.html", "safe_secrets_doc.txt"
])
def test_allowed(rules, path):
    assert not rules.is_denied(path)
