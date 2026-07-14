from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_dashboard_container_uses_the_assigned_frontend_port() -> None:
    dockerfile = (ROOT / "deploy/docker/Dockerfile").read_text(encoding="utf-8")
    compose = (ROOT / "deploy/docker/docker-compose.yml").read_text(encoding="utf-8")

    assert "EXPOSE 9898" in dockerfile
    assert '"http.server", "9898"' in dockerfile
    assert '"9898:9898"' in compose
    assert "7600" not in dockerfile
    assert "7600" not in compose


def test_nginx_frontend_uses_the_assigned_port() -> None:
    config = (ROOT / "deploy/nginx/default.conf").read_text(encoding="utf-8")

    assert "listen 9898;" in config
    assert "listen 80;" not in config
