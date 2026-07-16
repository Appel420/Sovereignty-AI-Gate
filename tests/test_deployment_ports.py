from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[1]
FORBIDDEN_PORTS = ("3000", "5000", "8000")


def test_dashboard_container_uses_only_the_sacred_frontend_port() -> None:
    dockerfile = (ROOT / "deploy/docker/Dockerfile").read_text(encoding="utf-8")
    compose = (ROOT / "deploy/docker/docker-compose.yml").read_text(encoding="utf-8")

    assert re.findall(r"^EXPOSE\s+(\d+)$", dockerfile, re.MULTILINE) == ["9898"]
    assert '"http.server", "9898"' in dockerfile
    ports_block = re.search(r"ports:\s*\n(\s+-\s+\"[0-9:]+\"\s*\n)+", compose)
    assert ports_block is not None
    assert re.findall(r'"(\d+):(\d+)"', ports_block.group(0)) == [("9898", "9898")]
    for forbidden_port in FORBIDDEN_PORTS:
        assert forbidden_port not in dockerfile
        assert forbidden_port not in compose


def test_nginx_uses_only_the_sacred_frontend_port() -> None:
    config = (ROOT / "deploy/nginx/default.conf").read_text(encoding="utf-8")

    assert re.findall(r"^\s*listen\s+(\d+);", config, re.MULTILINE) == ["9898"]
    for forbidden_port in FORBIDDEN_PORTS:
        assert forbidden_port not in config


def test_deployment_model_declares_the_complete_immutable_port_policy() -> None:
    deployment_model = (
        ROOT / "docs/architecture/deployment_model.md"
    ).read_text(encoding="utf-8")

    for port in ("9897", "9898", "9899"):
        assert f"**{port}**" in deployment_model
    assert "**8080/8443**" in deployment_model
    assert "must never be changed" in deployment_model
    for forbidden_port in FORBIDDEN_PORTS:
        assert forbidden_port in deployment_model
