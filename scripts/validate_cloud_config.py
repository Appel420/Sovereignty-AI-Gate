#!/usr/bin/env python3
from __future__ import annotations

import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
COMPOSE = ROOT / "deploy" / "docker" / "docker-compose.yml"
DOCKERFILE = ROOT / "deploy" / "docker" / "Dockerfile"
NGINX = ROOT / "deploy" / "nginx" / "default.conf"
WORKFLOWS = ROOT / ".github" / "workflows"
ACTION_PIN_RE = re.compile(
    r"^\s*(?:-\s+)?uses:\s+[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+@[0-9a-f]{40}\s*$"
)


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def validate_compose() -> None:
    text = COMPOSE.read_text(encoding="utf-8")
    _require(":latest" not in text, "compose must not use floating :latest image tags")
    _require("read_only: true" in text, "compose service must keep read_only root filesystem")
    _require("no-new-privileges:true" in text, "compose service must set no-new-privileges")
    _require("SIA_OFFLINE=1" in text, "compose must enforce offline mode by default")
    _require("internal: true" in text, "compose network must be marked internal")
    _require("networks:" in text, "compose must define explicit networks")
    _require("user:" in text, "compose must declare non-root runtime user")
    _require(
        re.search(r"(TOKEN|SECRET|PASSWORD|PRIVATE_KEY)\s*=\s*[^$\n]+", text) is None,
        "compose contains plaintext secret-like environment values",
    )


def validate_dockerfile() -> None:
    text = DOCKERFILE.read_text(encoding="utf-8")
    _require(not re.search(r"^FROM\s+\S+:latest", text, re.MULTILINE), "docker base image must not use :latest")
    _require(re.search(r"^USER\s+[^\s]+", text, re.MULTILINE) is not None, "dockerfile must set non-root USER")


def validate_nginx() -> None:
    text = NGINX.read_text(encoding="utf-8")
    _require("listen 9898;" in text, "nginx must listen on approved frontend port")
    _require("connect-src 'none'" in text, "nginx CSP must fail closed for outbound connections")
    _require(
        "Access-Control-Allow-Origin *" not in text and "add_header Access-Control-Allow-Origin \"*\"" not in text,
        "nginx must not allow wildcard CORS",
    )
    _require("ssl_protocols TLSv1 " not in text and "ssl_protocols TLSv1.1" not in text, "insecure TLS protocols are forbidden")


def validate_workflows() -> None:
    for workflow in WORKFLOWS.glob("*.yml"):
        text = workflow.read_text(encoding="utf-8")
        _require("pull_request_target:" not in text, f"{workflow.name}: pull_request_target is not allowed")
        _require("permissions:" in text and "contents: read" in text, f"{workflow.name}: permissions must be read-only")
        for line in text.splitlines():
            if "uses:" not in line:
                continue
            _require(
                ACTION_PIN_RE.match(line) is not None,
                f"{workflow.name}: third-party actions must be pinned by full commit SHA ({line.strip()})",
            )


def main() -> int:
    validate_compose()
    validate_dockerfile()
    validate_nginx()
    validate_workflows()
    print("cloud configuration validation passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
