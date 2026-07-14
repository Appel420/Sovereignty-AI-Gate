# Deployment Model

## Port Assignment

| Service | Port | Notes |
|---|---|---|
| Koder frontend | **9898** | Internal frontend port |
| Node.js backend | **9899** | External backend port |
| Python backend | **9897** | Internal backend port |

These assignments are immutable and must never be changed. No service may use ports
in the 3000, 5000, or 8000 ranges. Keycloak is the sole exception permitted to use
**8080/8443**; it is not exposed or configured by this deployment.

## Modes

### Local (default)
Single-user, single-machine. All state on device. Run with:
```bash
python3 -m http.server 9898 --directory src/dashboard
```

### Self-Hosted (Docker)
```bash
cd deploy/docker
docker compose up -d
```

## Security Posture

- Run as non-root user (UID 1001)
- Read-only root filesystem
- No privileged containers
- No external network calls from core services
