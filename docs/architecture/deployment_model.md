# Deployment Model

## Port Assignment

| Service | Port | Notes |
|---|---|---|
| Keycloak | **8080** | Reserved exclusively for Keycloak — no other service uses this port |
| SIA Dashboard | **7600** | Self-hosted dashboard internal port |
| nginx (Docker) | **80** | Public-facing reverse proxy inside the container |

## Modes

### Local (default)
Single-user, single-machine. All state on device. Run with:
```bash
python3 -m http.server 7600 --directory src/dashboard
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
