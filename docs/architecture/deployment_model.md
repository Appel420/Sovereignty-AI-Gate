# Deployment Model

## Port Assignment

| Service | Port | Notes |
|---|---|---|
| Koder frontend | **9898** | Internal frontend port |
| Node.js backend | **9899** | External backend port |
| Python backend | **9897** | Internal backend port |

Only these service ports are assigned by this project. Keycloak, when deployed, retains
its own port **8080** and is not exposed or configured by this deployment.

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
