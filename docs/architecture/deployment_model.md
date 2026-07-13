# Deployment Model

## Modes

### Local (default)
Single-user, single-machine. All state on device. Run with:
```bash
python3 -m http.server 8080 --directory src/dashboard
```

### Self-Hosted (Docker)
```bash
cd deploy/docker
docker compose up -d
```

### Kubernetes
```bash
kubectl apply -f deploy/k8s/
```

## Security Posture

- Run as non-root user (UID 1001)
- Read-only root filesystem
- No privileged containers
- No external network calls from core services
