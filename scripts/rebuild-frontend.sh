#!/usr/bin/env sh
# Rebuild and restart only the frontend service
set -e
cd "$(dirname "$0")/.."
# Print info
echo "Building frontend image (production target) with increased Node memory..."
# Build frontend image (no cache to ensure build args are picked up)
docker compose build --no-cache frontend
# Restart the frontend service
docker compose up -d frontend
# Show the logs for frontend
docker logs -f siberZed-frontend

# Note: On Linux make this executable: chmod +x scripts/rebuild-frontend.sh
