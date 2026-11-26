#!/bin/bash
# MIT Licence
set -euo pipefail

echo "=== Dokploy Security Check Script ==="
echo "Checking for potential command injection in backup and schedule configurations."
echo ""

# (a) Print Dokploy image
echo "[1/4] Checking Dokploy image..."
IMAGE=$(docker service inspect dokploy --format '{{.Spec.TaskTemplate.ContainerSpec.Image}}' 2>/dev/null || docker ps --filter name=dokploy --format '{{.Image}}')
if [ -n "$IMAGE" ]; then
    echo "Dokploy Image: $IMAGE"
    echo "Reminder: Ensure you are running version 0.31.1 or later. Check the version in the Dokploy panel."
else
    echo "Warning: Could not determine Dokploy image. Please check manually."
fi
echo ""

# (b) Find database container
echo "[2/4] Locating database container..."
DB_CONTAINER=$(docker ps -q -f name=dokploy-postgres | head -n 1)
if [ -z "$DB_CONTAINER" ]; then
    echo "Error: dokploy-postgres container not found. Exiting."
    exit 1
fi
echo "Database Container ID: $DB_CONTAINER"
echo ""

# (c) Run psql queries
echo "[3/4] Checking 'backup' table for suspicious characters..."
docker exec "$DB_CONTAINER" psql -U dokploy -d dokploy -c "SELECT * FROM \"backup\" WHERE \"serviceName\" ~ '[;\`\$\|&<>()]' OR \"prefix\" ~ '[;\`\$\|&<>()]' OR \"appName\" ~ '[;\`\$\|&<>()]' OR \"database\" ~ '[;\`\$\|&<>()]';"

echo "Checking 'schedule' table for suspicious characters..."
docker exec "$DB_CONTAINER" psql -U dokploy -d dokploy -c "SELECT * FROM \"schedule\" WHERE \"appName\" ~ '[;\`\$\|&<>()]' OR \"serviceName\" ~ '[;\`\$\|&<>()]';"
echo ""

# (d) Note on exclusions
echo "[4/4] Note: Users, sessions, and API keys are not queried by this script."
echo "Please review these manually in the Dokploy panel."
echo ""
echo "Check complete."
exit 0
