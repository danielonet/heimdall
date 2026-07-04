#!/bin/bash
# Quick start script for mock router offline development

set -euo pipefail

echo "🛡️  Heimdall Mock Router Setup"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# Check if we're in the right directory
if [ ! -f "docker-compose.yml" ]; then
  echo "❌ Error: docker-compose.yml not found"
  echo "Run this script from the heimdall/ directory"
  exit 1
fi

# Create secrets directory if needed
mkdir -p secrets

# Generate placeholder secrets if missing
if [ ! -f "secrets/router_password.txt" ]; then
  echo "📝 Creating placeholder secrets..."
  echo "mock-password" > secrets/router_password.txt
  echo "mock-jwt-secret-" > secrets/jwt_secret.txt
  echo "mock-db-password" > secrets/db_pass.txt
fi

# Check if .env exists
if [ ! -f ".env" ]; then
  echo "📝 Creating .env from .env.example..."
  cp .env.example .env
  echo "ℹ️  Edit .env if needed (USE_MOCK_ROUTER should be true)"
fi

echo ""
echo "✅ Setup complete!"
echo ""
echo "Starting Heimdall in mock mode..."
echo ""
echo "📊 Dashboard:    http://localhost:3000"
echo "🔌 API:          http://localhost:5000"
echo "📚 Docs:         docs/architecture/10-mock-router.md"
echo ""

# Enable mock mode
export USE_MOCK_ROUTER=true

# Start the stack
docker-compose up -d

echo ""
echo "⏳ Waiting for services to start..."
sleep 5

# Show logs
echo ""
echo "📋 Backend logs:"
docker-compose logs -f sentinel-backend --tail=20
