#!/bin/bash
# scripts/deploy.sh

set -e

ENVIRONMENT=${1:-dev}
VERSION=${2:-latest}

echo "🚀 Deploying WAF Killer to $ENVIRONMENT (version: $VERSION)"

# 1. Build and push image
echo "📦 Building Docker image..."
docker build -t ghcr.io/waf-killer/waf-killer:$VERSION .
docker push ghcr.io/waf-killer/waf-killer:$VERSION

# 2. Run smoke tests
echo "🧪 Running smoke tests..."
if [ -f "./scripts/smoke-test.sh" ]; then
    ./scripts/smoke-test.sh
else
    echo "⚠️ Smoke tests skipped (scripts/smoke-test.sh not found)"
fi

# 3. Deploy with Helm
echo "☸️  Deploying to Kubernetes..."
helm upgrade --install waf-killer \
  ./deploy/kubernetes/charts/waf-killer \
  --namespace waf-killer \
  --create-namespace \
  --values ./deploy/kubernetes/charts/waf-killer/values-$ENVIRONMENT.yaml \
  --set image.tag=$VERSION \
  --wait \
  --timeout 10m

# 4. Wait for rollout
echo "⏳ Waiting for rollout to complete..."
kubectl rollout status deployment/waf-killer -n waf-killer --timeout=10m

# 5. Post-deployment tests
if [ -f "./scripts/post-deploy-tests.sh" ]; then
    echo "✅ Running post-deployment tests..."
    ./scripts/post-deploy-tests.sh $ENVIRONMENT
fi

echo "🎉 Deployment complete!"
