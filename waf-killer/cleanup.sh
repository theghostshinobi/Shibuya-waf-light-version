#!/bin/bash
# Salva come: cleanup.sh

echo "🧹 Starting safe cleanup..."
echo ""

# Backup check
read -p "⚠️  This will delete build artifacts. Continue? (y/n) " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Cleanup cancelled."
    exit 1
fi

TOTAL_FREED=0

# Clean Rust build artifacts (SAFE - ricostruibile con cargo build)
if [ -d "target" ]; then
    SIZE=$(du -sm target 2>/dev/null | cut -f1)
    echo "🗑️  Removing Rust target/ (${SIZE}MB)..."
    rm -rf target
    TOTAL_FREED=$((TOTAL_FREED + SIZE))
fi

# Clean Node modules (SAFE - ricostruibile con npm install)
if [ -d "node_modules" ]; then
    SIZE=$(du -sm node_modules 2>/dev/null | cut -f1)
    echo "🗑️  Removing root node_modules/ (${SIZE}MB)..."
    rm -rf node_modules
    TOTAL_FREED=$((TOTAL_FREED + SIZE))
fi

if [ -d "dashboard/node_modules" ]; then
    SIZE=$(du -sm dashboard/node_modules 2>/dev/null | cut -f1)
    echo "🗑️  Removing dashboard/node_modules/ (${SIZE}MB)..."
    rm -rf dashboard/node_modules
    TOTAL_FREED=$((TOTAL_FREED + SIZE))
fi

# Clean Cargo cache incremental builds
if [ -d "$HOME/.cargo/registry" ]; then
    echo "🗑️  Cleaning Cargo registry cache..."
    cargo cache --autoclean 2>/dev/null || echo "   (cargo-cache not installed, skipping)"
fi

# Clean old log files (keep last 7 days)
if [ -d "logs" ]; then
    echo "🗑️  Cleaning old log files (>7 days)..."
    find logs -type f -name "*.log" -mtime +7 -delete 2>/dev/null
fi

# Clean temporary data files (keep important data)
if [ -d "data/temp" ]; then
    SIZE=$(du -sm data/temp 2>/dev/null | cut -f1)
    echo "🗑️  Removing temporary data (${SIZE}MB)..."
    rm -rf data/temp
    TOTAL_FREED=$((TOTAL_FREED + SIZE))
fi

# Clean npm cache
echo "🗑️  Cleaning npm cache..."
npm cache clean --force 2>/dev/null

# Clean Rust incremental compilation artifacts
echo "🗑️  Cleaning Rust incremental artifacts..."
find . -type d -name "incremental" -path "*/target/*" -exec rm -rf {} + 2>/dev/null

echo ""
echo "✅ Cleanup complete!"
echo "💾 Approximate space freed: ${TOTAL_FREED}MB"
echo ""
echo "To rebuild:"
echo "  Rust:  cd core && cargo build"
echo "  Node:  cd dashboard && npm install"
