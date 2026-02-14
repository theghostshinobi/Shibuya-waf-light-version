#!/bin/bash
# File: cleanup.sh

echo "🧹 Starting Shibuya Project Cleanup..."

PROJECT_ROOT="/Users/ghostshinobi/Desktop/shibuya"

# 1. Clean Rust artifacts (waf-killer)
if [ -d "$PROJECT_ROOT/waf-killer" ]; then
    echo "🦀 Cleaning Rust build artifacts in waf-killer..."
    cd "$PROJECT_ROOT/waf-killer"
    # Cargo clean is safer and more thorough than rm -rf target
    if command -v cargo &> /dev/null; then
        cargo clean
    else
        echo "⚠️ Cargo not found, manually removing target directory..."
        rm -rf target
    fi
    echo "✅ Rust cleaned"
fi

# 2. Clean Node.js artifacts (dashboard)
if [ -d "$PROJECT_ROOT/waf-killer/dashboard" ]; then
    echo "📦 Cleaning Node.js dependencies in dashboard..."
    cd "$PROJECT_ROOT/waf-killer/dashboard"
    rm -rf node_modules .svelte-kit build
    # Optional: rm package-lock.json if you want a fresh lock, but usually safer to keep it.
    # The prompt suggested removing it, so I will follow instructions but maybe verify first? 
    # Actually prompt said "rm -f package-lock.json (optional)". I'll skip it to be safe unless requested.
    echo "✅ Node.js cleaned"
fi

# 3. Clean stress test artifacts
if [ -d "$PROJECT_ROOT/stress_test" ]; then
    echo "🧪 Cleaning stress test reports..."
    cd "$PROJECT_ROOT/stress_test"
    rm -rf reports/
    find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null
    find . -type f -name "*.pyc" -delete
    rm -f attack_log*.jsonl stress_test_summary*.json
    echo "✅ Stress tests cleaned"
fi

# 4. Clean logs
echo "📝 Cleaning logs..."
cd "$PROJECT_ROOT"
# Clean logs in waf-killer root and core/logs if they exist
rm -f waf-killer/*.log
rm -f waf-killer/core/logs/*.log
rm -f waf-killer/waf_debug*.log
echo "✅ Logs cleaned"

# 5. Clean old config backups (keep last 5)
echo "💾 Cleaning old config backups..."
if [ -d "$PROJECT_ROOT/waf-killer/config/backups" ]; then
    cd "$PROJECT_ROOT/waf-killer/config/backups"
    count=$(ls -1 | wc -l)
    if [ "$count" -gt 5 ]; then
        ls -t | tail -n +6 | xargs rm -f
        echo "✅ Config backups cleaned"
    fi
fi

# 6. Report space saved
cd "$PROJECT_ROOT"
FINAL_SIZE=$(du -sh . | cut -f1)
echo ""
echo "✅ Cleanup complete!"
echo "📊 Current project size: $FINAL_SIZE"
echo ""
echo "🔧 To rebuild:"
echo "  Rust:   cd waf-killer && cargo build --release"
echo "  Node:   cd waf-killer/dashboard && npm install"
