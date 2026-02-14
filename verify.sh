#!/bin/bash
# Salva come: verify.sh

echo "🔍 Verifying project integrity after cleanup..."
echo ""

# Check Rust project
echo "1️⃣ Checking Rust project..."
if [ -d "waf-killer/core" ]; then
    cd waf-killer/core
    cargo check --quiet
    if [ $? -eq 0 ]; then
        echo "   ✅ Rust project OK"
    else
        echo "   ❌ Rust project has issues"
        exit 1
    fi
    cd ../..
else
    echo "   ❌ Root core directory not found in waf-killer/"
    exit 1
fi

# Check Node project
echo "2️⃣ Checking Node dependencies..."
if [ -d "waf-killer/dashboard" ]; then
    cd waf-killer/dashboard
    echo "⏳ Restoring dashboard dependencies (this may take a minute)..."
    npm install --quiet
    if [ $? -eq 0 ]; then
        echo "   ✅ Node dependencies restored"
    else
        echo "   ❌ Node dependencies failed"
        exit 1
    fi
    cd ../..
else
    echo "   ❌ Dashboard directory not found in waf-killer/"
    exit 1
fi

echo ""
echo "✅ All checks passed! Project is clean and functional."
