#!/bin/bash
# Salva come: verify.sh

echo "🔍 Verifying project integrity after cleanup..."
echo ""

echo "1️⃣ Checking Rust project..."
cd core
cargo check --quiet
if [ $? -eq 0 ]; then
    echo "   ✅ Rust project OK"
else
    echo "   ❌ Rust project has issues"
    exit 1
fi
cd ..

echo "2️⃣ Checking Node dependencies..."
cd dashboard
npm install --quiet
if [ $? -eq 0 ]; then
    echo "   ✅ Node dependencies restored"
else
    echo "   ❌ Node dependencies failed"
    exit 1
fi
cd ..

echo ""
echo "✅ All checks passed! Project is clean and functional."
