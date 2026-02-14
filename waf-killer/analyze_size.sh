#!/bin/bash
# Salva come: analyze_size.sh

echo "🔍 Analyzing directory sizes..."
echo ""
echo "Top 20 largest directories:"
du -sh * 2>/dev/null | sort -rh | head -20
echo ""
echo "Checking common waste locations..."
echo ""

# Check Rust build artifacts
if [ -d "target" ]; then
    echo "📦 Rust target/: $(du -sh target 2>/dev/null | cut -f1)"
fi

# Check Node modules
if [ -d "node_modules" ]; then
    echo "📦 Node modules: $(du -sh node_modules 2>/dev/null | cut -f1)"
fi

if [ -d "dashboard/node_modules" ]; then
    echo "📦 Dashboard node_modules: $(du -sh dashboard/node_modules 2>/dev/null | cut -f1)"
fi

# Check logs
if [ -d "logs" ]; then
    echo "📋 Logs directory: $(du -sh logs 2>/dev/null | cut -f1)"
fi

# Check data files
if [ -d "data" ]; then
    echo "💾 Data directory: $(du -sh data 2>/dev/null | cut -f1)"
fi

# Check models
if [ -d "models" ]; then
    echo "🧠 Models directory: $(du -sh models 2>/dev/null | cut -f1)"
fi
