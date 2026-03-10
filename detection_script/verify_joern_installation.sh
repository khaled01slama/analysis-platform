#!/bin/bash
# Verify Joern Installation Script
# This script checks if Java and Joern are properly installed
# and provides guidance for installation if they're not

echo "===== Joern Installation Verification ====="

# Check Java installation
echo "Checking Java installation..."
if java -version 2>&1 >/dev/null; then
    java_version=$(java -version 2>&1 | head -n 1)
    echo "✅ Java is installed: $java_version"
else
    echo "❌ Java is not installed or not in PATH"
    echo "Please install Java 11 or later with:"
    echo "  - Ubuntu/Debian: sudo apt install openjdk-11-jdk"
    echo "  - CentOS/RHEL: sudo yum install java-11-openjdk-devel"
    echo "  - macOS: brew install openjdk@11"
    echo "  - Windows: Download from https://adoptium.net/"
fi

# Check Joern installation
echo -e "\nChecking Joern installation..."
if command -v joern &>/dev/null; then
    joern_path=$(which joern 2>&1 || echo "not found")
    echo "✅ Joern is installed: $joern_path"
else
    echo "❌ Joern is not installed or not in PATH"
    echo "Please install Joern with:"
    echo "  1. Download from https://github.com/joernio/joern"
    echo "  2. Follow installation instructions in README.md"
    echo "  3. Make sure the 'joern' command is in your PATH"
fi

# Verify our scripts
echo -e "\nVerifying script setup..."
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"

if [ -f "$SCRIPT_DIR/joern_agent.py" ]; then
    echo "✅ joern_agent.py found"
else
    echo "❌ joern_agent.py is missing"
fi

if [ -f "$SCRIPT_DIR/detect_unused_functions.sc" ]; then
    echo "✅ detect_unused_functions.sc found"
else
    echo "❌ detect_unused_functions.sc is missing"
fi

if [ -f "$SCRIPT_DIR/joern_unused_detector.sh" ]; then
    echo "✅ joern_unused_detector.sh found"
else
    echo "❌ joern_unused_detector.sh is missing"
fi

echo -e "\nIf you need to install the missing components, please refer to the documentation."
echo "======================="
