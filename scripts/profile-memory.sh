#!/bin/bash
set -e

# Memory profiling script using Docker + ByteHound
# Works on macOS, Linux, Windows (with Docker)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
PROFILES_DIR="$PROJECT_DIR/profiles"

echo "🔍 Memory Profiling with ByteHound (via Docker)"
echo ""

# Create profiles directory
mkdir -p "$PROFILES_DIR"

# Check if Docker is running
if ! docker info >/dev/null 2>&1; then
    echo "❌ Docker is not running. Please start Docker first."
    exit 1
fi

echo "📦 Building Docker image with ByteHound..."
docker build -f "$PROJECT_DIR/Dockerfile.bytehound" -t wsc-bytehound "$PROJECT_DIR"

echo ""
echo "🧪 Running tests with memory profiling..."
docker run --rm \
    -v "$PROFILES_DIR:/output" \
    wsc-bytehound \
    bash -c "cargo test --release -- --test-threads=1 --nocapture; cp memory-profiling_*.dat /output/ 2>/dev/null || true"

echo ""
if ls "$PROFILES_DIR"/memory-profiling_*.dat 1> /dev/null 2>&1; then
    echo "✅ Profiling complete! Data saved to:"
    ls -lh "$PROFILES_DIR"/memory-profiling_*.dat

    echo ""
    echo "📊 To view results:"
    echo "  1. Install ByteHound on a Linux machine or use Docker:"
    echo "     docker run --rm -p 8080:8080 -v \"$PROFILES_DIR:/data\" wsc-bytehound bytehound server /data/memory-profiling_*.dat"
    echo ""
    echo "  2. Open http://localhost:8080 in your browser"
else
    echo "⚠️  No profiling data generated. Check Docker logs above for errors."
fi
