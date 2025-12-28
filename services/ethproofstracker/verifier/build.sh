#!/bin/bash
# Build script for the ethproofs verifier Rust library

set -e

echo "Building ethproofs-verifier Rust library..."

cd "$(dirname "$0")"

# Build in release mode for performance
cargo build --release

echo "Build complete!"
echo "Library location: target/release/libethproofs_verifier.so"

# Copy to a location Go can find it
mkdir -p ../lib
cp target/release/libethproofs_verifier.so ../lib/ 2>/dev/null || \
cp target/release/libethproofs_verifier.dylib ../lib/ 2>/dev/null || \
cp target/release/ethproofs_verifier.dll ../lib/ 2>/dev/null || true

echo "Copied library to services/ethproofstracker/lib/"
