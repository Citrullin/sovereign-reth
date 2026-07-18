#!/bin/bash
set -e

echo "Building Sovereign Reth for Gramine..."
cargo build --release

echo "Copying binary to gramine folder..."
cp ../target/release/sovereign-node .

echo "Generating manifest..."
gramine-manifest -Dlog_level=error \
                 -Darch_libdir=/lib/x86_64-linux-gnu \
                 sovereign-reth.manifest.template sovereign-reth.manifest

echo "Signing the enclave..."
gramine-sgx-sign --manifest sovereign-reth.manifest --output sovereign-reth.manifest.sgx

echo "Gramine build complete."
