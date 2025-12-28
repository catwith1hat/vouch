{ pkgs ? import <nixpkgs> {} }:

pkgs.mkShell {
  name = "vouch-dev-environment";

  buildInputs = with pkgs; [
    # Go toolchain (will use latest stable version)
    go

    # Rust toolchain (for ethproofs verifier FFI)
    cargo
    rustc
    rustfmt
    clippy

    # Linting and formatting
    golangci-lint

    # Build tools
    gnumake
    git

    # Container tools (optional, for Docker builds)
    podman

    # Debugging and development tools
    delve        # Go debugger
    gopls        # Go language server
    gotools      # Contains goimports, godoc, etc.

    # Testing tools
    gotest       # Enhanced go test output
  ];

  shellHook = ''
    echo "🚀 Vouch development environment loaded"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "Go version: $(go version)"
    echo "Rust version: $(rustc --version)"
    echo "Cargo version: $(cargo --version)"
    echo "golangci-lint version: $(golangci-lint version 2>&1 | head -1)"
    echo ""
    echo "Available commands:"
    echo "  go build                              - Build vouch binary"
    echo "  go test ./...                         - Run all tests"
    echo "  golangci-lint run ./.                 - Run linters"
    echo "  ./build.sh <version>                  - Build Docker image"
    echo "  (cd services/ethproofstracker/verifier && cargo build --release) - Build Rust verifier"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

    # Set up Go environment
    export GOPATH="$HOME/go"
    export PATH="$GOPATH/bin:$PATH"

    # Ensure go modules are enabled
    export GO111MODULE=on

    # Set up library path for Rust FFI
    export LD_LIBRARY_PATH="$PWD/services/ethproofstracker/lib:''${LD_LIBRARY_PATH:-}"
    export DYLD_LIBRARY_PATH="$PWD/services/ethproofstracker/lib:''${DYLD_LIBRARY_PATH:-}"
  '';

  # Environment variables
  CGO_ENABLED = "1";

  # Go build flags
  GOFLAGS = "-buildvcs=true";
}
