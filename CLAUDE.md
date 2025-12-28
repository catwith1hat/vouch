# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Vouch is an Ethereum 2 multi-node validator client that sits between beacon nodes and signers. It orchestrates validator duties (block proposals, attestations, sync committee participation) across multiple beacon nodes with sophisticated selection strategies for maximum reliability and value.

## Build & Test Commands

### Building
```bash
# Build the binary
go build

# Docker build (uses podman)
./build.sh <version>  # e.g., ./build.sh 1.12.0

# Docker build manually
podman build . -f Dockerfile -t vouch:latest
```

### Testing
```bash
# Run all tests
go test ./...

# Run tests in a specific package
go test ./services/attester/standard

# Run a specific test
go test ./services/attester/standard -run TestAttest

# Run tests with verbose output
go test -v ./...

# Run tests with coverage
go test -cover ./...
```

### Linting
```bash
# Run all linters (must have golangci-lint installed)
golangci-lint run ./...

# Run linters on specific directory
golangci-lint run ./services/...
```

Note: Tests are excluded from linting by default (see `.golangci.yml`).

## Architecture

### Core Philosophy

Vouch uses a **two-layer architecture**:

1. **Services Layer** (`/services`): Domain logic, coordination, state management
2. **Strategies Layer** (`/strategies`): Selection/aggregation algorithms for multi-node responses

```
Beacon Nodes (multiple)
    ↓
Strategies (select/aggregate responses)
    ↓
Services (business logic)
    ↓
Controller (orchestrator)
    ↓
Submitter (send back to beacon nodes)
```

### Services vs Strategies

**Services** are stateful, long-lived components that:
- Maintain context across calls
- Coordinate validator duties
- Exist for the lifetime of vouch
- Examples: `Attester`, `BeaconBlockProposer`, `Controller`

**Strategies** are stateless algorithms that:
- Query multiple beacon nodes concurrently
- Select "best" response or aggregate responses
- Can be swapped via configuration
- Examples: `best`, `first`, `majority`

### Multi-Node Resilience

Vouch connects to multiple beacon nodes for redundancy. Key concepts:

- **Per-strategy node selection**: Different strategies can use different subsets of nodes
- **Hierarchical configuration**: Strategy-specific addresses override global addresses
- **Failover**: `multiclient.Service` automatically handles node failures
- **Quality-based selection**: `best` strategies evaluate response quality

Configuration example:
```yaml
# Global default
beacon-node-addresses: [node1, node2, node3]

# Strategy-specific override
strategies:
  attestationdata:
    style: "best"
    best:
      beacon-node-addresses: [node1, node2]  # Only use these for attestation data
```

### Service Initialization Pattern

All services use **functional options pattern** for dependency injection:

```go
service, err := standardservice.New(ctx,
    standardservice.WithMonitor(monitor),
    standardservice.WithLogLevel(logLevel),
    standardservice.WithTimeout(timeout),
    // ... more parameters
)
```

This pattern is used throughout the codebase. When adding new services, follow this convention.

### Configuration System

Three-level hierarchy (highest to lowest precedence):
1. Command-line flags (e.g., `--log-level=debug`)
2. Environment variables (e.g., `VOUCH_LOG_LEVEL=debug`)
3. Configuration file (`vouch.json` or `vouch.yml`)

**Important configuration utilities** (in `util/`):
- `BeaconNodeAddresses(path)`: Resolves beacon node addresses hierarchically
- `BeaconNodeAddressesForAttesting()`: Addresses for attestation duties
- `BeaconNodeAddressesForProposing()`: Addresses for proposal duties

### Important Directories

```
/services/          Service implementations (business logic)
  /controller/      Main orchestrator
  /attester/        Attestation creation
  /beaconblockproposer/  Block proposal
  /accountmanager/  Validator account management
  /signer/          Signing interface
  /submitter/       Submission to beacon nodes
  /cache/           Block root caching
  /chaintime/       Slot/epoch timing
  ... 15+ other services

/strategies/        Selection/aggregation algorithms
  /attestationdata/ Attestation data strategies (best/first/majority)
  /beaconblockproposal/ Block proposal strategies
  /aggregateattestation/ Aggregate attestation strategies
  /beaconblockroot/ Block root strategies
  /builderbid/      MEV builder bid strategies
  ... 9+ strategy types

/util/              Shared utilities
  beaconnodeaddresses.go  Address resolution
  config.go              Configuration helpers
  scatter.go             Concurrent execution utilities
  timeout.go             Timeout utilities

/mock/              Mock implementations for testing
/testutil/          Test utilities
/docs/              Detailed documentation
```

### Main Entry Point (`main.go`)

The initialization sequence is critical to understand:

1. **fetchConfig()**: Load configuration from file/env/CLI
2. **initMajordomo()**: Initialize secret manager (for secure config)
3. **initLogging()**: Setup structured logging (zerolog)
4. **initTracing()**: Setup OpenTelemetry tracing
5. **startBasicServices()**: Metrics, Eth2Client, ChainTime
6. **consensusClientCapabilities()**: Detect beacon node capabilities (Altair/Bellatrix/Capella/Electra)
7. **startProviderServices()**: Initialize strategies based on config
8. **startSharedServices()**: Scheduler, Cache, Signer, AccountManager
9. **startSigningServices()**: Attester, BeaconBlockProposer, Aggregators
10. **startAltairServices()**: Sync committee services (if Altair capable)
11. **startBlockRelay()**: MEV-Boost integration (if Bellatrix capable)
12. **initController()**: Main orchestrator

This sequence must be maintained when adding new services.

### Client Management (`clients.go`)

Two key functions:
- `fetchClient(address)`: Creates single beacon node client (cached)
- `fetchMultiClient(addresses)`: Creates multi-node client with failover

Clients are cached in `knownClients` map to avoid duplicate connections.

### Hard Fork Awareness

Vouch adapts to network upgrades by querying beacon node capabilities:
- `ALTAIR_FORK_EPOCH`: Enables sync committees
- `BELLATRIX_FORK_EPOCH`: Enables execution layer (MEV)
- `CAPELLA_FORK_EPOCH`: Enables withdrawals
- `ELECTRA_FORK_EPOCH`: Enables EIP-7251

Services are conditionally initialized based on detected capabilities.

## Key Patterns

### 1. Slot-Based Execution

All validator duties are keyed to **slot number**:
- Controller watches for slot transitions
- Duties are scheduled relative to slot boundaries
- Attestations: 1/3 into slot
- Aggregations: 2/3 into slot
- Block proposals: Start of slot

When working with timing-sensitive code, always consider slot boundaries.

### 2. Concurrent Provider Queries

Strategies query multiple beacon nodes concurrently using scatter/gather pattern (`util/scatter.go`):

```go
// Launch concurrent requests
for name, provider := range s.providers {
    go func(name string, provider Provider) {
        result, err := provider.Get(ctx)
        respCh <- response{name: name, result: result, err: err}
    }(name, provider)
}

// Collect responses with timeout
select {
case resp := <-respCh:
    // Process response
case <-ctx.Done():
    // Timeout
}
```

### 3. Error Handling

- Use structured logging with `zerolog` (not `fmt.Printf`)
- Include context in errors: slot, validator index, provider name
- Emit metrics on errors for observability
- Don't panic; return errors

Example:
```go
log.Error().
    Uint64("slot", slot).
    Uint64("validator_index", validatorIndex).
    Str("provider", providerName).
    Err(err).
    Msg("Failed to obtain attestation data")
```

### 4. Testing with Mocks

Mock implementations exist for all services in `/mock` subdirectories:
- Use mocks for unit testing services in isolation
- Mocks implement same interfaces as real services
- Use functional options to inject mocks

### 5. Metrics & Observability

All operations should emit metrics:
- Client operation duration (per beacon node)
- Success/failure counts
- Validator duty counts
- Timing measurements (delays, latencies)

Metrics service is injected via `WithMonitor()` parameter.

## Common Development Scenarios

### Adding a New Service

1. Create service interface in `services/<name>/service.go`
2. Implement in `services/<name>/standard/service.go`
3. Add functional options pattern (`parameters` struct, `WithXXX` functions)
4. Add initialization in `main.go` at appropriate stage
5. Add mock in `services/<name>/mock/service.go` if needed for other services
6. Add metrics in `services/<name>/standard/metrics.go`
7. Add tests in `services/<name>/standard/*_test.go`

### Adding a New Strategy

1. Create strategy in `strategies/<type>/<style>/service.go`
2. Implement the provider interface (e.g., `eth2client.AttestationDataProvider`)
3. Add configuration parsing in `main.go` strategy initialization section
4. Update `docs/configuration.md` with new strategy documentation
5. Add tests

### Modifying Configuration

1. Add new config key to `docs/configuration.md` with documentation
2. Add parsing in `main.go` using `viper.Get*()` functions
3. Handle hierarchical overrides if needed (check `util/beaconnodeaddresses.go` pattern)
4. Add validation if required
5. Update example configs

### Working with Beacon Nodes

- Always use `eth2client` interfaces, not concrete types
- Handle errors gracefully (beacon nodes may be temporarily unavailable)
- Use appropriate timeouts (2s for critical operations, 2m for non-critical)
- Emit metrics for each beacon node operation
- Test with multiple beacon node implementations (Lighthouse, Prysm, Teku, Nimbus)

## Important Files

| File | Purpose |
|------|---------|
| `main.go` | Entry point, service initialization (2500+ lines) |
| `clients.go` | Beacon node client creation and caching |
| `commands.go` | CLI command handlers |
| `util/beaconnodeaddresses.go` | Hierarchical address resolution |
| `util/config.go` | Configuration utilities |
| `services/controller/standard/service.go` | Main orchestrator |
| `docs/configuration.md` | Complete configuration reference |
| `docs/getting_started.md` | Setup guide |

## Documentation

Detailed documentation in `/docs`:
- `configuration.md`: Complete configuration reference
- `getting_started.md`: Initial setup
- `accountmanager.md`: Account/key management
- `executionconfig.md`: Execution layer configuration
- `graffiti.md`: Graffiti provider configuration
- `blockrelay.md`: MEV-Boost setup
- `metrics/prometheus.md`: Metrics reference
- `metrics/grafana.md`: Grafana dashboard setup

## Ethproofs Integration

Vouch includes integration with [ethproofs.org](https://ethproofs.org) to verify that attestation source epochs have been cryptographically proven before casting votes.

### Overview

The **ethproofstracker** service polls the ethproofs.org REST API to track which Ethereum epochs have verified ZK proofs. When enabled, the attester service validates that the source epoch of an attestation has been proven before signing and submitting it.

**Critical Behavior**: If the source epoch has NOT been proven by ethproofs, the attestation is **blocked** (failed) rather than submitted. This prevents validators from voting on unverified checkpoints.

### Configuration

Add to `vouch.yml`:

```yaml
ethproofstracker:
  enabled: false                                  # Enable ethproofs verification (default: false)
  base-url: "https://ethproofs.org/api/v0"       # Ethproofs API base URL
  poll-interval: 12s                             # How often to poll for new proofs (default: 12s)
  timeout: 2s                                    # HTTP request timeout (default: 2s)
  cache-size: 100                                # Number of epochs to cache (default: 100, ~11 hours)
```

**Important**: Ethproofs verification is **disabled by default**. Set `enabled: true` to activate it.

### Architecture

**Location**: `services/ethproofstracker/`

**Key Components**:
- **Service Interface** (`service.go`): Defines `EpochProofChecker` interface with `IsEpochProven(epoch) bool`
- **Standard Implementation** (`standard/service.go`): Maintains thread-safe cache of proven epochs
- **Polling Logic** (`standard/poll.go`): Queries ethproofs.org API every 12 seconds
- **Metrics** (`standard/metrics.go`): Prometheus metrics for cache size, query success/failure, API latency
- **Mock** (`mock/ethproofstracker.go`): Test implementation

**Integration Point**: `services/attester/standard/attest.go:60-67`

After `validateAttestationData()`, the attester calls `validateSourceEpochProof()` which:
1. Checks if source epoch is proven via `IsEpochProven()`
2. If not proven, logs ERROR and returns error
3. If proven, continues with attestation signing

### API Interaction

The service queries the ethproofs.org REST API:

```
GET /api/v0/proofs?block={blockRootHex}
```

Response format:
```json
{
  "block": "0x1234...",
  "proofs": [
    {"type": "groth16", "status": "verified"},
    ...
  ]
}
```

The service considers an epoch proven if:
- The first slot of the epoch has a block
- That block's root has at least one verified proof in the ethproofs API

### Caching Strategy

- **Cache size**: Last 100 epochs (~11 hours)
- **Thread-safety**: `sync.RWMutex` protects the cache
- **Cleanup**: Old epochs are evicted when cache exceeds size limit
- **Polling**: Every 12 seconds (one slot), checks last 5 epochs for new proofs

### Metrics

Prometheus metrics emitted:

```
vouch_ethproofs_tracker_cache_size              # Current number of proven epochs in cache
vouch_ethproofs_tracker_query_total{result}     # Total API queries (result="proven" or "not_proven")
vouch_ethproofs_tracker_api_latency_seconds     # API request latency histogram
vouch_attestation_blocked_no_proof_total{epoch} # Attestations blocked due to unproven source
```

### Testing

**Mock Usage**: In tests, use the mock implementation:

```go
import "github.com/attestantio/vouch/services/ethproofstracker/mock"

tracker := mock.New()
tracker.SetProvenEpoch(phase0.Epoch(123), blockRoot)
```

**HTTP Mocking**: For integration tests, use `httptest.NewServer()` to mock the ethproofs API.

### Cryptographic Verification (Rust FFI)

The ethproofstracker performs **true cryptographic verification** of ZK proofs rather than trusting the API response. This is implemented using a **Hybrid Go/Rust architecture** via FFI (Foreign Function Interface).

**Architecture**:

1. **Rust Verifier Core** (`services/ethproofstracker/verifier/`):
   - Written in Rust using official zkVM verifier crates (`sp1-verifier`, `ziren-verifier`)
   - Compiled as a shared library (`.so` on Linux, `.dylib` on macOS)
   - Exposes C-compatible FFI interface

2. **Go CGO Bindings** (`services/ethproofstracker/standard/verifier_ffi.go`):
   - Calls Rust library via CGO
   - Type-safe Go wrapper around C FFI

3. **Verification Flow**:
   ```
   API Query → Download Proof Binary → Parse zkVM Type → FFI Call → Rust Verifier → Cryptographic Check
   ```

**Supported zkVMs**:
- **SP1** (Succinct): Fully supported with `sp1-verifier` crate
- **ZKM** (Ziren): Placeholder (verifier crate integration pending)
- **Pico** (Brevis): Placeholder (verifier crate integration pending)

**Building the Verifier**:

The Rust library is built automatically as part of the nix-shell environment:

```bash
# Build Rust verifier library
nix-shell shell.nix --run "cd services/ethproofstracker/verifier && cargo build --release"

# Library is automatically copied to services/ethproofstracker/lib/
# Go binary links to it via CGO LDFLAGS
```

**FFI Interface** (`verifier.h`):

```c
uint8_t verify_ethproof(
    uint8_t zkvm_type,      // 0=SP1, 1=ZKM, 2=Pico
    const uint8_t* proof_ptr,
    size_t proof_len,
    const uint8_t* block_root_ptr
);

// Returns:
// 0 = Verification failed
// 1 = Verification succeeded
// 2 = Error (unsupported zkVM, invalid data)
```

**Security**:
- Verification keys are embedded in the Rust library (not fetched from API)
- Prevents attacks where malicious API provides fake verification keys
- Proof format parsing handles zkVM-specific serialization (SP1ProofWithPublicValues, etc.)

**Implementation Status**:

The verifier uses the official `sp1-verifier` crate (v4.2.1) with proper API integration:
- `Groth16Verifier::verify()` - Cryptographic verification of Groth16 proofs
- Proof parsing and public input extraction
- Block root validation before cryptographic verification

**To enable full verification**, you need to obtain and embed:

1. **Ethereum Block Groth16 VKey** (`ETHEREUM_BLOCK_GROTH16_VK`):
   - Build the SP1 Reth program from [succinctlabs/rsp](https://github.com/succinctlabs/rsp)
   - Extract Groth16 verification key bytes from build artifacts
   - Or use `GROTH16_VK_BYTES` constant from sp1-verifier crate (for SP1 zkVM itself)

2. **Program VKey Hash** (`ETHEREUM_BLOCK_VKEY_HASH`):
   - Generated via `vk.bytes32()` from SP1 ProverClient
   - Format: hex string (e.g., "0x00...abc123")

**Current Behavior**: With empty placeholders, the verifier logs warnings and accepts proofs based on public input checking only (NOT SECURE - for development only).

**Production Deployment**: Set verification keys to proper values from trusted source. The verifier will then perform full Groth16 cryptographic verification.

See `services/ethproofstracker/verifier/src/lib.rs` for implementation details.

### Error Handling

- **Source epoch not proven**: Return error, block attestation, log at ERROR level
- **Ethproofs API timeout**: Log at DEBUG, continue with cached data
- **Ethproofs API 404**: Expected (not proven), mark as unproven in cache
- **Ethproofs API 5xx**: Log WARN, continue polling
- **Block root lookup fails**: Log WARN, skip that epoch
- **Proof verification fails**: Log WARN, mark epoch as unproven
- **FFI error**: Return error, block attestation (fail-safe)

### Development Notes

When working with ethproofstracker:

1. **Disabled by default**: The service only initializes if `enabled: true` in config
2. **Nil-safe**: All attester validation checks `if s.ethproofsTracker != nil` before calling
3. **Configuration check**: Also validates `viper.GetBool("ethproofstracker.enabled")` at runtime
4. **Fail-safe behavior**: Unknown proof status = block attestation (conservative approach)
5. **Initialization order**: Must be initialized in `main.go:startServices()` before passing to attester

## Code Style

- Use structured logging via `zerolog`
- Follow functional options pattern for service constructors
- Maintain interfaces for all services (enables mocking)
- Use context for cancellation and timeouts
- Emit metrics for all operations
- Include correlation IDs in logs where possible
- Don't use global state (except cached clients)
- Prefer dependency injection over singletons
