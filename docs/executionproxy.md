# Execution layer Pre-BAL verification proxy

Vouch includes an optional Execution Layer (EL) Engine API proxy (`executionproxy`) that sits between a Consensus Layer (CL) client and multiple Execution Layer clients to perform cross-client stateless payload verification using **Pre-Execution Block Access Lists (`Pre-BAL`)**.

## Overview

When configured, the consensus client points its `--execution-endpoint` at Vouch's `executionproxy` listener instead of talking directly to a single execution client:

1. **Primary EL (`produce_pre_bal = true`)**:
   On incoming `engine_newPayloadV1`–`engine_newPayloadV6` requests, Vouch forwards the payload to the primary stateful EL (such as Besu) with `produce_pre_bal = true`. The primary EL validates and imports the block as usual and returns `PayloadStatus` together with the RLP-encoded `pre_bal`.
2. **Secondary ELs (`pre_bal` consumers)**:
   When the primary EL returns `VALID` with a `pre_bal`, Vouch fans out `engine_newPayloadV*` concurrently to all configured secondary stateless consumer ELs (such as Erigon, Geth, Reth, Nethermind, and ethrex) with `produce_pre_bal = false` and `pre_bal` populated.
3. **Unanimous Agreement & Forkchoice Protection**:
   - **All agree (`VALID`)**: Vouch strips the experimental `pre_bal` field (unless explicitly requested by the caller) and returns `VALID` to the consensus client.
   - **Explicit disagreement (`INVALID`)**: If any secondary EL rejects the payload with `INVALID` (or `INVALID_BLOCK_HASH`), Vouch returns `INVALID` to the consensus client, blocks any subsequent `engine_forkchoiceUpdatedV*` referencing that block hash, and rejects descendant payloads building on the invalid block.
   - **Secondary error / timeout**: If a secondary EL is unreachable, times out, or returns a JSON-RPC error or non-`VALID` status, Vouch returns a JSON-RPC error on `engine_newPayloadV*` and responds `SYNCING` on `engine_forkchoiceUpdatedV*` for that unverified head so the consensus client stays optimistic and retries without permanently marking the block invalid.
4. **Other Engine API & Execution RPC Methods**:
   All non-`engine_newPayloadV*` calls (`engine_forkchoiceUpdatedV*` for verified blocks, `engine_getPayloadV*`, `engine_getBlobsV*`, `engine_exchangeCapabilities`, `eth_*`, etc.) are proxied to the primary stateful EL.

## Operating modes

- **Integrated mode**: Runs alongside Vouch's normal validator duties. Vouch starts the `executionproxy` listener before connecting to beacon nodes so the consensus client and Vouch never deadlock during startup.
- **Standalone proxy mode**: If `executionproxy` is configured without `beacon-node-address` / `beacon-node-addresses`, Vouch runs purely as a standalone Execution Layer verification proxy without requiring validator accounts.

## Configuration

### Simple configuration (shared JWT secret)

```yaml
executionproxy:
  listen-address: '127.0.0.1:18551'
  jwt-secret: '/path/to/jwt.hex'
  timeout: '10s'
  primary-el: 'http://127.0.0.1:8551'
  secondary-els:
    - 'http://127.0.0.1:8552'
    - 'http://127.0.0.1:8553'
```

### Advanced configuration (per-EL names and JWT secrets)

`jwt-secret` values accept filesystem paths, Majordomo URLs (e.g. `file:///...`, `direct:///...`), or raw 32-byte hex strings:

```yaml
executionproxy:
  listen-address: '0.0.0.0:18551'
  incoming-jwt-secret: 'file:///etc/vouch/cl-jwt.hex'
  jwt-secret: 'file:///etc/vouch/default-el-jwt.hex'
  timeout: '10s'
  primary-el:
    name: 'besu-producer'
    url: 'http://127.0.0.1:8551'
    jwt-secret: 'file:///etc/vouch/besu-jwt.hex'
  secondary-els:
    - name: 'geth-consumer'
      url: 'http://127.0.0.1:8552'
      jwt-secret: 'file:///etc/vouch/geth-jwt.hex'
    - name: 'reth-consumer'
      url: 'http://127.0.0.1:8553'
      jwt-secret: 'file:///etc/vouch/reth-jwt.hex'
```

If no `jwt-secret` or `incoming-jwt-secret` is configured, incoming requests are not checked for JWT authentication and any `Authorization` header sent by the consensus client is forwarded to execution clients that do not specify their own `jwt-secret`.
