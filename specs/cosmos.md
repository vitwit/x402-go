# x402 Exact Scheme - Cosmos SDK (bank MsgSend)

## Status

Stable

## Version

x402 Version: 2

## Scheme

`exact` / `upto`

---

## Overview

The Cosmos exact scheme uses a **fully-signed `MsgSend` transaction** submitted by the client. The client builds and signs the transaction locally; the facilitator verifies it off-chain (optionally simulates it via gRPC), then broadcasts it as-is. No facilitator signing is required.

---

## Network Identifiers (CAIP-2)

| Network     | CAIP-2 identifier      |
|---|---|
| Cosmos Hub  | `cosmos:cosmoshub-4`   |
| Osmosis     | `cosmos:osmosis-1`     |
| Neutron     | `cosmos:neutron-1`     |
| Celestia    | `cosmos:celestia`      |

Custom chains: any `cosmos:<chain-id>` value is accepted when registered via `Provider.AddNetwork`.

---

## PaymentOption (Server → Client)

```json
{
  "scheme":            "exact",
  "network":           "cosmos:cosmoshub-4",
  "amount":            "1000000",
  "asset":             "uatom",
  "payTo":             "cosmos1facilitator...",
  "maxTimeoutSeconds": 60
}
```

| Field    | Semantics                                    |
|---|---|
| `amount` | Minimum amount required, in atomic units     |
| `asset`  | Cosmos denom (e.g. `uatom`, `uosmo`)         |
| `payTo`  | Recipient bech32 address                     |

---

## PaymentPayloadV2 (Client → Server)

```json
{
  "x402Version": 2,
  "accepted": {
    "scheme":  "exact",
    "network": "cosmos:cosmoshub-4",
    "amount":  "1000000",
    "asset":   "uatom",
    "payTo":   "cosmos1facilitator...",
    "maxTimeoutSeconds": 60
  },
  "payload": { ... }
}
```

The `payload` field is a `CosmosPayload` object:

```json
{
  "signature": "<base64 signature>",
  "authorization": {
    "from":      "cosmos1payer...",
    "to":        "cosmos1facilitator...",
    "amount":    "1000000",
    "denom":     "uatom",
    "timeoutAt": 1700000300
  },
  "signedTx": "<base64-encoded protobuf TxRaw>"
}
```

| Field                  | Requirement                                     |
|---|---|
| `signedTx`             | Base64-encoded, fully-signed Cosmos SDK `TxRaw` |
| `authorization.to`     | MUST equal `accepted.payTo`                     |
| `authorization.amount` | MUST be ≥ `accepted.amount`                     |
| `authorization.denom`  | MUST match `accepted.asset`                     |
| `timeoutAt`            | Unix timestamp; payment MUST NOT be expired     |

---

## Verification (Facilitator)

The facilitator MUST:

1. Decode the `CosmosPayload`.
2. Check `timeoutAt > now`.
3. Check `authorization.amount ≥ accepted.amount`.
4. Check `authorization.to == accepted.payTo` (case-insensitive).
5. Base64-decode `signedTx` and decode as `TxRaw` using the Cosmos SDK codec.
6. Confirm the first message is `MsgSend`.
7. Confirm `MsgSend.ToAddress == authorization.to`.
8. Confirm `MsgSend` contains the required denom with sufficient amount.
9. Optionally call `tx.Service/Simulate` via gRPC to confirm the transaction would succeed.

### VerifyResult

```json
{ "valid": true, "payer": "cosmos1payer..." }
{ "valid": false, "error": "recipient mismatch" }
```

---

## Settlement (Facilitator)

The facilitator MUST:

1. Base64-decode `signedTx`.
2. Call `BroadcastTx` with `BROADCAST_MODE_SYNC` via gRPC.
3. Check `TxResponse.Code == 0`.
4. Poll `GetTx` until `TxResponse.Height > 0` or timeout (~15 s).

### SettleResult

```json
{ "success": true, "transactionHash": "ABC123...", "network": "cosmos:cosmoshub-4", "payer": "cosmos1payer..." }
{ "success": false, "error": "timeout waiting for confirmation" }
```

### Failure Modes

| Condition            | Error                                  |
|---|---|
| Broadcast failure    | gRPC error message                     |
| Non-zero tx code     | `TxResponse.RawLog`                    |
| Confirmation timeout | `"timeout waiting for confirmation"`   |

---

## Security Considerations

- Transactions are chain-bound by `chain_id` in the transaction body; cross-chain replay is impossible.
- The facilitator does not sign on behalf of the user; it only broadcasts the pre-signed transaction.
- Funds move directly from payer to recipient via the `MsgSend`.
- `Simulate` prevents broadcasting transactions that would fail on-chain.
- `timeoutAt` ensures the authorization cannot be replayed after expiry.
