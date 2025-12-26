# x402 Exact Scheme - Cosmos SDK

## Status

Draft

## Version

x402 Version: 1

## Scheme

`exact`

## Overview

The Cosmos Exact Scheme defines how a client pays for an x402-protected resource by submitting a fully signed Cosmos SDK transaction that transfers an exact amount of a native or Cosmos-based token to the resource's payTo address.

The facilitator:

- Verifies the transaction off-chain (structure, recipient, denom, amount).
- Simulates the transaction for validity.
- Broadcasts the transaction to the Cosmos network.
- Waits for confirmation and finalizes settlement.

This scheme mirrors the intent of the EVM/SVM exact schemes, while conforming to Cosmos SDK transaction semantics.

## Supported Networks

A network MUST be a Cosmos SDK chain.

## Assets

Assets are identified via the asset field in PaymentRequirements.

For Cosmos:

- Native tokens (e.g. uatom, uosmo)
- CW20 tokens are out of scope for this scheme version
- The facilitator MUST be configured with an acceptedDenom

If the transaction does not contain the accepted denom, it MUST be rejected.

## PaymentRequirements Object

A resource server advertises acceptable payment using:

``` json
{
  "scheme": "exact",
  "network": "cosmoshub-4",
  "maxAmountRequired": "1000000",
  "resource": "/v1/chat",
  "description": "LLM inference",
  "mimeType": "application/json",
  "payTo": "cosmos1facilitator...",
  "maxTimeoutSeconds": 30,
  "asset": "uatom"
}
```

### Semantics

| Field               | Meaning                    |
| ------------------- | -------------------------- |
| `scheme`            | MUST be `"exact"`          |
| `network`           | Cosmos chain ID            |
| `maxAmountRequired` | Amount in **atomic units** |
| `payTo`             | Recipient address          |
| `asset`             | Denom expected in tx       |
| `maxTimeoutSeconds` | Client response deadline   |

## Client Payment Payload

The client submits a PaymentPayload inside the retry request.

### PaymentPayload

``` json
{
  "x402Version": 1,
  "scheme": "exact",
  "network": "cosmoshub-4",
  "payload": "<base64(json)>"
}
```

The `payload` field MUST be a base64-encoded JSON object of type `CosmosPaymentPayload`.

### CosmosPaymentPayload

``` json
{
  "version": 1,
  "chainId": "cosmoshub-4",
  "payment": {
    "amount": "1000000",
    "denom": "uatom",
    "payer": "cosmos1payer...",
    "recipient": "cosmos1facilitator...",
    "txBase64": "<base64_tx_bytes>",
    "publicKey": "<base64_pubkey>",
    "fee": "5000",
    "gas": "200000",
    "memo": "x402 payment",
    "sequence": "42",
    "accountNumber": "12345"
  },
  "signature": "<optional>"
}

```

#### Requirements

- `txBase64` MUST be a fully signed Cosmos SDK transaction
- The transaction MUST contain a `MsgSend`
- The transaction MUST NOT require additional signatures
- The payer MUST be the signer

## Verification Phase (Facilitator)

When a `VerifyRequest` is received, the facilitator MUST:
- Base64-decode `PaymentPayload.payload`
- Decode `CosmosPaymentPayload`
- Base64-decode `txBase64`
- Decode the Cosmos SDK transaction
- Validate:
  - Transaction decodes successfully
  - At least one message exists
  - First message is `MsgSend`
  - `to_address` == `payTo`
  - Contains `acceptedDenom`
- Simulate the transaction via tx.Service/Simulate

### Verification Result

If valid:

``` json
{
  "isValid": true,
  "amount": "1000000",
  "token": "uatom",
  "recipient": "cosmos1facilitator...",
  "sender": "cosmos1payer...",
  "confirmations": 0
}
```

If invalid:

``` json
{
  "isValid": false,
  "invalidReason": "recipient mismatch"
}
```

## Settlement Phase

If verification succeeds, the facilitator MUST:
- Broadcast the transaction using:
  - BroadcastMode_SYNC
- Check TxResponse.Code == 0
- Poll GetTx until:
  - height > 0
  - OR timeout (~15s)

  ### Successful Settlement

``` json
{
  "success": true,
  "networkId": "cosmoshub-4",
  "asset": "uatom",
  "amount": "1000000",
  "recipient": "cosmos1facilitator...",
  "sender": "cosmos1payer...",
  "extra": {
    "code": 0,
    "codespace": "",
    "log": ""
  }
}
```

### Failure Modes

| Condition         | Error                              |
| ----------------- | ---------------------------------- |
| Broadcast failure | `SETTLEMENT_FAILED`                |
| Non-zero tx code  | `RawLog`                           |
| Timeout           | `timeout waiting for confirmation` |


## Finality & Confirmations
- Cosmos provides fast probabilistic finality
- This scheme treats inclusion in a block as sufficient
- confirmations is always 0 or 1 in v1

## Security Considerations

- Transactions are chain-bound via chainId
- Replay across chains is impossible
- Facilitator never signs on behalf of the user
- Funds move directly from payer → recipient
- Simulation prevents invalid or failing txs