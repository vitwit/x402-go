# Schemes: `exact` and `upto` on `EVM`

> Source: [x402-foundation/x402 — scheme_exact_evm.md](https://github.com/x402-foundation/x402/blob/main/specs/schemes/exact/scheme_exact_evm.md)

## Summary

The `exact` and `upto` schemes on EVM execute a transfer where the Facilitator (server) pays the gas, but the Client (user) controls the flow of funds via cryptographic signatures.

- **`exact`**: The transferred amount MUST equal the `PaymentOption.amount` exactly.
- **`upto`**: The transferred amount MUST be greater than or equal to `PaymentOption.amount`; any surplus goes to the recipient.

This is implemented via one of two asset transfer methods, depending on the token's capabilities:

| AssetTransferMethod | Use Case                                                     | Recommendation                                 | Usage Semantics                     |
| :------------------ | :----------------------------------------------------------- | :--------------------------------------------- | :---------------------------------- |
| **1. EIP-3009**     | Tokens with native `transferWithAuthorization` (e.g., USDC). | **Recommended** (Simplest, truly gasless).     | One-time use                        |
| **2. Permit2**      | Tokens without EIP-3009. Uses a Proxy + Permit2.             | **Universal Fallback** (Works for any ERC-20). | One-time use                        |
| **3. ERC-7710**     | Smart accounts with delegation support.                      | **Smart Account Option** (Paid from ERC-7710 compatible account). | One-time use and multi-use |

If no `assetTransferMethod` is specified in the payload, the implementation should prioritize `eip3009` (if compatible) and then `permit2`.

In all cases, the Facilitator cannot modify the amount or destination. They serve only as the transaction broadcaster.

---

## 1. AssetTransferMethod: `EIP-3009`

The `eip3009` asset transfer method uses the `transferWithAuthorization` function directly on token contracts that support it.

### Phase 1: `PAYMENT-SIGNATURE` Header Payload

The `payload` field must contain:

- `signature`: The 65-byte signature of the `transferWithAuthorization` operation.
- `authorization`: The parameters required to reconstruct the signed message.

**Example PaymentPayload:**

```json
{
  "x402Version": 2,
  "resource": {
    "url": "https://api.example.com/premium-data",
    "description": "Access to premium market data",
    "mimeType": "application/json"
  },
  "accepted": {
    "scheme": "exact",
    "network": "eip155:84532",
    "amount": "10000",
    "asset": "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
    "payTo": "0x209693Bc6afc0C5328bA36FaF03C514EF312287C",
    "maxTimeoutSeconds": 60,
    "extra": {
      "assetTransferMethod": "eip3009",
      "name": "USDC",
      "version": "2"
    }
  },
  "payload": {
    "signature": "0x2d6a7588d6acca505cbf0d9a4a227e0c52c6c34008c8e8986a1283259764173608a2ce6496642e377d6da8dbbf5836e9bd15092f9ecab05ded3d6293af148b571c",
    "authorization": {
      "from": "0x857b06519E91e3A54538791bDbb0E22373e36b66",
      "to": "0x209693Bc6afc0C5328bA36FaF03C514EF312287C",
      "value": "10000",
      "validAfter": "1740672089",
      "validBefore": "1740672154",
      "nonce": "0xf3746613c2d920b5fdabc0856f2aeb2d4f88ee6037b8cc5d04a71a4462f13480"
    }
  }
}
```

### Phase 2: Verification Logic

1. **Verify** the signature is valid and recovers to the `authorization.from` address.
2. **Verify** the `client` has sufficient balance of the `asset`.
3. **Verify** the authorization parameters (Amount, Validity Window) meet the `PaymentOption` requirements — `exact` requires value == amount; `upto` requires value >= amount.
4. **Verify** the Token and Network match the requirement.
5. **Simulate** `token.transferWithAuthorization(...)` to ensure success.

### Phase 3: Settlement Logic

Settlement is performed via the facilitator calling the `transferWithAuthorization` function on the `EIP-3009` compliant contract with the `payload.signature` and `payload.authorization` parameters from the `PAYMENT-SIGNATURE` header.

---

## 2. AssetTransferMethod: `Permit2`

This asset transfer method uses the `permitWitnessTransferFrom` from the [canonical **Permit2** contract](#canonical-permit2) combined with a [`x402ExactPermit2Proxy`](#reference-implementation-x402exactpermit2proxy) to enforce receiver address security via the "Witness" pattern.

### Phase 1: One-Time Gas Approval

Permit2 requires the user to approve the [**Permit2 Contract** (Canonical Address)](#canonical-permit2) to spend their tokens. This is a one-time setup. The specification supports three ways to handle this:

#### Option A: Direct User Approval (Standard)

The user submits a standard on-chain `approve(Permit2)` transaction paying their own gas.

#### Option B: Sponsored ERC20 Approval

The Facilitator pays the gas for the approval transaction on the user's behalf.

#### Option C: EIP2612 Permit

If the token supports EIP-2612, the user signs a permit authorizing Permit2.

### Phase 2: `PAYMENT-SIGNATURE` Header Payload

The `payload` field must contain:

- `signature`: The signature for `permitWitnessTransferFrom`.
- `permit2Authorization`: Parameters to reconstruct the message.

**Important Logic:** The `spender` in the signature is the [**x402ExactPermit2Proxy**](#reference-implementation-x402exactpermit2proxy), not the Facilitator. This Proxy enforces that funds are only sent to the `witness.to` address.

> **Requirement**: This contract will be deployed to the same address across all supported EVM chains using `CREATE2` to ensure consistent behavior and simpler integration.

**Example PaymentPayload:**

```json
{
  "x402Version": 2,
  "accepted": {
    "scheme": "exact",
    "network": "eip155:84532",
    "amount": "10000",
    "payTo": "0x209693Bc6afc0C5328bA36FaF03C514EF312287C",
    "maxTimeoutSeconds": 60,
    "asset": "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
    "extra": {
      "assetTransferMethod": "permit2",
      "name": "USDC",
      "version": "2"
    }
  },
  "payload": {
    "signature": "0x2d6a7588...",
    "permit2Authorization": {
      "permitted": {
        "token": "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
        "amount": "10000"
      },
      "from": "0x857b06519E91e3A54538791bDbb0E22373e36b66",
      "spender": "0x402085c248EeA27D92E8b30b2C58ed07f9E20001",
      "nonce": "33247007178036348590600198031289925668252061821958005840077069883511451257277",
      "deadline": "1740672154",
      "witness": {
        "to": "0x209693Bc6afc0C5328bA36FaF03C514EF312287C",
        "validAfter": "1740672089"
      }
    }
  }
}
```

### Phase 3: Verification Logic

1. **Verify** `payload.signature` is valid and recovers to the `permit2Authorization.from`.
2. **Verify** that the `client` has enabled the Permit2 approval.
3. **Verify** the `client` has sufficient balance of the `asset`.
4. **Verify** the `permit2Authorization.amount` covers the payment.
5. **Verify** the `deadline` (not expired) and `witness.validAfter` (active).
6. **Verify** the Token and Network match the requirement.
7. **Simulation (Recommended):** Simulate `x402ExactPermit2Proxy.settle`.

### Phase 4: Settlement Logic

Settlement is performed by calling the `x402ExactPermit2Proxy`. Standard settlement calls `x402ExactPermit2Proxy.settle`.

---

## 3. AssetTransferMethod: `ERC-7710`

This asset transfer method uses [ERC-7710](https://eips.ethereum.org/EIPS/eip-7710) smart contract delegation to authorize transfers from accounts that support the standard.

### Phase 1: `PAYMENT-SIGNATURE` Header Payload

```json
{
  "x402Version": 2,
  "accepted": {
    "scheme": "exact",
    "network": "eip155:84532",
    "amount": "10000",
    "asset": "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
    "payTo": "0x209693Bc6afc0C5328bA36FaF03C514EF312287C",
    "maxTimeoutSeconds": 60,
    "extra": {
      "assetTransferMethod": "erc7710"
    }
  },
  "payload": {
    "delegationManager": "0xDelegationManagerAddress",
    "permissionContext": "0x...",
    "delegator": "0x857b06519E91e3A54538791bDbb0E22373e36b66"
  }
}
```

### Phase 2: Verification Logic

Unlike EIP-3009 and Permit2, ERC-7710 verification is performed entirely through simulation.

1. **Construct** the `executionCallData` encoding an ERC-20 `transfer(payTo, amount)` call.
2. **Construct** the `mode` appropriate for the execution.
3. **Simulate** `delegationManager.redeemDelegations([permissionContext], [mode], [executionCallData])`.

**Security Considerations:**

- **Race Condition Risk**: A client may invalidate their delegation between simulation and execution. Mitigate by submitting via a private mempool and setting explicit gas limits.
- **Malicious Delegation Manager**: Always set an explicit gas limit on `redeemDelegations` calls.

### Phase 3: Settlement Logic

```solidity
delegationManager.redeemDelegations(
    [permissionContext],
    [mode],
    [executionCallData]
);
```

---

## Annex

### Canonical Permit2

The Canonical Permit2 contract address can be found at [https://docs.uniswap.org/contracts/v4/deployments](https://docs.uniswap.org/contracts/v4/deployments).

### Reference Implementation: `x402ExactPermit2Proxy`

**Canonical Address:** `0x402085c248EeA27D92E8b30b2C58ed07f9E20001`

This contract acts as the authorized Spender. It validates the Witness data to ensure the destination cannot be altered by the Facilitator. Deployed to the same address across all supported EVM chains using `CREATE2`.
