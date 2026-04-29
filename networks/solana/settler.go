package solana

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	bin "github.com/gagliardetto/binary"
	solanago "github.com/gagliardetto/solana-go"
	"github.com/gagliardetto/solana-go/rpc"
	"github.com/vitwit/x402-go"
)

// SettlerConfig holds the facilitator wallet and RPC endpoints.
type SettlerConfig struct {
	// PrivateKey is the facilitator's Solana private key.
	PrivateKey solanago.PrivateKey
	// RPCEndpoints maps CAIP-2 network ID to RPC HTTP URL.
	RPCEndpoints map[string]string
	// WSEndpoints maps CAIP-2 network ID to RPC WebSocket URL (optional).
	WSEndpoints map[string]string
}

// settlementCache is a short-lived, in-memory set of recently submitted transaction
// payloads. It guards against the duplicate-settlement race condition described in
// the x402 Solana spec: a client submitting the same transaction twice before the
// first one is confirmed on-chain would otherwise receive two successful responses.
// Entries are evicted after 120 s — roughly twice the Solana blockhash lifetime.
type settlementCache struct {
	mu      sync.Mutex
	entries map[string]time.Time
}

// checkAndAdd returns true (duplicate) if key is already present; otherwise it
// inserts key and returns false. Expired entries are evicted on each call.
func (c *settlementCache) checkAndAdd(key string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	for k, t := range c.entries {
		if now.Sub(t) > 120*time.Second {
			delete(c.entries, k)
		}
	}
	if _, exists := c.entries[key]; exists {
		return true
	}
	c.entries[key] = now
	return false
}

// Settler co-signs and broadcasts the Solana SPL token transfer transaction.
type Settler struct {
	networks []string
	cfg      SettlerConfig
	cache    *settlementCache
}

func NewSettler(networks []string, cfg SettlerConfig) *Settler {
	if networks == nil {
		networks = DefaultNetworks()
	}
	return &Settler{
		networks: networks,
		cfg:      cfg,
		cache:    &settlementCache{entries: make(map[string]time.Time)},
	}
}

func (s *Settler) Networks() []string { return s.networks }
func (s *Settler) Schemes() []x402.Scheme {
	return []x402.Scheme{x402.SchemeExact, x402.SchemeUpto}
}

func (s *Settler) Settle(ctx context.Context, req x402.SettleRequest) (x402.SettleResult, error) {
	var solPayload x402.SolanaPayload
	if err := json.Unmarshal(req.PaymentPayload.Payload, &solPayload); err != nil {
		return x402.SettleResult{}, fmt.Errorf("unmarshal solana payload: %w", err)
	}

	if s.cache.checkAndAdd(solPayload.Transaction) {
		return x402.SettleResult{Error: "duplicate_settlement"}, nil
	}

	txBytes, err := base64.StdEncoding.DecodeString(solPayload.Transaction)
	if err != nil {
		return x402.SettleResult{Error: "invalid_transaction_base64"}, nil
	}

	tx, err := solanago.TransactionFromDecoder(bin.NewBinDecoder(txBytes))
	if err != nil {
		return x402.SettleResult{Error: "invalid_transaction"}, nil
	}

	network := req.PaymentPayload.Accepted.Network
	rpcURL := s.cfg.RPCEndpoints[network]
	if rpcURL == "" {
		rpcURL = RPCFromNetwork(network)
	}
	if rpcURL == "" {
		return x402.SettleResult{Error: "no RPC endpoint for " + network}, nil
	}
	rpcClient := rpc.New(rpcURL)

	// Determine fee payer public key
	feePayer := s.cfg.PrivateKey.PublicKey()

	// Validate required signatures are present
	required := int(tx.Message.Header.NumRequiredSignatures)
	if required == 0 || len(tx.Signatures) < required {
		return x402.SettleResult{Error: "transaction_missing_required_signatures"}, nil
	}

	// Verify user (non-feepayer) signatures before co-signing
	msgBytes, err := getSignBytes(tx.Message)
	if err != nil {
		return x402.SettleResult{Error: err.Error()}, nil
	}
	if err := verifyUserSignatures(tx.Message, tx.Signatures, feePayer, msgBytes); err != nil {
		return x402.SettleResult{Error: err.Error()}, nil
	}

	// Blockhash freshness
	if err := verifyBlockhashFreshness(ctx, rpcClient, tx.Message); err != nil {
		return x402.SettleResult{Error: err.Error()}, nil
	}

	// Sign as facilitator (fee payer) using raw ed25519
	sk := ed25519.PrivateKey(s.cfg.PrivateKey)
	sigBytes := ed25519.Sign(sk, msgBytes)
	if len(sigBytes) != ed25519.SignatureSize {
		return x402.SettleResult{Error: "invalid_facilitator_signature_length"}, nil
	}
	var payerSig solanago.Signature
	copy(payerSig[:], sigBytes)

	// Place facilitator signature in the correct slot
	placed := false
	for i := 0; i < required; i++ {
		if tx.Message.AccountKeys[i].Equals(feePayer) {
			if i >= len(tx.Signatures) {
				newSigs := make([]solanago.Signature, required)
				copy(newSigs, tx.Signatures)
				tx.Signatures = newSigs
			}
			tx.Signatures[i] = payerSig
			placed = true
			break
		}
	}
	if !placed {
		tx.Signatures[0] = payerSig
	}

	// Determine client payer (first non-facilitator signed slot)
	clientPayer := ""
	for i, sig := range tx.Signatures {
		if sig == (solanago.Signature{}) {
			continue
		}
		pk := tx.Message.AccountKeys[i]
		if !pk.Equals(feePayer) {
			clientPayer = pk.String()
			break
		}
	}

	// Broadcast
	sentSig, err := rpcClient.SendTransaction(ctx, tx)
	if err != nil {
		// Fallback: marshal and send raw bytes
		raw, merr := tx.MarshalBinary()
		if merr != nil {
			return x402.SettleResult{Error: fmt.Sprintf("broadcast_failed: %v", err)}, nil
		}
		sentSig, err = rpcClient.SendRawTransaction(ctx, raw)
		if err != nil {
			return x402.SettleResult{Error: fmt.Sprintf("broadcast_failed: %v", err)}, nil
		}
	}

	// Poll for confirmation
	confirmed, confErr := waitForConfirmation(ctx, rpcClient, sentSig, 40, 500*time.Millisecond)
	res := x402.SettleResult{
		TransactionHash: sentSig.String(),
		Network:         network,
		Payer:           clientPayer,
	}
	if confErr != nil {
		res.Error = confErr.Error()
		return res, nil
	}
	if !confirmed {
		res.Error = "transaction_not_confirmed"
		return res, nil
	}

	res.Success = true
	return res, nil
}

func waitForConfirmation(ctx context.Context, rpcClient *rpc.Client, sig solanago.Signature, maxAttempts int, delay time.Duration) (bool, error) {
	for i := 0; i < maxAttempts; i++ {
		resp, err := rpcClient.GetSignatureStatuses(ctx, false, sig)
		if err != nil {
			return false, fmt.Errorf("rpc_signature_status_error: %w", err)
		}
		if len(resp.Value) > 0 && resp.Value[0] != nil {
			status := resp.Value[0]
			if status.ConfirmationStatus == rpc.ConfirmationStatusFinalized ||
				status.ConfirmationStatus == rpc.ConfirmationStatusConfirmed {
				if status.Err != nil {
					return false, fmt.Errorf("transaction_runtime_error: %v", status.Err)
				}
				return true, nil
			}
		}
		time.Sleep(delay)
	}
	return false, errors.New("confirmation_timeout")
}
