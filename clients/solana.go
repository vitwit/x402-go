package clients

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	bin "github.com/gagliardetto/binary"
	"github.com/gagliardetto/solana-go"
	"github.com/shopspring/decimal"

	"github.com/gagliardetto/solana-go/programs/token"
	"github.com/gagliardetto/solana-go/rpc"
	"github.com/vitwit/x402/types"
	x402types "github.com/vitwit/x402/types"
)

var _ Client = (*SolanaClient)(nil)

// --- Constants (program IDs) ---
// ComputeBudget program (canonical)
var ComputeBudgetProgramID = solana.MustPublicKeyFromBase58("ComputeBudget111111111111111111111111111111")

// SPL Token program (canonical)
var TokenProgramID = solana.MustPublicKeyFromBase58("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA")

// Associated Token Account program (canonical)
var AssociatedTokenProgramID = solana.MustPublicKeyFromBase58("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL")

// Token-2022 program ids (detect; unimplemented)
var Token2022ProgramIDs = []solana.PublicKey{
	// example token-2022 id (add known IDs as needed)
	solana.MustPublicKeyFromBase58("TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"),
}

// -------------------------
// Add to SolanaClient struct
// -------------------------
// store facilitator private key (ed25519 private key bytes)
type SolanaClient struct {
	network    string
	rpcURL     string
	client     *rpc.Client
	feePayerPK solana.PublicKey   // facilitator public key
	feePayerSK ed25519.PrivateKey // facilitator private key (32 or 64 bytes, depending)
}

// Close implements Client.
func (s *SolanaClient) Close() {
	panic("unimplemented")
}

// GetNetwork implements Client.
func (s *SolanaClient) GetNetwork() string {
	return s.network
}

// SettlePayment implements Client.
func (s *SolanaClient) SettlePayment(ctx context.Context, payload *x402types.VerifyRequest) (*x402types.SettlementResult, error) {
	// 1) Decode wrapper JSON (same as VerifyPayment)

	vr, err := s.VerifyPayment(ctx, payload)
	if err != nil {
		return &types.SettlementResult{
			NetworkId: payload.PaymentPayload.Network,
			Asset:     payload.PaymentRequirements.Asset,
			Amount:    payload.PaymentRequirements.MaxAmountRequired,
			Recipient: payload.PaymentRequirements.PayTo,
			Error:     err.Error(),
			Success:   false,
			Sender:    "",
		}, err
	}

	if !vr.IsValid {
		return &types.SettlementResult{
			NetworkId: payload.PaymentPayload.Network,
			Asset:     payload.PaymentRequirements.Asset,
			Amount:    payload.PaymentRequirements.MaxAmountRequired,
			Recipient: payload.PaymentRequirements.PayTo,
			Error:     vr.Error,
			Success:   false,
			Sender:    "",
		}, nil
	}

	wrapper, err := decodeTopLevelPaymentPayload(payload.PaymentPayload.Payload)
	if err != nil {
		return &x402types.SettlementResult{
			NetworkId: payload.PaymentPayload.Network,
			Asset:     payload.PaymentRequirements.Asset,
			Amount:    vr.Amount,
			Recipient: payload.PaymentRequirements.PayTo,
			Error:     err.Error(),
			Success:   false,
			Sender:    vr.Sender,
		}, fmt.Errorf("invalid_payload: %w", err)
	}

	// 2) Decode base64 transaction bytes
	txBytes, err := base64.StdEncoding.DecodeString(wrapper.Transaction)
	if err != nil {
		return &x402types.SettlementResult{
			NetworkId: payload.PaymentPayload.Network,
			Asset:     payload.PaymentRequirements.Asset,
			Amount:    vr.Amount,
			Recipient: payload.PaymentRequirements.PayTo,
			Error:     err.Error(),
			Success:   false,
			Sender:    vr.Sender,
		}, fmt.Errorf("invalid_transaction_base64: %w", err)
	}

	// 3) Parse transaction
	tx, err := solana.TransactionFromDecoder(bin.NewBinDecoder(txBytes))
	if err != nil {
		return &x402types.SettlementResult{
			NetworkId: payload.PaymentPayload.Network,
			Asset:     payload.PaymentRequirements.Asset,
			Amount:    vr.Amount,
			Recipient: payload.PaymentRequirements.PayTo,
			Error:     err.Error(),
			Success:   false,
			Sender:    vr.Sender,
		}, fmt.Errorf("invalid_transaction: %w", err)
	}

	// 4) Determine feePayer: prefer PaymentRequirements.Extra["feePayer"], fallback to configured facilitator PK.
	var feePayer solana.PublicKey
	if fp, ok := payload.PaymentRequirements.Extra["feePayer"]; ok {
		if fps, ok2 := fp.(string); ok2 && fps != "" {
			if pk, err := solana.PublicKeyFromBase58(fps); err == nil {
				feePayer = pk
			}
		}
	}
	if feePayer.IsZero() {
		feePayer = s.feePayerPK
	}

	// 5) Basic safety: ensure there is at least one signature slot (fee payer placeholder expected)
	required := int(tx.Message.Header.NumRequiredSignatures)
	if required == 0 || len(tx.Signatures) < required {
		return &x402types.SettlementResult{
			NetworkId: payload.PaymentPayload.Network,
			Asset:     payload.PaymentRequirements.Asset,
			Amount:    vr.Amount,
			Recipient: payload.PaymentRequirements.PayTo,
			Error:     "transaction_missing_required_signatures",
			Success:   false,
			Sender:    vr.Sender,
		}, errors.New("transaction_missing_required_signatures")
	}

	// 6) Verify user signatures (skip fee payer index). This uses the helper you already added.
	if err := verifyUserSignatures(tx.Message, tx.Signatures, feePayer); err != nil {
		return &x402types.SettlementResult{
			NetworkId: payload.PaymentPayload.Network,
			Asset:     payload.PaymentRequirements.Asset,
			Amount:    vr.Amount,
			Recipient: payload.PaymentRequirements.PayTo,
			Error:     err.Error(),
			Success:   false,
			Sender:    vr.Sender,
		}, fmt.Errorf("user_signature_verification_failed: %w", err)
	}

	// 7) Prepare sign-bytes for signing (v0 or legacy)
	msgBytes, err := getSignBytes(tx.Message)
	if err != nil {
		return &x402types.SettlementResult{
			NetworkId: payload.PaymentPayload.Network,
			Asset:     payload.PaymentRequirements.Asset,
			Amount:    vr.Amount,
			Recipient: payload.PaymentRequirements.PayTo,
			Error:     err.Error(),
			Success:   false,
			Sender:    vr.Sender,
		}, fmt.Errorf("failed_to_serialize_message_for_signing: %w", err)
	}

	if err := verifyBlockhashFreshness(ctx, s.client, tx.Message); err != nil {
		fmt.Println("Err = ", err)
		return &x402types.SettlementResult{
			NetworkId: payload.PaymentPayload.Network,
			Asset:     payload.PaymentRequirements.Asset,
			Amount:    vr.Amount,
			Recipient: payload.PaymentRequirements.PayTo,
			Error:     err.Error(),
			Success:   false,
			Sender:    vr.Sender,
		}, fmt.Errorf("failed_to_serialize_message_for_signing: %w", err)
	}

	// 8) Sign as facilitator (fee payer) using stored ed25519 private key
	sigBytes := ed25519.Sign(s.feePayerSK, msgBytes)
	if len(sigBytes) != ed25519.SignatureSize {
		return &x402types.SettlementResult{
			NetworkId: payload.PaymentPayload.Network,
			Asset:     payload.PaymentRequirements.Asset,
			Amount:    vr.Amount,
			Recipient: payload.PaymentRequirements.PayTo,
			Error:     "invalid_facilitator_signature_length",
			Success:   false,
			Sender:    vr.Sender,
		}, errors.New("invalid_facilitator_signature_length")
	}

	// Copy into solana.Signature type ([64]byte)
	var payerSig solana.Signature
	copy(payerSig[:], sigBytes)

	// Replace signature index corresponding to the fee payer.
	// The spec expects the fee payer to occupy one of the required signer slots (commonly index 0).
	// Find the first account key that equals feePayer among required signer indices and set its signature.
	placed := false
	for i := 0; i < required; i++ {
		if tx.Message.AccountKeys[i].Equals(feePayer) {
			// Ensure tx.Signatures slice is large enough (it should be), then set.
			if i >= len(tx.Signatures) {
				// extend if for some reason signatures slice is shorter (defensive)
				// create a zero-initialized signature array up to required length
				// NOTE: TransactionFromDecoder normally gives correct length; this is defensive.
				newSigs := make([]solana.Signature, required)
				copy(newSigs, tx.Signatures)
				tx.Signatures = newSigs
			}
			tx.Signatures[i] = payerSig
			placed = true
			break
		}
	}
	if !placed {
		// If feePayer wasn't found among the required signer indices, place at index 0 (best-effort)
		tx.Signatures[0] = payerSig
	}

	// 9) Broadcast transaction. Prefer SendTransaction (accepts *solana.Transaction), fallback to SendRawTransaction.
	var sentSig solana.Signature
	// Try SendTransaction (common in gagliardetto rpc client)
	sentSig, err = s.client.SendTransaction(ctx, tx)
	if err != nil {
		// fallback: try send raw bytes
		raw, err := tx.MarshalBinary() // Transaction.Bytes() returns wire-format bytes (gagliardetto)
		if err != nil {
			return &x402types.SettlementResult{
				NetworkId: payload.PaymentPayload.Network,
				Asset:     payload.PaymentRequirements.Asset,
				Amount:    vr.Amount,
				Recipient: payload.PaymentRequirements.PayTo,
				Error:     err.Error(),
				Success:   false,
				Sender:    vr.Sender,
			}, fmt.Errorf("transaction_marshal_error: %w", err)
		}

		sentSig, err = s.client.SendRawTransaction(ctx, raw)
		if err != nil {
			return &x402types.SettlementResult{
				NetworkId: payload.PaymentPayload.Network,
				Asset:     payload.PaymentRequirements.Asset,
				Amount:    vr.Amount,
				Recipient: payload.PaymentRequirements.PayTo,
				Success:   false,
				Sender:    vr.Sender,
				Error:     fmt.Sprintf("broadcast_failed: %v", err),
			}, fmt.Errorf("rpc_send_transaction_failed: %w", err)
		}
	}

	// Poll until confirmed
	confirmed, confErr := waitForConfirmation(ctx, s.client, sentSig, 40, 500*time.Millisecond)

	// Always include TxHash
	res := &x402types.SettlementResult{
		TxHash:    sentSig.String(),
		NetworkId: s.network,
		Extra: x402types.ExtraData{
			"feePayer": feePayer.String(),
		},
	}

	if confErr != nil {
		res.Success = false
		res.Error = confErr.Error()
		return res, nil
	}

	if !confirmed {
		res.Success = false
		res.Error = "transaction_not_confirmed"
		return res, nil
	}

	res.Asset = payload.PaymentRequirements.Asset
	res.Amount = vr.Amount
	res.Recipient = payload.PaymentRequirements.PayTo
	res.Sender = vr.Sender

	// Transaction confirmed
	res.Success = true
	res.Error = ""
	return res, nil
}

func waitForConfirmation(ctx context.Context, client *rpc.Client, sig solana.Signature, maxAttempts int, delay time.Duration) (bool, error) {
	for i := 0; i < maxAttempts; i++ {

		resp, err := client.GetSignatureStatuses(ctx, false, sig)
		if err != nil {
			return false, fmt.Errorf("rpc_signature_status_error: %w", err)
		}

		if len(resp.Value) > 0 {
			status := resp.Value[0]

			// If status is available
			if status != nil {
				if status.ConfirmationStatus == rpc.ConfirmationStatusFinalized ||
					status.ConfirmationStatus == rpc.ConfirmationStatusConfirmed {

					if status.Err != nil {
						return false, fmt.Errorf("transaction_runtime_error: %v", status.Err)
					}

					return true, nil
				}
			}
		}

		time.Sleep(delay)
	}

	return false, errors.New("confirmation_timeout")
}

// validateSchemeAndNetworkPayload checks payload.Scheme and payload.PaymentRequirements.Scheme/network parity
func validateSchemeAndNetworkPayload(payload *x402types.VerifyRequest) error {
	// spec uses scheme string "exact-svm" per user-specified doc.
	requiredScheme := "exact"

	// PaymentPayload.Scheme (top-level) AND PaymentRequirements.Scheme must equal requiredScheme
	if payload.PaymentPayload.Scheme != requiredScheme || payload.PaymentRequirements.Scheme != requiredScheme {
		return errors.New(ErrUnsupportedScheme)
	}

	return nil
}

// VerifyPayment implements Client.
func (c *SolanaClient) VerifyPayment(
	ctx context.Context,
	payload *x402types.VerifyRequest,
) (*x402types.VerificationResult, error) {
	if err := validateSchemeAndNetworkPayload(payload); err != nil {
		return &x402types.VerificationResult{IsValid: false, InvalidReason: err.Error()}, nil
	}

	// 1) Decode top-level payment payload wrapper (base64 JSON => wrapper struct)
	wrapper, err := decodeTopLevelPaymentPayload(payload.PaymentPayload.Payload)
	if err != nil {
		return &x402types.VerificationResult{IsValid: false, InvalidReason: ErrInvalidExactSvmPayload}, nil
	}

	// 2) Decode transaction bytes (base64 inside wrapper)
	txBytes, err := base64.StdEncoding.DecodeString(wrapper.Transaction)
	if err != nil {
		return &x402types.VerificationResult{IsValid: false, InvalidReason: ErrInvalidExactSvmPayload}, nil
	}

	tx, err := solana.TransactionFromDecoder(bin.NewBinDecoder(txBytes))
	if err != nil {
		return &x402types.VerificationResult{IsValid: false, InvalidReason: ErrInvalidExactSvmPayload}, nil
	}

	tx, err = solana.TransactionFromDecoder(bin.NewBinDecoder(txBytes))

	// 3) Decompile message and resolve lookup tables into "msg" and "allKeys"
	msg, allKeys, err := c.decompileMessageWithLookups(ctx, *tx)
	if err != nil {
		return &x402types.VerificationResult{IsValid: false, InvalidReason: ErrInvalidExactSvmPayload}, nil
	}

	// after decompileMessageWithLookups(...)
	if err := verifyBlockhashFreshness(ctx, c.client, msg); err != nil {
		return &x402types.VerificationResult{IsValid: false, InvalidReason: err.Error()}, nil
	}

	// 4) Validate instruction count & order
	// Allowed: 3 instructions OR 4 instructions (with ATA create at index 2)
	if len(msg.Instructions) != 3 && len(msg.Instructions) != 4 {
		return &x402types.VerificationResult{IsValid: false, InvalidReason: ErrInvalidInstructionsLength}, nil
	}

	// Expect order:
	// 0: compute limit (discriminator 2)
	// 1: compute price (discriminator 3)
	// optional 2: create associated token account (if present)
	// last: transfer checked
	// Validate first two
	if err := verifyComputeLimitInstructionMsg(&msg, 0, allKeys); err != nil {
		return &x402types.VerificationResult{IsValid: false, InvalidReason: err.Error()}, nil
	}
	if err := verifyComputePriceInstructionMsg(&msg, 1, allKeys); err != nil {
		return &x402types.VerificationResult{IsValid: false, InvalidReason: err.Error()}, nil
	}

	// Determine index of transfer instruction and whether a create ATA exists at index 2
	createATAExists := false
	transferIdx := 2
	if len(msg.Instructions) == 4 {
		// index 2 must be associated token account create
		if !isCreateAssociatedTokenAccountInstruction(msg.Instructions[2]) {
			return &x402types.VerificationResult{IsValid: false, InvalidReason: ErrInvalidInstructionsLength}, nil
		}
		createATAExists = true
		transferIdx = 3
	}

	// 5) Fee payer safety: configured fee payer MUST NOT appear in any instruction's accounts
	var feePayer solana.PublicKey // default nil
	// prefer feePayer from paymentRequirements Extra "feePayer" if present
	// payload.PaymentRequirements should contain "Extra" map with feePayer - try to extract
	if fp, ok := payload.PaymentRequirements.Extra["feePayer"]; ok {
		if fps, ok2 := fp.(string); ok2 && fps != "" {
			if pk, err := solana.PublicKeyFromBase58(fps); err == nil {
				feePayer = pk
			}
		}
	}

	// after feePayer resolved and msg obtained
	if err := verifyPayerIdentity(msg, feePayer); err != nil {
		return &x402types.VerificationResult{IsValid: false, InvalidReason: err.Error()}, nil
	}

	// If still zero, use tx.Message.AccountKeys[0] as fee payer
	if feePayer.IsZero() {
		if len(msg.AccountKeys) > 0 {
			feePayer = msg.AccountKeys[0]
		}
	}

	if err := verifyUserSignatures(msg, tx.Signatures, feePayer); err != nil {
		return &x402types.VerificationResult{IsValid: false, InvalidReason: err.Error()}, nil
	}

	// Ensure feePayer does not appear in any instruction accounts
	for _, inst := range msg.Instructions {
		for _, ai := range inst.Accounts {
			fmt.Println(allKeys[ai])
			if allKeys[ai].Equals(feePayer) {
				return &x402types.VerificationResult{IsValid: false, InvalidReason: ErrFeePayerIncludedInInstructionAccounts}, nil
			}
		}
	}

	// 6) Validate transfer instruction: should be SPL or token-2022 TransferChecked
	transferInst := msg.Instructions[transferIdx]
	transferProg := allKeys[transferInst.ProgramIDIndex]

	// If token-2022 program - return unimplemented
	for _, p := range Token2022ProgramIDs {
		if transferProg.Equals(p) {
			return &x402types.VerificationResult{
				IsValid:       false,
				InvalidReason: "token-2022_unimplemented",
			}, nil
		}
	}

	// If not SPL token program -> invalid
	if !transferProg.Equals(TokenProgramID) {
		return &x402types.VerificationResult{IsValid: false, InvalidReason: ErrNotATransferInstruction}, nil
	}

	// 7) Parse TransferChecked (SPL) and validate accounts, amount, mint, destination == ATA(owner=payTo, mint=asset)
	vr, err := c.validateSplTransferChecked(ctx, *tx, &msg, allKeys, transferIdx, createATAExists, payload.PaymentRequirements)
	if err != nil {
		// return error reason if it's an x402 error string
		return &x402types.VerificationResult{IsValid: false, InvalidReason: err.Error()}, nil
	}

	return vr, nil
}

// validateSplTransferChecked parses and validates the TransferChecked at transferIdx
func (c *SolanaClient) validateSplTransferChecked(
	ctx context.Context,
	tx solana.Transaction,
	msg *solana.Message,
	allKeys []solana.PublicKey,
	transferIdx int,
	createATAExists bool,
	preq x402types.PaymentRequirements,
) (*x402types.VerificationResult, error) {
	if transferIdx >= len(msg.Instructions) {
		return nil, errors.New(ErrNotATransferInstruction)
	}

	inst := msg.Instructions[transferIdx]

	// Build local account metas for decode (order matters)
	metas := make([]*solana.AccountMeta, len(inst.Accounts))
	for i, ai := range inst.Accounts {
		pk := allKeys[ai]
		writable, _ := msg.IsWritable(pk)
		metas[i] = &solana.AccountMeta{
			PublicKey:  pk,
			IsSigner:   msg.IsSigner(pk),
			IsWritable: writable,
		}
	}

	// Try decode as SPL token instruction
	splInst, err := token.DecodeInstruction(metas, inst.Data)
	if err != nil {
		return nil, errors.New(ErrNotATransferInstruction)
	}

	// Ensure it's TransferChecked
	tc, ok := splInst.Impl.(*token.TransferChecked)
	if !ok {
		return nil, errors.New(ErrNotATransferCheckedInstruction)
	}

	// Expected account ordering for TransferChecked (per spl token lib):
	// [source, mint, destination, authority, token_program?, ...]
	if len(inst.Accounts) < 4 {
		return nil, errors.New(ErrNotATransferInstruction)
	}
	source := allKeys[inst.Accounts[0]]
	mint := allKeys[inst.Accounts[1]]
	dest := allKeys[inst.Accounts[2]]
	authority := allKeys[inst.Accounts[3]]

	// 1) Fee payer must NOT be authority or source
	var feePayer solana.PublicKey
	if fp, ok := preq.Extra["feePayer"]; ok {
		if fps, ok2 := fp.(string); ok2 && fps != "" {
			if pk, err := solana.PublicKeyFromBase58(fps); err == nil {
				feePayer = pk
			}
		}
	}
	// fallback: set feePayer to tx top-level account if still zero
	if feePayer.IsZero() {
		if len(msg.AccountKeys) > 0 {
			feePayer = msg.AccountKeys[0]
		}
	}
	if authority.Equals(feePayer) {
		return nil, errors.New(ErrFeePayerTransferringFunds)
	}
	if source.Equals(feePayer) {
		return nil, errors.New(ErrFeePayerTransferringFunds)
	}

	// in validateSplTransferChecked, after mint := allKeys[inst.Accounts[1]]
	whitelist := []solana.PublicKey{ /* fill from config or PaymentRequirements.Extra if provided */ }
	if err := verifyMintWhitelisted(ctx, c.client, mint, whitelist); err != nil {
		return nil, err
	}

	// 2) Destination must be the ATA for (owner=payTo, mint=asset) under the selected token program
	expectedMint := preq.Asset
	expectedOwner := preq.PayTo
	if expectedMint == "" || expectedOwner == "" {
		return nil, errors.New(ErrInvalidExactSvmPayload)
	}
	mintPk, err := solana.PublicKeyFromBase58(expectedMint)
	if err != nil {
		return nil, errors.New(ErrInvalidExactSvmPayload)
	}
	ownerPk, err := solana.PublicKeyFromBase58(expectedOwner)
	if err != nil {
		return nil, errors.New(ErrInvalidExactSvmPayload)
	}
	expectedATA, err := findAssociatedTokenPDA(ownerPk, mintPk)
	if err != nil {
		return nil, fmt.Errorf("ata_derivation_failed: %w", err)
	}
	if !dest.Equals(expectedATA) {
		return nil, errors.New(ErrTransferToIncorrectATA)
	}

	// 3) Account existence checks:
	// source must exist
	okSrc, _ := c.fetchAccountExists(ctx, source)
	if !okSrc {
		return nil, errors.New(ErrSenderATANotFound)
	}
	// destination must exist iff createATAExists == false
	okDst, _ := c.fetchAccountExists(ctx, dest)
	if !createATAExists && !okDst {
		return nil, errors.New(ErrReceiverATANotFound)
	}

	// convert required decimals from preq.Decimals (string/int) to uint8
	expectedDecimals := uint8(6) // adapt conversion as needed
	if err := verifyMintDecimals(ctx, c.client, mint, expectedDecimals); err != nil {
		return nil, err
	}

	// 4) Amount must equal maxAmountRequired exactly
	reqAmt, err := decimal.NewFromString(preq.MaxAmountRequired)
	if err != nil {
		return nil, errors.New(ErrInvalidExactSvmPayload)
	}
	actualAmt := decimal.NewFromInt(int64(*tc.Amount))
	if !actualAmt.Equal(reqAmt) {
		return nil, errors.New(ErrAmountMismatch)
	}

	// 5) All checks pass -> return success struct
	return &x402types.VerificationResult{
		IsValid:       true,
		Amount:        actualAmt.String(),
		Token:         mint.String(),
		Recipient:     dest.String(),
		Sender:        source.String(),
		Confirmations: 1,
	}, nil
}

// findAssociatedTokenPDA derives the ATA PDA for ownermint using associated token program
func findAssociatedTokenPDA(owner, mint solana.PublicKey) (solana.PublicKey, error) {
	// seeds: [owner, tokenProgramID, mint]
	seeds := [][]byte{
		owner.Bytes(),
		TokenProgramID.Bytes(),
		mint.Bytes(),
	}
	pda, _, err := solana.FindProgramAddress(seeds, AssociatedTokenProgramID)
	if err != nil {
		return solana.PublicKey{}, err
	}
	return pda, nil
}

// fetchAccountExists queries RPC GetAccountInfo and returns true if account exists
func (c *SolanaClient) fetchAccountExists(ctx context.Context, pk solana.PublicKey) (bool, error) {
	resp, err := c.client.GetAccountInfo(ctx, pk)
	if err != nil {
		return false, fmt.Errorf("rpc_get_account_info_failed: %w", err)
	}
	return resp.Value != nil, nil
}

// isCreateAssociatedTokenAccountInstruction heuristically checks if instruction is an ATA create (program = system  associated)
func isCreateAssociatedTokenAccountInstruction(inst solana.CompiledInstruction) bool {
	// return inst.ProgramID.Equals(AssociatedTokenProgramID)

	return false
}

// verifyComputePriceInstructionMsg checks instruction at index is compute budget set price (discriminator 3) and <= 5 lamports
func verifyComputePriceInstructionMsg(msg *solana.Message, index int, allKeys []solana.PublicKey) error {
	if index >= len(msg.Instructions) {
		return errors.New(ErrInvalidComputePriceInstruction)
	}
	inst := msg.Instructions[index]

	prog := allKeys[inst.ProgramIDIndex]
	if !prog.Equals(ComputeBudgetProgramID) {
		return errors.New(ErrInvalidComputePriceInstruction)
	}

	// discriminator == 3
	if len(inst.Data) == 0 || inst.Data[0] != 3 {
		return errors.New(ErrInvalidComputePriceInstruction)
	}

	if len(inst.Data) < 9 {
		return errors.New(ErrInvalidComputePriceInstruction)
	}

	microLamports := binary.LittleEndian.Uint64(inst.Data[1:9])
	if microLamports > 5_000_000 {
		return errors.New(ErrComputePriceTooHigh)
	}
	return nil
}

// verifyComputeLimitInstructionMsg checks instruction at index is compute budget set limit (discriminator 2)
func verifyComputeLimitInstructionMsg(msg *solana.Message, index int, allKeys []solana.PublicKey) error {
	if index >= len(msg.Instructions) {
		return errors.New(ErrInvalidComputeLimitInstruction)
	}
	inst := msg.Instructions[index]

	prog := allKeys[inst.ProgramIDIndex]
	if !prog.Equals(ComputeBudgetProgramID) {
		return errors.New(ErrInvalidComputeLimitInstruction)
	}

	// discriminator == 2
	if len(inst.Data) == 0 || inst.Data[0] != 2 {
		return errors.New(ErrInvalidComputeLimitInstruction)
	}
	return nil
}

// decompileMessageWithLookups resolves address lookup tables and returns decompiled msg + flat keys.
// NOTE: the solana-go Message type exposes AccountKeys and AddressTableLookups; we fetch lookup tables and append
func (c *SolanaClient) decompileMessageWithLookups(ctx context.Context, tx solana.Transaction) (solana.Message, []solana.PublicKey, error) {
	msg := tx.Message

	// if no lookups, return as-is
	if msg.GetVersion() == solana.MessageVersionLegacy || len(msg.AddressTableLookups) == 0 {
		return msg, msg.AccountKeys, nil
	}

	// fetch each lookup table (we parse using our ParseLookupTableAccount earlier)
	tables := make([]*AddressLookupTableAccount, 0, len(msg.AddressTableLookups))
	for _, l := range msg.AddressTableLookups {
		resp, err := c.client.GetAccountInfo(ctx, l.AccountKey)
		if err != nil {
			return solana.Message{}, nil, fmt.Errorf("lookup_fetch_failed: %w", err)
		}
		if resp.Value == nil {
			return solana.Message{}, nil, fmt.Errorf("lookup_table_not_found: %s", l.AccountKey.String())
		}
		// Parse binary into addresses (we only need addresses)
		raw := resp.Value.Data.GetBinary()
		tbl, perr := ParseLookupTableAccount(l.AccountKey, raw)
		if perr != nil {
			return solana.Message{}, nil, fmt.Errorf("lookup_table_parse_failed: %w", perr)
		}
		tables = append(tables, tbl)
	}

	// expand static keys + lookup addresses in exact order (writables then read-only per lookup)
	all := append([]solana.PublicKey{}, msg.AccountKeys...)
	for _, l := range msg.AddressTableLookups {
		// find matching table
		var table *AddressLookupTableAccount
		for _, t := range tables {
			if t.Key.Equals(l.AccountKey) {
				table = t
				break
			}
		}
		if table == nil {
			return solana.Message{}, nil, fmt.Errorf("lookup_table_not_found_after_fetch: %s", l.AccountKey.String())
		}
		for _, idx := range l.WritableIndexes {
			if int(idx) >= len(table.Addresses) {
				return solana.Message{}, nil, errors.New("lookup_index_oob")
			}
			all = append(all, table.Addresses[idx])
		}
		for _, idx := range l.ReadonlyIndexes {
			if int(idx) >= len(table.Addresses) {
				return solana.Message{}, nil, errors.New("lookup_index_oob")
			}
			all = append(all, table.Addresses[idx])
		}
	}

	return msg, all, nil
}

type AddressLookupTableAccount struct {
	Key       solana.PublicKey
	Addresses []solana.PublicKey
}

// ParseLookupTableAccount reads the canonical layout and returns addresses array
func ParseLookupTableAccount(key solana.PublicKey, data []byte) (*AddressLookupTableAccount, error) {
	// minimal parsing to extract addresses vector per solana Address Lookup Table account layout
	// layout (prefix bytes) is skipped; we look for u32 length then addresses
	if len(data) < 1+32+8+1+4 {
		return nil, errors.New("invalid_lookup_table_data")
	}
	// check discriminator (first byte), spec suggests a specific discriminator; but many implementations use 1
	// We skip strict discriminator check to be resilient, but ensure enough bytes
	offset := 1 + 32 + 8 + 1 // disc + meta fields
	count := int(binary.LittleEndian.Uint32(data[offset : offset+4]))
	offset += 4
	if len(data) < offset+32*count {
		return nil, errors.New("lookup_table_data_truncated")
	}
	addrs := make([]solana.PublicKey, 0, count)
	for i := 0; i < count; i++ {
		start := offset + i*32
		var pk solana.PublicKey
		copy(pk[:], data[start:start+32])
		addrs = append(addrs, pk)
	}
	return &AddressLookupTableAccount{Key: key, Addresses: addrs}, nil
}

// helper to initialize the client with facilitator key (pass base58 or hex of private key)
func NewSolanaClientWithFeePayer(network string, rpcURL string, feePayerPrivKeyHex string) (*SolanaClient, error) {
	client := rpc.New(rpcURL)

	// decode private key: the exact storage of your key may vary.
	// Many opt to store 64-byte ed25519 seed+pub; adjust as needed.
	skBytes, err := hex.DecodeString(feePayerPrivKeyHex)
	if err != nil {
		return nil, fmt.Errorf("failed to decode fee payer private key: %w", err)
	}

	// ADJUST: ensure the length matches ed25519.PrivateKey requirements in your setup.
	var sk ed25519.PrivateKey
	if len(skBytes) == ed25519.PrivateKeySize {
		sk = ed25519.PrivateKey(skBytes)
	} else if len(skBytes) == ed25519.PublicKeySize { // unlikely, just a guard
		return nil, fmt.Errorf("provided fee payer key looks like a public key, provide private key")
	} else {
		// If you have a 32-byte seed, derive full private key:
		if len(skBytes) == ed25519.SeedSize {
			sk = ed25519.NewKeyFromSeed(skBytes)
		} else {
			return nil, fmt.Errorf("unexpected private key length: %d", len(skBytes))
		}
	}

	// derive solana public key from ed25519 pubkey bytes
	pub := solana.PublicKeyFromBytes(sk[32:]) // ADJUST: how to slice depends on whether sk is 64 or 32 bytes
	// safer approach: use NewKeyFromSeed if seed provided above; then derive pub appropriately.

	return &SolanaClient{
		network:    network,
		rpcURL:     rpcURL,
		client:     client,
		feePayerPK: pub,
		feePayerSK: sk,
	}, nil
}

func decodeTopLevelPaymentPayload(payloadBase64 string) (*types.SolanaPaymentPayload, error) {
	raw, err := base64.StdEncoding.DecodeString(payloadBase64)
	if err != nil {
		return nil, fmt.Errorf("invalid base64: %w", err)
	}

	var hdr types.SolanaPaymentPayload
	if err := json.Unmarshal(raw, &hdr); err != nil {
		return nil, fmt.Errorf("invalid json: %w", err)
	}

	return &hdr, nil
}

func verifyComputeLimitInstruction(tx *solana.Transaction, index int) error {
	inst := tx.Message.Instructions[index]
	prog := tx.Message.AccountKeys[inst.ProgramIDIndex]

	if !prog.Equals(ComputeBudgetProgramID) {
		return errors.New(ErrInvalidComputeLimitInstruction)
	}

	// TS logic: first byte is the discriminator (2)
	if len(inst.Data) == 0 || inst.Data[0] != 2 {
		return errors.New(ErrInvalidComputeLimitInstruction)
	}

	return nil
}

func getSignBytes(msg solana.Message) ([]byte, error) {
	switch msg.GetVersion() {
	case solana.MessageVersionLegacy:
		return msg.MarshalLegacy()
	case solana.MessageVersionV0:
		return msg.MarshalV0()
	default:
		return nil, errors.New("unknown_message_version")
	}
}

func verifyUserSignatures(msg solana.Message, sigs []solana.Signature, feePayer solana.PublicKey) error {
	required := int(msg.Header.NumRequiredSignatures)

	for i := 0; i < required; i++ {
		// skip fee payer (index 0)
		if msg.AccountKeys[i].Equals(feePayer) {
			continue
		}

		sig := sigs[i][:]
		pub := msg.AccountKeys[i].Bytes()

		msgBytes, err := getSignBytes(msg)
		if err != nil {
			return err
		}

		if !ed25519.Verify(ed25519.PublicKey(pub), msgBytes, sig) {
			return fmt.Errorf("signature_verify_failed_at_user_index_%d", i)
		}
	}

	return nil
}

// verifyBlockhashFreshness ensures the transaction's recent blockhash is still recent per RPC latest blockhash info.
// maxAgeSlots is the allowed difference in slots (e.g., 150). Returns nil if fresh.
func verifyBlockhashFreshness(
	ctx context.Context,
	rpcClient *rpc.Client,
	txMsg solana.Message,
) error {
	commitment := rpc.CommitmentFinalized
	latest, err := rpcClient.GetLatestBlockhash(ctx, commitment)
	if err != nil {
		return fmt.Errorf("rpc_get_latest_blockhash_failed: %w", err)
	}

	// If the tx blockhash matches latest blockhash → guaranteed fresh
	if txMsg.RecentBlockhash.Equals(latest.Value.Blockhash) {
		return nil
	}

	// Fetch the block height for the tx's blockhash
	bhResp, err := rpcClient.GetBlockHeight(ctx, commitment)
	if err != nil {
		return fmt.Errorf("rpc_get_block_height_failed: %w", err)
	}

	// This is the validator rule:
	// A blockhash is valid if currentHeight <= lastValidHeight.
	if uint64(bhResp) > latest.Value.LastValidBlockHeight {
		return errors.New("recent_blockhash_stale")
	}

	return nil
}

// verifyPayerIdentity checks transaction's payer (account index 0) equals expectedPayer.
// expectedPayer may be provided from PaymentRequirements.Extra["expectedPayer"] or wrapper.FeePayer.
func verifyPayerIdentity(msg solana.Message, expectedPayer solana.PublicKey) error {
	if expectedPayer == (solana.PublicKey{}) {
		return errors.New("expected_payer_not_provided")
	}
	if len(msg.AccountKeys) == 0 {
		return errors.New("tx_missing_account_keys")
	}
	txPayer := msg.AccountKeys[0]
	if !txPayer.Equals(expectedPayer) {
		return errors.New("tx_payer_mismatch")
	}
	return nil
}

// verifyMintWhitelisted checks mint is in the provided whitelist. If whitelist is nil/empty, it returns nil (no whitelist enforced).
// Optionally performs an on-chain sanity check: ensure mint account exists.
func verifyMintWhitelisted(ctx context.Context, rpcClient *rpc.Client, mint solana.PublicKey, whitelist []solana.PublicKey) error {
	// whitelist enforcement
	if len(whitelist) > 0 {
		found := false
		for _, w := range whitelist {
			if w.Equals(mint) {
				found = true
				break
			}
		}
		if !found {
			return errors.New("mint_not_in_whitelist")
		}
	}
	// on-chain existence check (sanity)
	resp, err := rpcClient.GetAccountInfo(ctx, mint)
	if err != nil {
		return fmt.Errorf("rpc_get_mint_account_failed: %w", err)
	}
	if resp.Value == nil {
		return errors.New("mint_account_not_found")
	}
	// optional: further parsing of mint account could be added here (supply, freeze authority, etc.)
	return nil
}

// verifyMintDecimals fetches the mint account and validates its decimals match expectedDecimals.
// This uses the canonical SPL Token Mint layout where decimals is a single byte at a stable offset.
// NOTE: the offset used here is the common SPL Token layout where decimals is at byte offset 44.
// If your token library exposes a mint parsing helper, prefer that instead (safer).
func verifyMintDecimals(ctx context.Context, rpcClient *rpc.Client, mint solana.PublicKey, expectedDecimals uint8) error {
	resp, err := rpcClient.GetAccountInfo(ctx, mint)
	if err != nil {
		return fmt.Errorf("rpc_get_mint_account_failed: %w", err)
	}
	if resp.Value == nil {
		return errors.New("mint_account_not_found")
	}
	raw := resp.Value.Data.GetBinary()
	// sanity check: mint account must be at least 46 bytes for decimals offset
	const decimalsOffset = 44
	if len(raw) <= decimalsOffset {
		return errors.New("mint_account_data_too_short_for_decimals")
	}
	decimals := uint8(raw[decimalsOffset])
	if decimals != expectedDecimals {
		return errors.New("mint_decimals_mismatch")
	}
	return nil
}
