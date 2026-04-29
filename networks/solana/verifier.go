package solana

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"

	bin "github.com/gagliardetto/binary"
	solanago "github.com/gagliardetto/solana-go"
	"github.com/gagliardetto/solana-go/programs/token"
	"github.com/gagliardetto/solana-go/rpc"
	"github.com/vitwit/x402-go"
)

// Verifier verifies Solana SPL token payment transactions.
type Verifier struct {
	networks     []string
	rpcEndpoints map[string]string
}

func NewVerifier(networks []string, rpcEndpoints map[string]string) *Verifier {
	if networks == nil {
		networks = DefaultNetworks()
	}
	if rpcEndpoints == nil {
		rpcEndpoints = make(map[string]string)
		for _, n := range networks {
			rpcEndpoints[n] = RPCFromNetwork(n)
		}
	}
	return &Verifier{networks: networks, rpcEndpoints: rpcEndpoints}
}

func (v *Verifier) Networks() []string { return v.networks }
func (v *Verifier) Schemes() []x402.Scheme {
	return []x402.Scheme{x402.SchemeExact, x402.SchemeUpto}
}

func (v *Verifier) Verify(ctx context.Context, req x402.VerifyRequest) (x402.VerifyResult, error) {
	var solPayload x402.SolanaPayload
	if err := json.Unmarshal(req.PaymentPayload.Payload, &solPayload); err != nil {
		return x402.VerifyResult{}, fmt.Errorf("unmarshal solana payload: %w", err)
	}

	txBytes, err := base64.StdEncoding.DecodeString(solPayload.Transaction)
	if err != nil {
		return x402.VerifyResult{Error: ErrInvalidExactSvmPayload}, nil
	}

	tx, err := solanago.TransactionFromDecoder(bin.NewBinDecoder(txBytes))
	if err != nil {
		return x402.VerifyResult{Error: ErrInvalidExactSvmPayload}, nil
	}

	rpcURL := v.rpcEndpoints[req.PaymentPayload.Accepted.Network]
	if rpcURL == "" {
		rpcURL = RPCFromNetwork(req.PaymentPayload.Accepted.Network)
	}
	if rpcURL == "" {
		return x402.VerifyResult{}, fmt.Errorf("no RPC endpoint for %s", req.PaymentPayload.Accepted.Network)
	}
	rpcClient := rpc.New(rpcURL)

	msg, allKeys, err := decompileMessageWithLookups(ctx, rpcClient, *tx)
	if err != nil {
		return x402.VerifyResult{Error: ErrInvalidExactSvmPayload}, nil
	}

	if err := verifyBlockhashFreshness(ctx, rpcClient, msg); err != nil {
		return x402.VerifyResult{Error: err.Error()}, nil
	}

	// Parse extra fields (feePayer from server, memo requirement).
	var extra struct {
		FeePayer string `json:"feePayer"`
		Memo     string `json:"memo"`
	}
	if len(req.PaymentOption.Extra) > 0 {
		_ = json.Unmarshal(req.PaymentOption.Extra, &extra)
	}

	// Instruction layout per spec (section "Instruction layout"):
	//   0: ComputeBudget SetLimit
	//   1: ComputeBudget SetPrice
	//   2: (optional) AssociatedTokenProgram CreateATA  — extension beyond spec, kept for wallet compat
	//   next: SPL Token or Token-2022 TransferChecked
	//   remaining: each MUST be Lighthouse or SPL Memo
	n := len(msg.Instructions)
	if n < 3 {
		return x402.VerifyResult{Error: ErrInvalidInstructionsLength}, nil
	}
	if err := verifyComputeLimitInstruction(&msg, 0, allKeys); err != nil {
		return x402.VerifyResult{Error: err.Error()}, nil
	}
	if err := verifyComputePriceInstruction(&msg, 1, allKeys); err != nil {
		return x402.VerifyResult{Error: err.Error()}, nil
	}

	createATAExists := false
	transferIdx := 2
	if n > 2 && isCreateATAInstruction(msg.Instructions[2], allKeys) {
		createATAExists = true
		transferIdx = 3
	}

	if transferIdx >= n {
		return x402.VerifyResult{Error: ErrInvalidInstructionsLength}, nil
	}

	// Fee payer must not appear in any instruction's accounts.
	feePayer := msg.AccountKeys[0]
	if err := verifyPayerNotInInstructions(msg, allKeys, feePayer); err != nil {
		return x402.VerifyResult{Error: err.Error()}, nil
	}

	// Verify user (non-feepayer) signatures.
	msgBytes, err := getSignBytes(msg)
	if err != nil {
		return x402.VerifyResult{Error: err.Error()}, nil
	}
	if err := verifyUserSignatures(msg, tx.Signatures, feePayer, msgBytes); err != nil {
		return x402.VerifyResult{Error: err.Error()}, nil
	}

	// Validate optional instructions after transferIdx (must be Lighthouse or Memo).
	memoCount := 0
	var memoData string
	for i := transferIdx + 1; i < n; i++ {
		prog := allKeys[msg.Instructions[i].ProgramIDIndex]
		switch {
		case prog.Equals(LighthouseProgramID):
			// allowed, no-op
		case prog.Equals(MemoProgramID):
			memoCount++
			memoData = string(msg.Instructions[i].Data)
		default:
			return x402.VerifyResult{Error: ErrUnknownOptionalInstruction}, nil
		}
	}

	// If extra.memo is set, exactly one Memo instruction must exist and match.
	if extra.Memo != "" {
		if memoCount == 0 {
			return x402.VerifyResult{Error: ErrMemoMissing}, nil
		}
		if memoCount > 1 {
			return x402.VerifyResult{Error: ErrMemoTooMany}, nil
		}
		if memoData != extra.Memo {
			return x402.VerifyResult{Error: ErrMemoMismatch}, nil
		}
	}

	// Validate the SPL / Token-2022 TransferChecked instruction.
	vr, err := validateSPLTransferChecked(
		ctx, rpcClient, msg, allKeys, transferIdx, createATAExists,
		req.PaymentOption,
	)
	if err != nil {
		return x402.VerifyResult{Error: err.Error()}, nil
	}

	return *vr, nil
}

// validateSPLTransferChecked parses the transfer instruction and validates all fields.
func validateSPLTransferChecked(
	ctx context.Context,
	rpcClient *rpc.Client,
	msg solanago.Message,
	allKeys []solanago.PublicKey,
	transferIdx int,
	createATAExists bool,
	opt x402.PaymentOption,
) (*x402.VerifyResult, error) {
	inst := msg.Instructions[transferIdx]

	// Accept SPL Token or Token-2022 for the TransferChecked instruction.
	progID := allKeys[inst.ProgramIDIndex]
	if !progID.Equals(SPLTokenProgramID) && !progID.Equals(Token2022ProgramID) {
		return nil, errors.New(ErrNotATransferInstruction)
	}

	metas := make([]*solanago.AccountMeta, len(inst.Accounts))
	for i, ai := range inst.Accounts {
		pk := allKeys[ai]
		writable, _ := msg.IsWritable(pk)
		metas[i] = &solanago.AccountMeta{
			PublicKey:  pk,
			IsSigner:   msg.IsSigner(pk),
			IsWritable: writable,
		}
	}

	splInst, err := token.DecodeInstruction(metas, inst.Data)
	if err != nil {
		return nil, errors.New(ErrNotATransferInstruction)
	}
	tc, ok := splInst.Impl.(*token.TransferChecked)
	if !ok {
		return nil, errors.New(ErrNotATransferCheckedInstruction)
	}

	if len(inst.Accounts) < 4 {
		return nil, errors.New(ErrNotATransferInstruction)
	}
	source := allKeys[inst.Accounts[0]]
	mint := allKeys[inst.Accounts[1]]
	dest := allKeys[inst.Accounts[2]]
	authority := allKeys[inst.Accounts[3]]

	feePayer := msg.AccountKeys[0]
	if authority.Equals(feePayer) || source.Equals(feePayer) {
		return nil, errors.New(ErrFeePayerTransferringFunds)
	}

	// Derive expected ATA for (owner=payTo, mint=asset).
	mintPk, err := solanago.PublicKeyFromBase58(opt.Asset)
	if err != nil {
		return nil, errors.New(ErrInvalidExactSvmPayload)
	}
	ownerPk, err := solanago.PublicKeyFromBase58(opt.PayTo)
	if err != nil {
		return nil, errors.New(ErrInvalidExactSvmPayload)
	}

	expectedATA, _, err := solanago.FindAssociatedTokenAddress(ownerPk, mintPk)
	if err != nil {
		return nil, fmt.Errorf("ata_derivation_failed: %w", err)
	}
	if !dest.Equals(expectedATA) {
		return nil, errors.New(ErrTransferToIncorrectATA)
	}

	if !mint.Equals(mintPk) {
		return nil, errors.New(ErrInvalidExactSvmPayload)
	}

	// Source ATA must exist.
	if ok, _ := accountExists(ctx, rpcClient, source); !ok {
		return nil, errors.New(ErrSenderATANotFound)
	}
	// Destination ATA must exist unless a CreateATA instruction is present.
	if !createATAExists {
		if ok, _ := accountExists(ctx, rpcClient, dest); !ok {
			return nil, errors.New(ErrReceiverATANotFound)
		}
	}

	if tc.Amount == nil {
		return nil, errors.New(ErrNotATransferInstruction)
	}
	actual := new(big.Int).SetUint64(*tc.Amount)
	required, ok := new(big.Int).SetString(opt.Amount, 10)
	if !ok {
		return nil, fmt.Errorf("invalid amount")
	}

	// For the exact scheme, the transferred amount must match precisely.
	// For upto, it must be at least the required amount.
	if opt.Scheme == x402.SchemeExact {
		if actual.Cmp(required) != 0 {
			return nil, errors.New(ErrAmountMismatch)
		}
	} else {
		if actual.Cmp(required) < 0 {
			return nil, errors.New(ErrAmountMismatch)
		}
	}

	return &x402.VerifyResult{
		Valid: true,
		Payer: source.String(),
	}, nil
}

// --- helpers ---

func decompileMessageWithLookups(ctx context.Context, rpcClient *rpc.Client, tx solanago.Transaction) (solanago.Message, []solanago.PublicKey, error) {
	msg := tx.Message
	if msg.GetVersion() == solanago.MessageVersionLegacy || len(msg.AddressTableLookups) == 0 {
		return msg, msg.AccountKeys, nil
	}

	tables := make([]*addressLookupTable, 0, len(msg.AddressTableLookups))
	for _, l := range msg.AddressTableLookups {
		resp, err := rpcClient.GetAccountInfo(ctx, l.AccountKey)
		if err != nil || resp.Value == nil {
			return solanago.Message{}, nil, fmt.Errorf("lookup_table_fetch_failed: %s", l.AccountKey)
		}
		tbl, err := parseLookupTableAccount(l.AccountKey, resp.Value.Data.GetBinary())
		if err != nil {
			return solanago.Message{}, nil, fmt.Errorf("lookup_table_parse_failed: %w", err)
		}
		tables = append(tables, tbl)
	}

	all := append([]solanago.PublicKey{}, msg.AccountKeys...)
	for _, l := range msg.AddressTableLookups {
		var table *addressLookupTable
		for _, t := range tables {
			if t.key.Equals(l.AccountKey) {
				table = t
				break
			}
		}
		if table == nil {
			return solanago.Message{}, nil, fmt.Errorf("lookup_table_not_found: %s", l.AccountKey)
		}
		for _, idx := range l.WritableIndexes {
			if int(idx) >= len(table.addresses) {
				return solanago.Message{}, nil, errors.New("lookup_index_oob")
			}
			all = append(all, table.addresses[idx])
		}
		for _, idx := range l.ReadonlyIndexes {
			if int(idx) >= len(table.addresses) {
				return solanago.Message{}, nil, errors.New("lookup_index_oob")
			}
			all = append(all, table.addresses[idx])
		}
	}
	return msg, all, nil
}

type addressLookupTable struct {
	key       solanago.PublicKey
	addresses []solanago.PublicKey
}

func parseLookupTableAccount(key solanago.PublicKey, data []byte) (*addressLookupTable, error) {
	const minLen = 1 + 32 + 8 + 1 + 4
	if len(data) < minLen {
		return nil, errors.New("invalid_lookup_table_data")
	}
	offset := 1 + 32 + 8 + 1
	count := int(binary.LittleEndian.Uint32(data[offset : offset+4]))
	offset += 4
	if len(data) < offset+32*count {
		return nil, errors.New("lookup_table_data_truncated")
	}
	addrs := make([]solanago.PublicKey, count)
	for i := 0; i < count; i++ {
		copy(addrs[i][:], data[offset+i*32:offset+i*32+32])
	}
	return &addressLookupTable{key: key, addresses: addrs}, nil
}

func verifyBlockhashFreshness(ctx context.Context, rpcClient *rpc.Client, msg solanago.Message) error {
	latest, err := rpcClient.GetLatestBlockhash(ctx, rpc.CommitmentFinalized)
	if err != nil {
		return fmt.Errorf("rpc_get_latest_blockhash_failed: %w", err)
	}
	if msg.RecentBlockhash.Equals(latest.Value.Blockhash) {
		return nil
	}
	currentHeight, err := rpcClient.GetBlockHeight(ctx, rpc.CommitmentFinalized)
	if err != nil {
		return fmt.Errorf("rpc_get_block_height_failed: %w", err)
	}
	if currentHeight > latest.Value.LastValidBlockHeight {
		return errors.New("recent_blockhash_stale")
	}
	return nil
}

func verifyComputeLimitInstruction(msg *solanago.Message, index int, allKeys []solanago.PublicKey) error {
	if index >= len(msg.Instructions) {
		return errors.New(ErrInvalidComputeLimitInstruction)
	}
	inst := msg.Instructions[index]
	if !allKeys[inst.ProgramIDIndex].Equals(ComputeBudgetProgramID) {
		return errors.New(ErrInvalidComputeLimitInstruction)
	}
	if len(inst.Data) == 0 || inst.Data[0] != 2 {
		return errors.New(ErrInvalidComputeLimitInstruction)
	}
	return nil
}

func verifyComputePriceInstruction(msg *solanago.Message, index int, allKeys []solanago.PublicKey) error {
	if index >= len(msg.Instructions) {
		return errors.New(ErrInvalidComputePriceInstruction)
	}
	inst := msg.Instructions[index]
	if !allKeys[inst.ProgramIDIndex].Equals(ComputeBudgetProgramID) {
		return errors.New(ErrInvalidComputePriceInstruction)
	}
	if len(inst.Data) == 0 || inst.Data[0] != 3 {
		return errors.New(ErrInvalidComputePriceInstruction)
	}
	// Spec: compute unit price MUST be ≤ 5 lamports = 5,000,000 micro-lamports per CU.
	if len(inst.Data) >= 9 {
		microLamports := binary.LittleEndian.Uint64(inst.Data[1:9])
		if microLamports > 5_000_000 {
			return errors.New(ErrComputePriceTooHigh)
		}
	}
	return nil
}

func isCreateATAInstruction(inst solanago.CompiledInstruction, allKeys []solanago.PublicKey) bool {
	return allKeys[inst.ProgramIDIndex].Equals(AssociatedTokenProgramID)
}

func verifyPayerNotInInstructions(msg solanago.Message, allKeys []solanago.PublicKey, feePayer solanago.PublicKey) error {
	for _, inst := range msg.Instructions {
		for _, ai := range inst.Accounts {
			if allKeys[ai].Equals(feePayer) {
				return errors.New(ErrFeePayerIncludedInInstructionAccounts)
			}
		}
	}
	return nil
}

func verifyUserSignatures(msg solanago.Message, sigs []solanago.Signature, feePayer solanago.PublicKey, msgBytes []byte) error {
	required := int(msg.Header.NumRequiredSignatures)
	for i := 0; i < required; i++ {
		if msg.AccountKeys[i].Equals(feePayer) {
			continue // fee payer slot — to be filled by facilitator
		}
		sig := sigs[i][:]
		pub := ed25519.PublicKey(msg.AccountKeys[i].Bytes())
		if !ed25519.Verify(pub, msgBytes, sig) {
			return fmt.Errorf("signature_verify_failed_at_user_index_%d", i)
		}
	}
	return nil
}

func getSignBytes(msg solanago.Message) ([]byte, error) {
	switch msg.GetVersion() {
	case solanago.MessageVersionLegacy:
		return msg.MarshalLegacy()
	case solanago.MessageVersionV0:
		return msg.MarshalV0()
	default:
		return nil, errors.New("unknown_message_version")
	}
}

func accountExists(ctx context.Context, rpcClient *rpc.Client, pk solanago.PublicKey) (bool, error) {
	resp, err := rpcClient.GetAccountInfo(ctx, pk)
	if err != nil {
		return false, err
	}
	return resp.Value != nil, nil
}
