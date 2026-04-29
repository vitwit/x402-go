package solana

import solanago "github.com/gagliardetto/solana-go"

// Well-known Solana program IDs.
var (
	ComputeBudgetProgramID   = solanago.MustPublicKeyFromBase58("ComputeBudget111111111111111111111111111111")
	AssociatedTokenProgramID = solanago.MustPublicKeyFromBase58("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL")
	SPLTokenProgramID        = solanago.MustPublicKeyFromBase58("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA")
	Token2022ProgramID       = solanago.MustPublicKeyFromBase58("TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb")
	// LighthouseProgramID is injected by Phantom wallet as a user protection mechanism.
	LighthouseProgramID = solanago.MustPublicKeyFromBase58("L2TExMFKdjpN9kozasaurPirfHy9P8sbXoAN1qA3S95")
	// MemoProgramID is the SPL Memo program, used for transaction uniqueness and payment references.
	MemoProgramID = solanago.MustPublicKeyFromBase58("MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr")
)

// Error sentinel strings — match the x402 spec error identifiers.
const (
	ErrUnsupportedScheme = "unsupported_scheme"

	ErrInvalidExactSvmPayload = "invalid_exact_svm_payload_transaction"

	ErrInvalidInstructionsLength      = "invalid_exact_svm_payload_transaction_instructions_length"
	ErrInvalidComputeLimitInstruction = "invalid_exact_svm_payload_transaction_instructions_compute_limit_instruction"
	ErrInvalidComputePriceInstruction = "invalid_exact_svm_payload_transaction_instructions_compute_price_instruction"
	ErrComputePriceTooHigh            = "invalid_exact_svm_payload_transaction_instructions_compute_price_instruction_too_high"

	ErrFeePayerIncludedInInstructionAccounts = "invalid_exact_svm_payload_transaction_fee_payer_included_in_instruction_accounts"
	ErrFeePayerTransferringFunds             = "invalid_exact_svm_payload_transaction_fee_payer_transferring_funds"

	ErrTransferToIncorrectATA = "invalid_exact_svm_payload_transaction_transfer_to_incorrect_ata"
	ErrSenderATANotFound      = "invalid_exact_svm_payload_transaction_sender_ata_not_found"
	ErrReceiverATANotFound    = "invalid_exact_svm_payload_transaction_receiver_ata_not_found"
	ErrAmountMismatch         = "invalid_exact_svm_payload_transaction_amount_mismatch"

	ErrNotATransferInstruction        = "invalid_exact_svm_payload_transaction_not_a_transfer_instruction"
	ErrNotATransferCheckedInstruction = "invalid_exact_svm_payload_transaction_instruction_not_transfer_checked"

	ErrMemoMissing  = "invalid_exact_svm_payload_transaction_memo_missing"
	ErrMemoMismatch = "invalid_exact_svm_payload_transaction_memo_mismatch"
	ErrMemoTooMany  = "invalid_exact_svm_payload_transaction_memo_too_many"

	ErrUnknownOptionalInstruction = "invalid_exact_svm_payload_transaction_unknown_optional_instruction"
)
