package clients

const (
	// -----------------------------
	// SCHEME / NETWORK
	// -----------------------------
	ErrUnsupportedScheme = "unsupported_scheme"
	ErrInvalidNetwork    = "invalid_network"

	// -----------------------------
	// GENERIC PAYLOAD
	// -----------------------------
	ErrInvalidExactSvmPayload = "invalid_exact_svm_payload_transaction"

	// -----------------------------
	// TRANSACTION STRUCTURE
	// -----------------------------
	ErrInvalidInstructionsLength      = "invalid_exact_svm_payload_transaction_instructions_length"
	ErrInvalidComputeLimitInstruction = "invalid_exact_svm_payload_transaction_instructions_compute_limit_instruction"
	ErrInvalidComputePriceInstruction = "invalid_exact_svm_payload_transaction_instructions_compute_price_instruction"
	ErrComputePriceTooHigh            = "invalid_exact_svm_payload_transaction_instructions_compute_price_instruction_too_high"

	// -----------------------------
	// FEE PAYER SAFETY
	// -----------------------------
	ErrFeePayerIncludedInInstructionAccounts = "invalid_exact_svm_payload_transaction_fee_payer_included_in_instruction_accounts"
	ErrFeePayerTransferringFunds             = "invalid_exact_svm_payload_transaction_fee_payer_transferring_funds"

	// -----------------------------
	// TRANSFER CHECKS
	// -----------------------------
	ErrTransferToIncorrectATA = "invalid_exact_svm_payload_transaction_transfer_to_incorrect_ata"
	ErrSenderATANotFound      = "invalid_exact_svm_payload_transaction_sender_ata_not_found"
	ErrReceiverATANotFound    = "invalid_exact_svm_payload_transaction_receiver_ata_not_found"
	ErrAmountMismatch         = "invalid_exact_svm_payload_transaction_amount_mismatch"

	// -----------------------------
	// TRANSFER PARSING ERRORS
	// -----------------------------
	ErrNotATransferInstruction        = "invalid_exact_svm_payload_transaction_not_a_transfer_instruction"
	ErrNotATransferCheckedInstruction = "invalid_exact_svm_payload_transaction_instruction_not_transfer_checked"

	// -----------------------------
	// UNEXPECTED
	// -----------------------------
	ErrUnexpectedVerifyError = "unexpected_verify_error"

	// -----------------------------
	// SETTLEMENT ERRORS
	// -----------------------------
	ErrTransactionSignerMissingSignatures    = "transaction_signer_missing_signatures"
	ErrSettleBlockHeightExceeded             = "settle_exact_svm_block_height_exceeded"
	ErrSettleTransactionConfirmationTimedOut = "settle_exact_svm_transaction_confirmation_timed_out"
	ErrUnexpectedSettleError                 = "unexpected_settle_error"
)
