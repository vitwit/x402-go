package clients

// import (
// 	"context"
// 	"crypto/ecdsa"
// 	"encoding/base64"
// 	"encoding/hex"
// 	"encoding/json"
// 	"fmt"
// 	"math/big"
// 	"strings"
// 	"time"

// 	"github.com/ethereum/go-ethereum"
// 	"github.com/ethereum/go-ethereum/accounts/abi"
// 	"github.com/ethereum/go-ethereum/common"
// 	"github.com/ethereum/go-ethereum/core/types"
// 	"github.com/ethereum/go-ethereum/crypto"
// 	"github.com/ethereum/go-ethereum/ethclient"
// 	x402types "github.com/vitwit/x402/types"
// )

// const (
// 	EIP3009_NAME    = "USD Coin"
// 	EIP3009_VERSION = "2"
// )

// // ----------------- EIP-3009 ABI -----------------
// const eip3009ABI = `[{
// 	"inputs":[
// 	  {"name":"from","type":"address"},
// 	  {"name":"to","type":"address"},
// 	  {"name":"value","type":"uint256"},
// 	  {"name":"validAfter","type":"uint256"},
// 	  {"name":"validBefore","type":"uint256"},
// 	  {"name":"nonce","type":"bytes32"},
// 	  {"name":"v","type":"uint8"},
// 	  {"name":"r","type":"bytes32"},
// 	  {"name":"s","type":"bytes32"}
// 	],
// 	"name":"transferWithAuthorization",
// 	"outputs":[],
// 	"stateMutability":"nonpayable",
// 	"type":"function"
// }]`

// // ----------------- Payload structs (Option A) -----------------
// type EthereumPaymentPayload struct {
// 	Version   int                 `json:"version"`
// 	ChainID   string              `json:"chainId"`
// 	Payment   EthereumPaymentData `json:"payment"`
// 	Signature string              `json:"signature,omitempty"`
// }

// type EthereumPaymentData struct {
// 	Amount      string               `json:"amount"`
// 	Token       string               `json:"token"`
// 	Payer       string               `json:"payer"`
// 	Recipient   string               `json:"recipient"`
// 	PaymentType string               `json:"paymentType"` // "eip3009"
// 	EIP3009Data *EIP3009TransferData `json:"eip3009Data,omitempty"`
// }

// type EIP3009TransferData struct {
// 	From        string `json:"from"`
// 	To          string `json:"to"`
// 	Value       string `json:"value"`
// 	ValidAfter  string `json:"validAfter"`
// 	ValidBefore string `json:"validBefore"`
// 	Nonce       string `json:"nonce"` // 0x..
// 	V           uint8  `json:"v"`
// 	R           string `json:"r"` // 0x..
// 	S           string `json:"s"` // 0x..
// }

// // ----------------- EthereumClient -----------------
// type EthereumClient struct {
// 	client        *ethclient.Client
// 	chainID       *big.Int
// 	acceptedToken string
// 	network       x402types.Network
// 	signer        *ecdsa.PrivateKey // optional; required for settlement broadcast
// }

// // NewEthereumClient creates a new client. signerPrivHex may be empty.
// func NewEthereumClient(rpcURL string, chainID *big.Int, acceptedToken string, network x402types.Network, signerPrivHex string) (*EthereumClient, error) {
// 	c, err := ethclient.Dial(rpcURL)
// 	if err != nil {
// 		return nil, fmt.Errorf("dial rpc: %w", err)
// 	}
// 	var signer *ecdsa.PrivateKey
// 	if signerPrivHex != "" {
// 		signer, err = crypto.HexToECDSA(signerPrivHex)
// 		if err != nil {
// 			c.Close()
// 			return nil, fmt.Errorf("invalid signer key: %w", err)
// 		}
// 	}
// 	return &EthereumClient{
// 		client:        c,
// 		chainID:       chainID,
// 		acceptedToken: acceptedToken,
// 		network:       network,
// 		signer:        signer,
// 	}, nil
// }

// func (e *EthereumClient) GetNetwork() x402types.Network { return e.network }
// func (e *EthereumClient) Close() {
// 	if e.client != nil {
// 		e.client.Close()
// 	}
// }

// // ----------------- VerifyPayment -----------------
// func (e *EthereumClient) VerifyPayment(ctx context.Context, payload *x402types.VerifyRequest) (*x402types.VerificationResult, error) {
// 	// basic checks
// 	if e.client == nil {
// 		return &x402types.VerificationResult{IsValid: false, InvalidReason: "rpc not initialized"}, nil
// 	}

// 	// decode header
// 	data, err := base64.StdEncoding.DecodeString(payload.PaymentHeader)
// 	if err != nil {
// 		return &x402types.VerificationResult{IsValid: false, InvalidReason: fmt.Sprintf("invalid base64 header: %v", err)}, nil
// 	}
// 	var header EthereumPaymentPayload
// 	if err := json.Unmarshal(data, &header); err != nil {
// 		return &x402types.VerificationResult{IsValid: false, InvalidReason: fmt.Sprintf("invalid header json: %v", err)}, nil
// 	}

// 	// ensure chain id matches
// 	currentChainID, err := e.client.ChainID(ctx)
// 	if err != nil {
// 		return &x402types.VerificationResult{IsValid: false, InvalidReason: fmt.Sprintf("chain id fetch failed: %v", err)}, nil
// 	}
// 	if header.ChainID != currentChainID.String() {
// 		return &x402types.VerificationResult{IsValid: false, InvalidReason: "chain id mismatch"}, nil
// 	}

// 	// route by type
// 	if header.Payment.PaymentType == "eip3009" {
// 		return e.verifyEIP3009Payment(ctx, &header, payload)
// 	} else {
// 		// fallback: not implemented here
// 		return &x402types.VerificationResult{IsValid: false, InvalidReason: "unsupported payment type"}, nil
// 	}
// }

// // verifyEIP3009Payment checks signature + validity window + recipient + amount
// func (e *EthereumClient) verifyEIP3009Payment(_ context.Context, header *EthereumPaymentPayload, payload *x402types.VerifyRequest) (*x402types.VerificationResult, error) {
// 	if header.Payment.EIP3009Data == nil {
// 		return &x402types.VerificationResult{IsValid: false, InvalidReason: "missing eip3009 data"}, nil
// 	}
// 	d := header.Payment.EIP3009Data

// 	// quick parse
// 	tokenAddr := common.HexToAddress(header.Payment.Token)
// 	from := common.HexToAddress(d.From)
// 	to := common.HexToAddress(d.To)
// 	expectedRecipient := common.HexToAddress(payload.PaymentRequirements.PayTo)

// 	if to.Hex() != expectedRecipient.Hex() {
// 		return &x402types.VerificationResult{IsValid: false, InvalidReason: "recipient mismatch"}, nil
// 	}

// 	// parse numeric fields
// 	value, ok := new(big.Int).SetString(d.Value, 10)
// 	if !ok {
// 		return &x402types.VerificationResult{IsValid: false, InvalidReason: "invalid value"}, nil
// 	}
// 	validAfter, _ := new(big.Int).SetString(d.ValidAfter, 10)
// 	validBefore, _ := new(big.Int).SetString(d.ValidBefore, 10)

// 	// parse nonce/r/s
// 	nonceBytes, err := hex.DecodeString(cleanHex(d.Nonce))
// 	if err != nil || len(nonceBytes) != 32 {
// 		return &x402types.VerificationResult{IsValid: false, InvalidReason: "invalid nonce"}, nil
// 	}
// 	var nonce [32]byte
// 	copy(nonce[:], nonceBytes)

// 	rBytes, err := hex.DecodeString(cleanHex(d.R))
// 	if err != nil || len(rBytes) != 32 {
// 		return &x402types.VerificationResult{IsValid: false, InvalidReason: "invalid r"}, nil
// 	}
// 	var r [32]byte
// 	copy(r[:], rBytes)

// 	sBytes, err := hex.DecodeString(cleanHex(d.S))
// 	if err != nil || len(sBytes) != 32 {
// 		return &x402types.VerificationResult{IsValid: false, InvalidReason: "invalid s"}, nil
// 	}
// 	var s [32]byte
// 	copy(s[:], sBytes)

// 	// check time window
// 	now := big.NewInt(time.Now().Unix())
// 	if validAfter.Cmp(big.NewInt(0)) > 0 && now.Cmp(validAfter) <= 0 {
// 		return &x402types.VerificationResult{IsValid: false, InvalidReason: "authorization not yet valid"}, nil
// 	}
// 	if validBefore.Cmp(big.NewInt(0)) > 0 && now.Cmp(validBefore) >= 0 {
// 		return &x402types.VerificationResult{IsValid: false, InvalidReason: "authorization expired"}, nil
// 	}

// 	// reconstruct digest
// 	var nonceArr [32]byte
// 	copy(nonceArr[:], nonce[:])
// 	digest := e.GetEIP3009Digest(tokenAddr, from, to, value, validAfter, validBefore, nonceArr)

// 	// recover signer
// 	// expected r|s|v with v as 0/1 for Ecrecover; our header stores v as 27/28 (likely) so convert
// 	v := d.V
// 	vAdj := byte(0)
// 	if v == 27 || v == 28 {
// 		vAdj = byte(v - 27)
// 	} else {
// 		// if already 0/1
// 		vAdj = byte(v)
// 	}
// 	sig := append(r[:], s[:]...)
// 	sig = append(sig, vAdj)

// 	pubBytes, err := crypto.Ecrecover(digest, sig)
// 	if err != nil {
// 		return &x402types.VerificationResult{IsValid: false, InvalidReason: fmt.Sprintf("ecrecover failed: %v", err)}, nil
// 	}
// 	pubKey, err := crypto.UnmarshalPubkey(pubBytes)
// 	if err != nil {
// 		return &x402types.VerificationResult{IsValid: false, InvalidReason: fmt.Sprintf("unmarshal pubkey failed: %v", err)}, nil
// 	}
// 	recovered := crypto.PubkeyToAddress(*pubKey)
// 	if recovered.Hex() != from.Hex() {
// 		return &x402types.VerificationResult{IsValid: false, InvalidReason: "signature signer mismatch"}, nil
// 	}

// 	// check amount threshold (assume token decimals = 6 for USDC)
// 	// payload.PaymentRequirements.MaxAmountRequired is in base units for our examples
// 	reqAmount := new(big.Int)
// 	_, ok = reqAmount.SetString(payload.PaymentRequirements.MaxAmountRequired, 10)
// 	if !ok || reqAmount == nil {
// 		return &x402types.VerificationResult{IsValid: false, InvalidReason: "invalid requirements amount"}, nil
// 	}
// 	if value.Cmp(reqAmount) < 0 {
// 		return &x402types.VerificationResult{IsValid: false, InvalidReason: "insufficient payment amount"}, nil
// 	}

// 	// Optionally simulate the call to ensure it would succeed on-chain
// 	parsedABI, err := abi.JSON(stringsNewReader(eip3009ABI))
// 	if err == nil {
// 		callData, err := parsedABI.Pack("transferWithAuthorization", from, to, value, validAfter, validBefore, nonceArr, d.V, r, s)
// 		if err == nil {
// 			msg := ethereum.CallMsg{To: &tokenAddr, Data: callData}
// 			if _, err := e.client.EstimateGas(context.Background(), msg); err != nil {
// 				// simulation failed — we still return invalid
// 				return &x402types.VerificationResult{IsValid: false, InvalidReason: fmt.Sprintf("simulation failed: %v", err)}, nil
// 			}
// 		}
// 	}

// 	// All good
// 	return &x402types.VerificationResult{
// 		IsValid:       true,
// 		InvalidReason: "",
// 		Amount:        nil,
// 		Token:         header.Payment.Token,
// 		Recipient:     to.Hex(),
// 		Sender:        from.Hex(),
// 		Confirmations: 0,
// 	}, nil
// }

// // ----------------- SettlePayment -----------------
// func (e *EthereumClient) SettlePayment(ctx context.Context, payload *x402types.VerifyRequest) (*x402types.SettlementResult, error) {
// 	if e.client == nil {
// 		return &x402types.SettlementResult{Success: false, Error: "rpc not initialized"}, nil
// 	}
// 	// decode header
// 	data, err := base64.StdEncoding.DecodeString(payload.PaymentHeader)
// 	if err != nil {
// 		return &x402types.SettlementResult{Success: false, Error: fmt.Sprintf("invalid base64 header: %v", err)}, nil
// 	}
// 	var header EthereumPaymentPayload
// 	if err := json.Unmarshal(data, &header); err != nil {
// 		return &x402types.SettlementResult{Success: false, Error: fmt.Sprintf("invalid header json: %v", err)}, nil
// 	}

// 	if header.Payment.PaymentType != "eip3009" {
// 		return &x402types.SettlementResult{Success: false, Error: "unsupported payment type for settlement"}, nil
// 	}
// 	if header.Payment.EIP3009Data == nil {
// 		return &x402types.SettlementResult{Success: false, Error: "missing eip3009 data"}, nil
// 	}

// 	// we require a signer configured on the client to broadcast
// 	if e.signer == nil {
// 		return &x402types.SettlementResult{Success: false, Error: "no signer configured on client"}, nil
// 	}

// 	eip := header.Payment.EIP3009Data
// 	tokenAddr := common.HexToAddress(header.Payment.Token)
// 	from := common.HexToAddress(eip.From)
// 	to := common.HexToAddress(eip.To)

// 	value, ok := new(big.Int).SetString(eip.Value, 10)
// 	if !ok {
// 		return &x402types.SettlementResult{Success: false, Error: "invalid value"}, nil
// 	}
// 	validAfter, _ := new(big.Int).SetString(eip.ValidAfter, 10)
// 	validBefore, _ := new(big.Int).SetString(eip.ValidBefore, 10)

// 	nonceBytes, err := hex.DecodeString(cleanHex(eip.Nonce))
// 	if err != nil || len(nonceBytes) != 32 {
// 		return &x402types.SettlementResult{Success: false, Error: "invalid nonce"}, nil
// 	}
// 	var nonceArr [32]byte
// 	copy(nonceArr[:], nonceBytes)

// 	rBytes, err := hex.DecodeString(cleanHex(eip.R))
// 	if err != nil || len(rBytes) != 32 {
// 		return &x402types.SettlementResult{Success: false, Error: "invalid r"}, nil
// 	}
// 	var rArr [32]byte
// 	copy(rArr[:], rBytes)

// 	sBytes, err := hex.DecodeString(cleanHex(eip.S))
// 	if err != nil || len(sBytes) != 32 {
// 		return &x402types.SettlementResult{Success: false, Error: "invalid s"}, nil
// 	}
// 	var sArr [32]byte
// 	copy(sArr[:], sBytes)

// 	parsedABI, err := abi.JSON(stringsNewReader(eip3009ABI))
// 	if err != nil {
// 		return &x402types.SettlementResult{Success: false, Error: fmt.Sprintf("parse abi failed: %v", err)}, nil
// 	}

// 	callData, err := parsedABI.Pack("transferWithAuthorization", from, to, value, validAfter, validBefore, nonceArr, eip.V, rArr, sArr)
// 	if err != nil {
// 		return &x402types.SettlementResult{Success: false, Error: fmt.Sprintf("pack call data failed: %v", err)}, nil
// 	}

// 	// prepare tx params
// 	signerAddr := crypto.PubkeyToAddress(e.signer.PublicKey)

// 	gasLimit, err := e.client.EstimateGas(ctx, ethereum.CallMsg{From: signerAddr, To: &tokenAddr, Data: callData})
// 	if err != nil {
// 		return &x402types.SettlementResult{Success: false, Error: fmt.Sprintf("estimate gas failed: %v", err)}, nil
// 	}

// 	gasPrice, err := e.client.SuggestGasPrice(ctx)
// 	if err != nil {
// 		return &x402types.SettlementResult{Success: false, Error: fmt.Sprintf("suggest gas price failed: %v", err)}, nil
// 	}

// 	nonceAccount, err := e.client.PendingNonceAt(ctx, signerAddr)
// 	if err != nil {
// 		return &x402types.SettlementResult{Success: false, Error: fmt.Sprintf("pending nonce failed: %v", err)}, nil
// 	}

// 	tx := types.NewTransaction(nonceAccount, tokenAddr, big.NewInt(0), gasLimit, gasPrice, callData)

// 	signed, err := types.SignTx(tx, types.NewEIP155Signer(e.chainID), e.signer)
// 	if err != nil {
// 		return &x402types.SettlementResult{Success: false, Error: fmt.Sprintf("sign tx failed: %v", err)}, nil
// 	}

// 	if err := e.client.SendTransaction(ctx, signed); err != nil {
// 		return &x402types.SettlementResult{Success: false, Error: fmt.Sprintf("send tx failed: %v", err)}, nil
// 	}

// 	return &x402types.SettlementResult{
// 		Success:   true,
// 		TxHash:    signed.Hash().Hex(),
// 		NetworkId: e.network.String(),
// 	}, nil
// }

// // ----------------- EIP-3009 digest generator -----------------
// func (e *EthereumClient) GetEIP3009Digest(token, from, to common.Address, value, validAfter, validBefore *big.Int, nonce [32]byte) []byte {
// 	// domain separator
// 	domainTypeHash := crypto.Keccak256([]byte("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"))
// 	nameHash := crypto.Keccak256([]byte(EIP3009_NAME))
// 	versionHash := crypto.Keccak256([]byte(EIP3009_VERSION))
// 	chainIDPadded := common.LeftPadBytes(e.chainID.Bytes(), 32)
// 	verifyingContractPadded := common.LeftPadBytes(token.Bytes(), 32)

// 	domainSeparator := crypto.Keccak256Hash(domainTypeHash, nameHash, versionHash, chainIDPadded, verifyingContractPadded)

// 	// type hash
// 	typeHash := crypto.Keccak256([]byte("TransferWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)"))

// 	structHash := crypto.Keccak256Hash(
// 		typeHash,
// 		common.LeftPadBytes(from.Bytes(), 32),
// 		common.LeftPadBytes(to.Bytes(), 32),
// 		common.LeftPadBytes(value.Bytes(), 32),
// 		common.LeftPadBytes(validAfter.Bytes(), 32),
// 		common.LeftPadBytes(validBefore.Bytes(), 32),
// 		nonce[:],
// 	)

// 	// final digest = keccak256("\x19\x01" || domainSeparator || structHash)
// 	digestInput := append([]byte("\x19\x01"), append(domainSeparator.Bytes(), structHash.Bytes()...)...)
// 	digest := crypto.Keccak256(digestInput)
// 	return digest
// }

// // ----------------- Helpers -----------------
// func cleanHex(s string) string {
// 	if len(s) >= 2 && s[0:2] == "0x" {
// 		return s[2:]
// 	}
// 	return s
// }

// // small wrapper because we can't call strings.NewReader directly in a few spots (keeps readability)
// func stringsNewReader(s string) *strings.Reader {
// 	return strings.NewReader(s)
// }
