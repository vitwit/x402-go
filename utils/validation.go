package utils

import (
	"encoding/json"
	"fmt"
	"math/big"
	"regexp"
	"strings"
	"time"

	"github.com/shopspring/decimal"
)

// ValidateJSON validates that a string is valid JSON
func ValidateJSON(data string) error {
	var js json.RawMessage
	return json.Unmarshal([]byte(data), &js)
}

// ValidateAmount checks if an amount string is a valid decimal
func ValidateAmount(amount string) (*decimal.Decimal, error) {
	if amount == "" {
		return nil, fmt.Errorf("amount cannot be empty")
	}
	
	dec, err := decimal.NewFromString(amount)
	if err != nil {
		return nil, fmt.Errorf("invalid amount format: %w", err)
	}
	
	if dec.IsNegative() {
		return nil, fmt.Errorf("amount cannot be negative")
	}
	
	return &dec, nil
}

// ValidateBigInt checks if a string is a valid big integer
func ValidateBigInt(value string) (*big.Int, error) {
	if value == "" {
		return nil, fmt.Errorf("value cannot be empty")
	}
	
	bigInt := new(big.Int)
	_, success := bigInt.SetString(value, 10)
	if !success {
		return nil, fmt.Errorf("invalid big integer format")
	}
	
	return bigInt, nil
}

// ValidateTransactionHash validates different types of transaction hashes
func ValidateTransactionHash(hash string, network string) error {
	if hash == "" {
		return fmt.Errorf("transaction hash cannot be empty")
	}
	
	switch {
	case strings.Contains(network, "ethereum") || strings.Contains(network, "polygon") || strings.Contains(network, "base"):
		// EVM transaction hash - 66 characters (0x + 64 hex)
		if !strings.HasPrefix(hash, "0x") {
			return fmt.Errorf("EVM transaction hash must start with 0x")
		}
		if len(hash) != 66 {
			return fmt.Errorf("EVM transaction hash must be 66 characters long")
		}
		if !isHexString(hash[2:]) {
			return fmt.Errorf("EVM transaction hash must be valid hex")
		}
		
	case strings.Contains(network, "solana"):
		// Solana transaction signature - base58 encoded, typically 87-88 characters
		if len(hash) < 80 || len(hash) > 90 {
			return fmt.Errorf("Solana transaction signature has invalid length")
		}
		if !isBase58String(hash) {
			return fmt.Errorf("Solana transaction signature must be valid base58")
		}
		
	case strings.Contains(network, "cosmos"):
		// Cosmos transaction hash - uppercase hex, typically 64 characters
		if len(hash) != 64 {
			return fmt.Errorf("Cosmos transaction hash must be 64 characters long")
		}
		if !isHexString(hash) {
			return fmt.Errorf("Cosmos transaction hash must be valid hex")
		}
		
	default:
		return fmt.Errorf("unsupported network for transaction hash validation")
	}
	
	return nil
}

// ValidateAddress validates addresses for different networks
func ValidateAddressForNetwork(address string, network string) error {
	if address == "" {
		return fmt.Errorf("address cannot be empty")
	}
	
	switch {
	case strings.Contains(network, "ethereum") || strings.Contains(network, "polygon") || strings.Contains(network, "base"):
		// Ethereum address validation
		if !strings.HasPrefix(address, "0x") {
			return fmt.Errorf("Ethereum address must start with 0x")
		}
		if len(address) != 42 {
			return fmt.Errorf("Ethereum address must be 42 characters long")
		}
		if !isHexString(address[2:]) {
			return fmt.Errorf("Ethereum address must be valid hex")
		}
		
	case strings.Contains(network, "solana"):
		// Solana address validation - base58, typically 32-44 characters
		if len(address) < 32 || len(address) > 44 {
			return fmt.Errorf("Solana address has invalid length")
		}
		if !isBase58String(address) {
			return fmt.Errorf("Solana address must be valid base58")
		}
		
	case strings.Contains(network, "cosmos"):
		// Cosmos address validation - bech32 format
		if !strings.HasPrefix(address, "cosmos") && !strings.HasPrefix(address, "osmo") {
			return fmt.Errorf("Cosmos address must start with valid prefix")
		}
		if len(address) < 39 || len(address) > 45 {
			return fmt.Errorf("Cosmos address has invalid length")
		}
		
	default:
		return fmt.Errorf("unsupported network for address validation")
	}
	
	return nil
}

// ValidateTokenAddress validates token contract addresses
func ValidateTokenAddress(address string, network string) error {
	if address == "" {
		// Native tokens don't have addresses
		return nil
	}
	
	return ValidateAddressForNetwork(address, network)
}

// ValidateTimestamp ensures a timestamp is reasonable (not too far in past/future)
func ValidateTimestamp(timestamp time.Time) error {
	now := time.Now()
	
	// Check if timestamp is too far in the past (more than 1 hour)
	if timestamp.Before(now.Add(-1 * time.Hour)) {
		return fmt.Errorf("timestamp is too far in the past")
	}
	
	// Check if timestamp is too far in the future (more than 10 minutes)
	if timestamp.After(now.Add(10 * time.Minute)) {
		return fmt.Errorf("timestamp is too far in the future")
	}
	
	return nil
}

// ValidateDeadline ensures a deadline is in the future
func ValidateDeadline(deadline time.Time) error {
	if deadline.Before(time.Now()) {
		return fmt.Errorf("deadline must be in the future")
	}
	
	return nil
}

// Helper function to check if a string is valid hexadecimal
func isHexString(s string) bool {
	match, _ := regexp.MatchString("^[0-9a-fA-F]+$", s)
	return match
}

// Helper function to check if a string is valid base58
func isBase58String(s string) bool {
	// Base58 alphabet: 123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz
	match, _ := regexp.MatchString("^[1-9A-HJ-NP-Za-km-z]+$", s)
	return match
}

// ValidateNetwork checks if a network is supported
func ValidateNetwork(network string) error {
	supportedNetworks := []string{
		"polygon", "polygon-amoy", "base", "base-sepolia",
		"solana-mainnet", "solana-devnet",
		"cosmoshub-4", "theta-testnet-001",
	}
	
	for _, supported := range supportedNetworks {
		if network == supported {
			return nil
		}
	}
	
	return fmt.Errorf("unsupported network: %s", network)
}

// ValidatePaymentScheme checks if a payment scheme is supported
func ValidatePaymentScheme(scheme string) error {
	supportedSchemes := []string{"exact", "range", "any"}
	
	for _, supported := range supportedSchemes {
		if scheme == supported {
			return nil
		}
	}
	
	return fmt.Errorf("unsupported payment scheme: %s", scheme)
}

// ConvertDecimals converts an amount from one decimal precision to another
func ConvertDecimals(amount *big.Int, fromDecimals, toDecimals int) *big.Int {
	if fromDecimals == toDecimals {
		return new(big.Int).Set(amount)
	}
	
	result := new(big.Int).Set(amount)
	
	if fromDecimals > toDecimals {
		// Divide by 10^(fromDecimals - toDecimals)
		divisor := new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(fromDecimals-toDecimals)), nil)
		result.Div(result, divisor)
	} else {
		// Multiply by 10^(toDecimals - fromDecimals)
		multiplier := new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(toDecimals-fromDecimals)), nil)
		result.Mul(result, multiplier)
	}
	
	return result
}

// ParseAmountWithDecimals parses a decimal amount string and converts to big.Int with specified decimals
func ParseAmountWithDecimals(amount string, decimals int) (*big.Int, error) {
	dec, err := ValidateAmount(amount)
	if err != nil {
		return nil, err
	}
	
	// Multiply by 10^decimals to get the raw integer amount
	multiplier := decimal.NewFromBigInt(new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(decimals)), nil), 0)
	result := dec.Mul(multiplier)
	
	return result.BigInt(), nil
}

// FormatAmountFromBigInt formats a big.Int amount to decimal string with specified decimals
func FormatAmountFromBigInt(amount *big.Int, decimals int) string {
	dec := decimal.NewFromBigInt(amount, -int32(decimals))
	return dec.String()
}