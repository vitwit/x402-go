package utils

import (
	"bytes"
	"encoding/json"
	"fmt"
	"time"

	"github.com/go-playground/validator/v10"
	"github.com/vitwit/x402/types"
)

var validate *validator.Validate

func init() {
	validate = validator.New()

	// Register custom validators
	// validate.RegisterValidation("network", validateNetworkTag)
	// validate.RegisterValidation("paymentscheme", validatePaymentSchemeTag)
	// validate.RegisterValidation("amount", validateAmountTag)
}

// ParsePaymentRequirements parses and validates PaymentRequirements from JSON
func ParsePaymentRequirements(data []byte) (*types.PaymentRequirements, error) {
	var req types.PaymentRequirements

	if err := json.Unmarshal(data, &req); err != nil {
		return nil, &types.X402Error{
			Code:    types.ErrInvalidRequirements,
			Message: fmt.Sprintf("failed to parse payment requirements: %v", err),
		}
	}

	// Validate using struct tags
	if err := validate.Struct(&req); err != nil {
		return nil, &types.X402Error{
			Code:    types.ErrInvalidRequirements,
			Message: fmt.Sprintf("validation failed: %v", err),
		}
	}

	// Custom validation
	// if err := req.Validate(); err != nil {
	// 	return nil, err
	// }

	// Additional validation for amount based on scheme
	// if err := validateAmountForScheme(&req); err != nil {
	// 	return nil, err
	// }

	return &req, nil
}

// SerializePaymentRequirements converts PaymentRequirements to JSON
func SerializePaymentRequirements(req *types.PaymentRequirements) ([]byte, error) {
	return json.Marshal(req)
}

// SerializeVerificationResult converts VerificationResult to JSON
func SerializeVerificationResult(result *types.VerificationResult) ([]byte, error) {
	return json.Marshal(result)
}

// SerializeSettlementResult converts SettlementResult to JSON
func SerializeSettlementResult(result *types.SettlementResult) ([]byte, error) {
	return json.Marshal(result)
}

// Custom validator functions
// func validateNetworkTag(fl validator.FieldLevel) bool {
// 	network := fl.Field().String()
// 	return ValidateNetwork(network) == nil
// }

// func validatePaymentSchemeTag(fl validator.FieldLevel) bool {
// 	scheme := fl.Field().String()
// 	return ValidatePaymentScheme(scheme) == nil
// }

// func validateAmountTag(fl validator.FieldLevel) bool {
// 	amount := fl.Field().String()
// 	_, err := ValidateAmount(amount)
// 	return err == nil
// }

// validateAmountForScheme ensures amount fields are properly set based on payment scheme
// func validateAmountForScheme(req *types.PaymentRequirements) error {
// 	switch req.Scheme {
// 	case types.SchemeExact:
// 		if req.Amount == nil || req.Amount.Value == nil {
// 			return &types.X402Error{
// 				Code:    types.ErrInvalidRequirements,
// 				Message: "exact payment scheme requires a value",
// 			}
// 		}
// 		if req.Amount.Min != nil || req.Amount.Max != nil {
// 			return &types.X402Error{
// 				Code:    types.ErrInvalidRequirements,
// 				Message: "exact payment scheme should not have min/max values",
// 			}
// 		}

// 	case types.SchemeRange:
// 		if req.Amount == nil || req.Amount.Min == nil || req.Amount.Max == nil {
// 			return &types.X402Error{
// 				Code:    types.ErrInvalidRequirements,
// 				Message: "range payment scheme requires min and max values",
// 			}
// 		}
// 		if req.Amount.Value != nil {
// 			return &types.X402Error{
// 				Code:    types.ErrInvalidRequirements,
// 				Message: "range payment scheme should not have a fixed value",
// 			}
// 		}
// 		if req.Amount.Min.GreaterThan(*req.Amount.Max) {
// 			return &types.X402Error{
// 				Code:    types.ErrInvalidRequirements,
// 				Message: "min amount cannot be greater than max amount",
// 			}
// 		}

// 	case types.SchemeAny:
// 		if req.Amount == nil || req.Amount.Currency == "" {
// 			return &types.X402Error{
// 				Code:    types.ErrInvalidRequirements,
// 				Message: "any payment scheme requires a currency",
// 			}
// 		}
// 		if req.Amount.Value != nil || req.Amount.Min != nil || req.Amount.Max != nil {
// 			return &types.X402Error{
// 				Code:    types.ErrInvalidRequirements,
// 				Message: "any payment scheme should not have specific amounts",
// 			}
// 		}
// 	}

// 	return nil
// }

// Helper functions for common parsing tasks

// ParseClientConfig parses ClientConfig from JSON
func ParseClientConfig(data []byte) (*types.ClientConfig, error) {
	var config types.ClientConfig

	if err := json.Unmarshal(data, &config); err != nil {
		return nil, &types.X402Error{
			Code:    types.ErrConfigError,
			Message: fmt.Sprintf("failed to parse client config: %v", err),
		}
	}

	if err := validate.Struct(&config); err != nil {
		return nil, &types.X402Error{
			Code:    types.ErrConfigError,
			Message: fmt.Sprintf("validation failed: %v", err),
		}
	}

	return &config, nil
}

// ParseX402Config parses X402Config from JSON
func ParseX402Config(data []byte) (*types.X402Config, error) {
	var config types.X402Config

	if err := json.Unmarshal(data, &config); err != nil {
		return nil, &types.X402Error{
			Code:    types.ErrConfigError,
			Message: fmt.Sprintf("failed to parse x402 config: %v", err),
		}
	}

	if err := validate.Struct(&config); err != nil {
		return nil, &types.X402Error{
			Code:    types.ErrConfigError,
			Message: fmt.Sprintf("validation failed: %v", err),
		}
	}

	return &config, nil
}

// Helper to parse time fields that might be in different formats
func ParseFlexibleTime(timeStr string) (time.Time, error) {
	formats := []string{
		time.RFC3339,
		time.RFC3339Nano,
		"2006-01-02T15:04:05Z",
		"2006-01-02 15:04:05",
		"2006-01-02",
	}

	for _, format := range formats {
		if t, err := time.Parse(format, timeStr); err == nil {
			return t, nil
		}
	}

	return time.Time{}, fmt.Errorf("unable to parse time: %s", timeStr)
}

// NormalizeJSON formats JSON with consistent indentation
func NormalizeJSON(data interface{}) ([]byte, error) {
	return json.MarshalIndent(data, "", "  ")
}

// CompactJSON removes whitespace from JSON
func CompactJSON(data []byte) ([]byte, error) {
	var buffer bytes.Buffer
	if err := json.Compact(&buffer, data); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}
