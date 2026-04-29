package x402

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
)

// EncodeHeader JSON-encodes v and base64url-encodes the result for use in an x402 header.
func EncodeHeader(v any) (string, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

// DecodeHeader base64url-decodes raw and JSON-unmarshals it into dst.
func DecodeHeader(raw string, dst any) error {
	b, err := base64.URLEncoding.DecodeString(raw)
	if err != nil {
		// fall back to standard encoding
		b, err = base64.StdEncoding.DecodeString(raw)
		if err != nil {
			return fmt.Errorf("base64 decode: %w", err)
		}
	}
	return json.Unmarshal(b, dst)
}

// ParsePaymentPayload decodes the Payment-Signature header value.
// v1 payloads carry scheme/network at the top level; they are promoted into
// the Accepted field so the rest of the stack only handles PaymentPayloadV2.
func ParsePaymentPayload(raw string) (PaymentPayloadV2, error) {
	b, err := base64.URLEncoding.DecodeString(raw)
	if err != nil {
		b, err = base64.StdEncoding.DecodeString(raw)
		if err != nil {
			return PaymentPayloadV2{}, fmt.Errorf("base64 decode payment-signature: %w", err)
		}
	}

	var peek struct {
		X402Version int `json:"x402Version"`
	}
	if err := json.Unmarshal(b, &peek); err != nil {
		return PaymentPayloadV2{}, fmt.Errorf("parse version: %w", err)
	}

	switch peek.X402Version {
	case VersionV1:
		var v1 PaymentPayloadV1
		if err := json.Unmarshal(b, &v1); err != nil {
			return PaymentPayloadV2{}, fmt.Errorf("parse v1 payload: %w", err)
		}
		return PaymentPayloadV2{
			X402Version: VersionV2,
			Accepted: PaymentOption{
				Scheme:  v1.Scheme,
				Network: v1.Network,
			},
			Payload: v1.Payload,
		}, nil
	default:
		var v2 PaymentPayloadV2
		if err := json.Unmarshal(b, &v2); err != nil {
			return PaymentPayloadV2{}, fmt.Errorf("parse v2 payload: %w", err)
		}
		return v2, nil
	}
}

// ParsePaymentRequired decodes the Payment-Required header / body value.
func ParsePaymentRequired(raw string) (PaymentRequiredV2, error) {
	b, err := base64.URLEncoding.DecodeString(raw)
	if err != nil {
		b, err = base64.StdEncoding.DecodeString(raw)
		if err != nil {
			// treat raw as plain JSON (v1 body usage)
			b = []byte(raw)
		}
	}

	var peek struct {
		X402Version int `json:"x402Version"`
	}
	if err := json.Unmarshal(b, &peek); err != nil {
		return PaymentRequiredV2{}, fmt.Errorf("parse version: %w", err)
	}

	switch peek.X402Version {
	case VersionV1:
		var v1 PaymentRequiredV1
		if err := json.Unmarshal(b, &v1); err != nil {
			return PaymentRequiredV2{}, fmt.Errorf("parse v1 payment-required: %w", err)
		}
		return PaymentRequiredV2{
			X402Version: VersionV2,
			Accepts:     v1.Accepts,
		}, nil
	default:
		var v2 PaymentRequiredV2
		if err := json.Unmarshal(b, &v2); err != nil {
			return PaymentRequiredV2{}, fmt.Errorf("parse v2 payment-required: %w", err)
		}
		return v2, nil
	}
}
