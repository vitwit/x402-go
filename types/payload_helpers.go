package types

import (
	"encoding/json"
	"fmt"
)

// PayloadBytes returns the payload as JSON bytes from the V2 map.
// This is the V2 equivalent of base64-decoding the V1 string payload.
func (p *PaymentPayload) PayloadBytes() ([]byte, error) {
	return json.Marshal(p.Payload)
}

// SetPayloadFromBytes sets the Payload map from JSON bytes.
// This allows V1 compatibility by parsing a JSON byte slice into the map.
func (p *PaymentPayload) SetPayloadFromBytes(data []byte) error {
	if len(data) == 0 {
		return nil
	}

	// 1. Try unmarshaling directly (handles case where data is a JSON object)
	if err := json.Unmarshal(data, &p.Payload); err == nil {
		return nil
	}

	// 2. If it fails, it might be a quoted JSON string
	var s string
	if err := json.Unmarshal(data, &s); err == nil {
		// Try unmarshaling the string content as JSON
		return json.Unmarshal([]byte(s), &p.Payload)
	}

	return fmt.Errorf("could not unmarshal payload as object or string")
}

// SetPayloadFromBase64String sets the Payload map from a base64-decoded JSON string.
// This bridges V1 (string payload) to V2 (map payload) format.
func (p *PaymentPayload) SetPayloadFromString(jsonStr string) error {
	return json.Unmarshal([]byte(jsonStr), &p.Payload)
}
