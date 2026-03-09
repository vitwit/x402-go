package types

import "encoding/json"

// PayloadBytes returns the payload as JSON bytes from the V2 map.
// This is the V2 equivalent of base64-decoding the V1 string payload.
func (p *PaymentPayload) PayloadBytes() ([]byte, error) {
	return json.Marshal(p.Payload)
}

// SetPayloadFromBytes sets the Payload map from JSON bytes.
// This allows V1 compatibility by parsing a JSON byte slice into the map.
func (p *PaymentPayload) SetPayloadFromBytes(data []byte) error {
	return json.Unmarshal(data, &p.Payload)
}

// SetPayloadFromBase64String sets the Payload map from a base64-decoded JSON string.
// This bridges V1 (string payload) to V2 (map payload) format.
func (p *PaymentPayload) SetPayloadFromString(jsonStr string) error {
	return json.Unmarshal([]byte(jsonStr), &p.Payload)
}
