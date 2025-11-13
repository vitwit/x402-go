package types

type EthereumPaymentPayload struct {
	Payment struct {
		TxHex string `json:"txHex"` // raw signed tx in hex
	} `json:"payment"`
}
