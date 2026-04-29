package x402

import (
	"context"
	"encoding/json"
	"net/http"
)

// HandlerConfig configures the payment middleware for a single route.
type HandlerConfig struct {
	// Accepts lists the payment options the server will accept for this route.
	Accepts []PaymentOption
	// Resource describes the protected resource (optional, shown to clients).
	Resource *Resource
	// Registry is used to verify and settle payments.
	Registry *Registry
	// SettleOnVerify controls whether the middleware also settles after verifying.
	// Set to false if you use a separate facilitator for settlement.
	SettleOnVerify bool
}

// PaymentMiddleware returns an http.Handler that enforces x402 payment for h.
func PaymentMiddleware(cfg HandlerConfig, h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sigHeader := r.Header.Get(HeaderPaymentSignature)
		if sigHeader == "" {
			sendPaymentRequired(w, r, cfg)
			return
		}

		payload, err := ParsePaymentPayload(sigHeader)
		if err != nil {
			sendPaymentRequired(w, r, cfg)
			return
		}

		// Find which accepted option matches the incoming payload
		opt, ok := matchOption(cfg.Accepts, payload)
		if !ok {
			sendPaymentRequired(w, r, cfg)
			return
		}

		ctx := r.Context()
		vreq := VerifyRequest{PaymentPayload: payload, PaymentOption: opt}
		vres, err := cfg.Registry.Verify(ctx, vreq)
		if err != nil || !vres.Valid {
			errMsg := "verification failed"
			if err != nil {
				errMsg = err.Error()
			} else if vres.Error != "" {
				errMsg = vres.Error
			}
			sendPaymentResponseHeader(w, PaymentResponse{Status: "failed", Error: errMsg, Payer: vres.Payer})
			sendPaymentRequired(w, r, cfg)
			return
		}

		if cfg.SettleOnVerify {
			sreq := SettleRequest{PaymentPayload: payload, PaymentOption: opt}
			sres, err := cfg.Registry.Settle(ctx, sreq)
			if err != nil || !sres.Success {
				errMsg := "settlement failed"
				if err != nil {
					errMsg = err.Error()
				} else if sres.Error != "" {
					errMsg = sres.Error
				}
				sendPaymentResponseHeader(w, PaymentResponse{Status: "failed", Error: errMsg, Payer: sres.Payer})
				w.WriteHeader(http.StatusPaymentRequired)
				return
			}
			sendPaymentResponseHeader(w, PaymentResponse{
				Status:          "success",
				TransactionHash: sres.TransactionHash,
				Network:         sres.Network,
				Payer:           sres.Payer,
			})
		}

		// Attach payer to context so the handler can read it if needed
		ctx = context.WithValue(ctx, contextKeyPayer{}, vres.Payer)
		h.ServeHTTP(w, r.WithContext(ctx))
	})
}

type contextKeyPayer struct{}

// PayerFromContext returns the verified payer address set by PaymentMiddleware.
func PayerFromContext(ctx context.Context) string {
	v, _ := ctx.Value(contextKeyPayer{}).(string)
	return v
}

// matchOption returns the first PaymentOption whose network and scheme match
// the incoming payment payload's accepted field.
func matchOption(accepts []PaymentOption, p PaymentPayloadV2) (PaymentOption, bool) {
	for _, opt := range accepts {
		if opt.Network == p.Accepted.Network && opt.Scheme == p.Accepted.Scheme {
			return opt, true
		}
	}
	return PaymentOption{}, false
}

func sendPaymentRequired(w http.ResponseWriter, r *http.Request, cfg HandlerConfig) {
	pr := PaymentRequiredV2{
		X402Version: VersionV2,
		Error:       "payment_required",
		Resource: func() *Resource {
			if cfg.Resource != nil {
				return cfg.Resource
			}
			return &Resource{URL: r.URL.Path}
		}(),
		Accepts: cfg.Accepts,
	}

	encoded, err := EncodeHeader(pr)
	if err == nil {
		w.Header().Set(HeaderPaymentRequired, encoded)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusPaymentRequired)
	_ = json.NewEncoder(w).Encode(pr)
}

func sendPaymentResponseHeader(w http.ResponseWriter, pr PaymentResponse) {
	encoded, err := EncodeHeader(pr)
	if err == nil {
		w.Header().Set(HeaderPaymentResponse, encoded)
	}
}
