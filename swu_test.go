package ims

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	swutunnel "github.com/damonto/ims-go/swu/tunnel"
	usim "github.com/damonto/wwan-go/sim"
)

func TestSWUAPNPolicyKeys(t *testing.T) {
	tests := []struct {
		name string
		cfg  swutunnel.Config
		want string
	}{
		{name: "implicit ims apn", want: swutunnel.DefaultAPN},
		{name: "explicit apn", cfg: swutunnel.Config{APN: " Internet "}, want: "internet"},
		{name: "network default apn", cfg: swutunnel.Config{RequestDefaultAPN: true}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Config{Access: VoWiFi(VoWiFiConfig{Tunnel: tt.cfg})}
			if got := swuBackoffAPNFor(cfg); got != tt.want {
				t.Errorf("swuBackoffAPNFor() = %q, want %q", got, tt.want)
			}
			if got := swuPDNTypeRestrictionAPNFor(tt.cfg); got != tt.want {
				t.Errorf("swuPDNTypeRestrictionAPNFor() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestClientSWuConnectRequest(t *testing.T) {
	t.Run("usim not loaded", func(t *testing.T) {
		client := newClient(Config{Logger: testLogger(), Terminal: TerminalInfo{ID: "356938035643809"}})
		if _, err := client.SWuConnectRequest(); !errors.Is(err, ErrClientNotConnected) {
			t.Fatalf("SWuConnectRequest() error = %v, want %v", err, ErrClientNotConnected)
		}
	})

	t.Run("loaded usim", func(t *testing.T) {
		client := newClient(Config{Logger: testLogger(), Terminal: TerminalInfo{ID: "356938035643809"}})
		client.card = stubCard{}

		req, err := client.SWuConnectRequest()
		if err != nil {
			t.Fatalf("SWuConnectRequest() error = %v", err)
		}
		if req.IMEI != "356938035643809" {
			t.Errorf("IMEI = %q, want %q", req.IMEI, "356938035643809")
		}
		if req.Card == nil || req.Card.IMSI() != (stubCard{}).IMSI() || req.Card.MCC() != "001" || req.Card.MNC() != "001" {
			t.Errorf("Card = %+v, want stub card identity", req.Card)
		}
		if _, ok := req.Card.(interface {
			AKAIdentityState() usim.AKAIdentityState
		}); ok {
			t.Error("Card exposes AKA identity state; extra tunnels must not share it with the Client tunnel")
		}
		got, err := req.AuthenticateAKA(context.Background(), make([]byte, 16), make([]byte, 16))
		if err != nil {
			t.Fatalf("AuthenticateAKA() error = %v", err)
		}
		if !bytes.Equal(got.RES, []byte("12345678")) {
			t.Errorf("AuthenticateAKA() RES = %q, want %q", got.RES, "12345678")
		}

		client.withStateLock(func(s *clientState) { s.closed = true })
		if _, err := req.AuthenticateAKA(context.Background(), make([]byte, 16), make([]byte, 16)); !errors.Is(err, ErrClientClosed) {
			t.Errorf("AuthenticateAKA() after close error = %v, want %v", err, ErrClientClosed)
		}
		if _, err := client.SWuConnectRequest(); !errors.Is(err, ErrClientClosed) {
			t.Errorf("SWuConnectRequest() after close error = %v, want %v", err, ErrClientClosed)
		}
	})
}

func TestClientCoordinatedAKASerializesWithoutRegistrationGroup(t *testing.T) {
	client := newClient(Config{Logger: testLogger()})
	entered := make(chan struct{})
	unblock := make(chan struct{})
	blocking := client.coordinatedAKA(ServiceConfig{}, func(context.Context, []byte, []byte) (usim.AKAResult, error) {
		close(entered)
		<-unblock
		return usim.AKAResult{}, nil
	})
	done := make(chan error, 1)
	go func() {
		_, err := blocking(t.Context(), nil, nil)
		done <- err
	}()
	<-entered

	// A second AKA, for example a data tunnel during SIP re-registration, must
	// wait for the first one instead of interleaving APDUs on the card.
	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()
	second := client.coordinatedAKA(ServiceConfig{}, func(context.Context, []byte, []byte) (usim.AKAResult, error) {
		t.Error("second AKA ran while the first was still in progress")
		return usim.AKAResult{}, nil
	})
	if _, err := second(ctx, nil, nil); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("second AKA error = %v, want %v", err, context.DeadlineExceeded)
	}

	close(unblock)
	if err := <-done; err != nil {
		t.Fatalf("first AKA error = %v", err)
	}
	if _, err := client.coordinatedAKA(ServiceConfig{}, func(context.Context, []byte, []byte) (usim.AKAResult, error) {
		return usim.AKAResult{}, nil
	})(t.Context(), nil, nil); err != nil {
		t.Fatalf("AKA after release error = %v", err)
	}
}
