package ims

import (
	"context"
	"fmt"

	"github.com/damonto/ims-go/ims/registration"
	usim "github.com/damonto/wwan-go/sim"
)

const (
	defaultVoWiFiRegistrationID         uint32 = 1
	defaultVoLTERegistrationID          uint32 = 2
	defaultVoWiFiRegistrationPreference        = 1000
	defaultVoLTERegistrationPreference         = 500
)

// NewRegistrationGroup returns an empty group ready to be shared by Clients.
func NewRegistrationGroup() *registration.Group {
	return &registration.Group{}
}

// coordinatedAKA runs authenticate one USIM AKA at a time. wwan-go locks each
// APDU, but AKA is a SELECT/AUTHENTICATE/GET RESPONSE sequence that must not
// interleave with another AKA on the same card. A configured RegistrationGroup
// also orders AKA across Clients; otherwise the Client's own group serializes
// its registration, tunnels, and WFC checks.
func (c *Client) coordinatedAKA(cfg ServiceConfig, authenticate func(context.Context, []byte, []byte) (usim.AKAResult, error)) func(context.Context, []byte, []byte) (usim.AKAResult, error) {
	group := cfg.RegistrationGroup
	if group == nil {
		group = c.akaGroup
	}
	if group == nil {
		return authenticate
	}
	return func(ctx context.Context, rand, autn []byte) (usim.AKAResult, error) {
		release, err := group.BeginAKA(ctx, cfg.RegistrationPreference)
		if err != nil {
			return usim.AKAResult{}, fmt.Errorf("waiting for USIM AKA access: %w", err)
		}
		defer release()
		return authenticate(ctx, rand, autn)
	}
}
