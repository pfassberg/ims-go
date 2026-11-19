package ims

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/damonto/ims-go/swu/handshake"
	swutunnel "github.com/damonto/ims-go/swu/tunnel"
	usim "github.com/damonto/wwan-go/sim"
)

// SWuConnectRequest returns the identity and USIM authentication needed to
// open an additional SWu tunnel, for example to a data APN, with
// swutunnel.Session.Connect. Each PDN connection over an ePDG uses its own
// IKE SA (3GPP TS 24.302), so the extra tunnel needs its own EAP-AKA run
// against the same USIM that the Client already owns.
//
// The USIM is loaded by Connect, so call this after Connect has succeeded at
// least once; before that it returns ErrClientNotConnected.
//
// The returned AuthenticateAKA is serialized with every other USIM AKA of the
// Client (SIP registration, its own tunnel, and other requests), including
// RegistrationGroup ordering when one is configured. It fails with
// ErrClientClosed once the Client is closed, because the reader is then closed.
//
// The returned Card exposes only the permanent identity. A tunnel opened with
// it always runs full EAP-AKA and never reads or replaces the pseudonym and
// fast re-authentication state used by the Client's own tunnel (RFC 4187
// section 4.1 binds that state to one EAP peer context).
// The caller owns any tunnel opened with the request: Client.Close does not
// close it, and the caller must close it before or after closing the Client.
func (c *Client) SWuConnectRequest() (swutunnel.ConnectRequest, error) {
	var (
		card   Card
		cfg    Config
		closed bool
	)
	c.withStateLock(func(s *clientState) {
		card = c.card
		cfg = c.cfg
		closed = s.closed
	})
	if closed {
		return swutunnel.ConnectRequest{}, fmt.Errorf("preparing swu connect request: %w", ErrClientClosed)
	}
	if card == nil {
		return swutunnel.ConnectRequest{}, fmt.Errorf("preparing swu connect request: usim is not loaded: %w", ErrClientNotConnected)
	}

	authenticate := c.coordinatedAKA(cfg.IMS, card.EAPAKA)
	return swutunnel.ConnectRequest{
		IMEI: cfg.Terminal.ID,
		// Not the USIM itself: the extra tunnel must not share the Client
		// tunnel's EAP-AKA pseudonym and fast re-authentication state.
		Card: swuSubscriberCard{imsi: card.IMSI(), mcc: card.MCC(), mnc: card.MNC()},
		AuthenticateAKA: func(ctx context.Context, rand, autn []byte) (usim.AKAResult, error) {
			if c.isClosed() {
				return usim.AKAResult{}, fmt.Errorf("authenticating swu: %w", ErrClientClosed)
			}
			return authenticate(ctx, rand, autn)
		},
	}, nil
}

// swuSubscriberCard is a snapshot of the subscriber identity for tunnels
// opened outside the Client. It deliberately lacks AKA identity storage.
type swuSubscriberCard struct {
	imsi, mcc, mnc string
}

func (c swuSubscriberCard) IMSI() string { return c.imsi }
func (c swuSubscriberCard) MCC() string  { return c.mcc }
func (c swuSubscriberCard) MNC() string  { return c.mnc }

func (c *Client) openTunnel(ctx context.Context, setup *connectSetup) (swutunnel.Info, error) {
	c.emitStatus(StatusAuthenticating)
	c.logger.Info("connecting SWu tunnel", "tunnel_remote_addr", setup.tunnelCfg.RemoteAddr)

	underlay := Underlay(nil)
	if c.cfg.Access.VoWiFi != nil {
		underlay = c.cfg.Access.VoWiFi.Underlay
	}
	remotes, err := epdgRemoteCandidates(ctx, underlay, setup.tunnelCfg.RemoteAddr, setup.tunnelCfg.InitialPort)
	if err != nil {
		return swutunnel.Info{}, err
	}

	var errs error
	for attempt, remote := range remotes {
		tunnelCfg := setup.tunnelCfg
		tunnelCfg.RemoteAddr = remote
		session, err := swutunnel.Dial(ctx, tunnelCfg)
		if err == nil {
			setup.tunnel = session
			err = session.Connect(ctx, swutunnel.ConnectRequest{
				IMEI:            c.cfg.Terminal.ID,
				Card:            c.card,
				AuthenticateAKA: c.coordinatedAKA(setup.imsCfg, c.card.EAPAKA),
			})
		}
		if err == nil {
			setup.tunnelCfg = tunnelCfg
			tunnelInfo := session.Info()
			c.recordSWUPDNTypeRestriction(tunnelInfo)
			c.logger.Info("SWu tunnel established", "inner_ip", tunnelInfo.DefaultInnerIP(), "pcscf_ip", tunnelInfo.DefaultPCSCFIP(), "pcscf_ips", tunnelInfo.PCSCFAddresses(), "esp_initiator_spi", tunnelInfo.ESPInitiatorSPI, "esp_responder_spi", tunnelInfo.ESPResponderSPI)
			return tunnelInfo, nil
		}
		if session := setup.tunnel; session != nil {
			err = errors.Join(fmt.Errorf("connecting swu via %s: %w", remote, err), session.Close())
			setup.tunnel = nil
		} else {
			err = fmt.Errorf("dialing tunnel via %s: %w", remote, err)
		}
		errs = errors.Join(errs, err)
		if attempt+1 == len(remotes) || !shouldTryNextEPDG(ctx, err) {
			break
		}
	}
	return swutunnel.Info{}, errs
}

var errSWUBackoffDeactivated = errors.New("swu backoff deactivated")

type swuBackoffGate struct {
	entries map[swuBackoffKey]swuBackoffEntry
}

type swuBackoffKey struct {
	scope swutunnel.BackoffScope
	epdg  string
	mcc   string
	mnc   string
	apn   string
}

type swuBackoffEntry struct {
	until       time.Time
	deactivated bool
}

func (c *Client) recordSWUBackoff(err error, now time.Time) {
	c.withStateLock(func(s *clientState) {
		policy, ok := swuBackoffPolicyFor(c.cfg, err)
		if !ok {
			return
		}
		key, ok := swuBackoffKeyFor(c.cfg, c.card, policy.Scope)
		if !ok {
			return
		}
		c.recordSWUBackoffLocked(s, key, policy, now)
	})
}

func (c *Client) recordSWUBackoffLocked(s *clientState, key swuBackoffKey, policy swutunnel.BackoffPolicy, now time.Time) {
	if !policy.Deactivated && policy.Delay == 0 {
		delete(s.swuBackoff.entries, key)
		return
	}
	if s.swuBackoff.entries == nil {
		s.swuBackoff.entries = make(map[swuBackoffKey]swuBackoffEntry)
	}
	entry := swuBackoffEntry{deactivated: policy.Deactivated}
	if !policy.Deactivated {
		entry.until = now.Add(policy.Delay)
	}
	current, exists := s.swuBackoff.entries[key]
	if !exists || entry.deactivated || entry.until.After(current.until) {
		s.swuBackoff.entries[key] = entry
	}
}

func swuBackoffPolicyFor(cfg Config, err error) (swutunnel.BackoffPolicy, bool) {
	if policy, ok := swutunnel.BackoffPolicyFor(err); ok {
		return policy, true
	}
	if swutunnel.NetworkFailure(err) {
		return swutunnel.BackoffPolicy{
			Delay: cfg.ReconnectDelay,
			Scope: swutunnel.BackoffScopeEPDG,
		}, cfg.ReconnectDelay > 0
	}
	if errors.Is(err, swutunnel.ErrNoAPNSubscription) {
		return swutunnel.BackoffPolicy{
			Delay: cfg.ReconnectDelay,
			Scope: swutunnel.BackoffScopePLMNAPN,
		}, cfg.ReconnectDelay > 0
	}
	return swutunnel.BackoffPolicy{}, false
}

func (c *Client) clearCurrentSWUBackoff() {
	c.withStateLock(func(s *clientState) {
		for _, key := range c.swuBackoffKeys() {
			delete(s.swuBackoff.entries, key)
		}
	})
}

func (c *Client) waitSWUBackoff(ctx context.Context) error {
	for {
		delay, deactivated, active := c.swuBackoffDelay(time.Now())
		if !active {
			return nil
		}
		if deactivated {
			return fmt.Errorf("preparing connect: %w", errSWUBackoffDeactivated)
		}
		c.logger.Info("waiting for SWu backoff", "delay", delay)
		if err := sleepContext(ctx, delay); err != nil {
			return fmt.Errorf("waiting for swu backoff: %w", err)
		}
	}
}

func (c *Client) swuBackoffDelay(now time.Time) (time.Duration, bool, bool) {
	var delay time.Duration
	var deactivated bool
	c.withStateLock(func(s *clientState) {
		for _, key := range c.swuBackoffKeys() {
			entry, ok := s.swuBackoff.entries[key]
			if !ok {
				continue
			}
			if entry.deactivated {
				deactivated = true
				return
			}
			if !entry.until.After(now) {
				delete(s.swuBackoff.entries, key)
				continue
			}
			delay = max(delay, entry.until.Sub(now))
		}
	})
	if deactivated {
		return 0, true, true
	}
	return delay, false, delay > 0
}

func (c *Client) swuBackoffKeys() []swuBackoffKey {
	keys := make([]swuBackoffKey, 0, 2)
	for _, scope := range []swutunnel.BackoffScope{swutunnel.BackoffScopeEPDG, swutunnel.BackoffScopePLMNAPN} {
		key, ok := swuBackoffKeyFor(c.cfg, c.card, scope)
		if ok {
			keys = append(keys, key)
		}
	}
	return keys
}

func swuBackoffKeyFor(cfg Config, card Card, scope swutunnel.BackoffScope) (swuBackoffKey, bool) {
	key := swuBackoffKey{scope: scope}
	if scope == swutunnel.BackoffScopeEPDG {
		epdg := strings.ToLower(strings.TrimSpace(cfg.Access.VoWiFi.EPDG))
		if epdg == "" {
			return swuBackoffKey{}, false
		}
		key.epdg = epdg
		return key, true
	}
	if scope != swutunnel.BackoffScopePLMNAPN {
		return swuBackoffKey{}, false
	}
	if card == nil {
		return swuBackoffKey{}, false
	}
	mcc, mnc, ok := normalizedBackoffPLMN(card)
	if !ok {
		return swuBackoffKey{}, false
	}
	key.mcc = mcc
	key.mnc = mnc
	key.apn = swuBackoffAPNFor(cfg)
	return key, true
}

func swuBackoffAPNFor(cfg Config) string {
	if cfg.Access.VoWiFi.Tunnel.RequestDefaultAPN {
		return ""
	}
	apn := strings.ToLower(strings.TrimSpace(cfg.Access.VoWiFi.Tunnel.APN))
	if apn == "" {
		return swutunnel.DefaultAPN
	}
	return apn
}

func normalizedBackoffPLMN(card Card) (string, string, bool) {
	mcc := strings.TrimSpace(card.MCC())
	if len(mcc) != 3 {
		return "", "", false
	}
	mnc := strings.TrimSpace(card.MNC())
	switch len(mnc) {
	case 2:
		mnc = "0" + mnc
	case 3:
	default:
		return "", "", false
	}
	return mcc, mnc, true
}

type swuPDNTypeRestrictionGate struct {
	entries map[swuPDNTypeRestrictionKey]handshake.PDNType
}

type swuPDNTypeRestrictionKey struct {
	mcc string
	mnc string
	apn string
}

func (c *Client) recordSWUPDNTypeRestriction(info swutunnel.Info) {
	restriction := info.PDNTypeRestriction
	if restriction != swutunnel.PDNTypeIPv4 && restriction != swutunnel.PDNTypeIPv6 {
		return
	}
	c.withStateLock(func(s *clientState) {
		key, ok := swuPDNTypeRestrictionKeyFor(c.card, c.cfg.Access.VoWiFi.Tunnel)
		if !ok {
			return
		}
		if s.swuPDNTypes.entries == nil {
			s.swuPDNTypes.entries = make(map[swuPDNTypeRestrictionKey]handshake.PDNType)
		}
		s.swuPDNTypes.entries[key] = restriction
	})
}

func (c *Client) applySWUPDNTypeRestriction(cfg *swutunnel.Config) {
	var restriction handshake.PDNType
	c.withStateLock(func(s *clientState) {
		key, ok := swuPDNTypeRestrictionKeyFor(c.card, *cfg)
		if !ok {
			return
		}
		restriction = s.swuPDNTypes.entries[key]
	})
	if restriction == swutunnel.PDNTypeIPv4 || restriction == swutunnel.PDNTypeIPv6 {
		cfg.PDNType = restriction
	}
}

func (c *Client) clearSWUPDNTypeRestrictionAfterDisconnect(cause error) {
	if !swutunnel.PDNDeactivated(cause) || swutunnel.ReactivationRequested(cause) {
		return
	}
	c.clearSWUPDNTypeRestriction()
}

func (c *Client) clearSWUPDNTypeRestriction() {
	c.withStateLock(func(s *clientState) {
		key, ok := swuPDNTypeRestrictionKeyFor(c.card, c.cfg.Access.VoWiFi.Tunnel)
		if !ok || len(s.swuPDNTypes.entries) == 0 {
			return
		}
		delete(s.swuPDNTypes.entries, key)
	})
}

func swuPDNTypeRestrictionKeyFor(card Card, cfg swutunnel.Config) (swuPDNTypeRestrictionKey, bool) {
	if card == nil {
		return swuPDNTypeRestrictionKey{}, false
	}
	mcc, mnc, ok := normalizedBackoffPLMN(card)
	if !ok {
		return swuPDNTypeRestrictionKey{}, false
	}
	return swuPDNTypeRestrictionKey{
		mcc: mcc,
		mnc: mnc,
		apn: swuPDNTypeRestrictionAPNFor(cfg),
	}, true
}

func swuPDNTypeRestrictionAPNFor(cfg swutunnel.Config) string {
	if cfg.RequestDefaultAPN {
		return ""
	}
	apn := strings.ToLower(strings.TrimSpace(cfg.APN))
	if apn == "" {
		return swutunnel.DefaultAPN
	}
	return apn
}
