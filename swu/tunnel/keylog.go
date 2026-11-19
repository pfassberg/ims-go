package tunnel

import (
	"encoding/hex"
	"fmt"
	"sync"
)

// keyLogMu serializes key log lines from every session, so callers can share
// one writer (for example a file) between several tunnels.
var keyLogMu sync.Mutex

// logIKEKeys writes the IKE SA keys to Config.KeyLog as one line of
// Wireshark's ikev2_decryption_table UAT file. Wireshark then decrypts
// IKE_AUTH, CREATE_CHILD_SA, and INFORMATIONAL exchanges in a capture.
// Transforms Wireshark cannot decrypt are reported through the logger
// instead of writing an unusable line.
func (s *Session) logIKEKeys(c *ikeCrypto) {
	if s.cfg.KeyLog == nil || c == nil {
		return
	}
	line, err := ikeKeyLogLine(c)
	if err != nil {
		s.logger.Warn("skipping IKE key log line", "err", err)
		return
	}
	keyLogMu.Lock()
	_, err = fmt.Fprintln(s.cfg.KeyLog, line)
	keyLogMu.Unlock()
	if err != nil {
		s.logger.Warn("writing IKE key log", "err", err)
	}
}

// ikeKeyLogLine formats the keys in Wireshark's ikev2_decryption_table order:
// SPIi, SPIr, SK_ei, SK_er, encryption, SK_ai, SK_ar, integrity. Wireshark's
// UAT format writes byte fields as bare hex and enum fields as quoted
// strings; the algorithm names must match Wireshark's enum strings exactly.
func ikeKeyLogLine(c *ikeCrypto) (string, error) {
	encr, err := wiresharkIKEEncryption(c.encr, c.encrKeyBits)
	if err != nil {
		return "", err
	}
	integ, err := wiresharkIKEIntegrity(c.integ)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%016x,%016x,%s,%s,%q,%s,%s,%q",
		c.initiatorSPI,
		c.responderSPI,
		hex.EncodeToString(c.keys.SKEI),
		hex.EncodeToString(c.keys.SKER),
		encr,
		hex.EncodeToString(c.keys.SKAI),
		hex.EncodeToString(c.keys.SKAR),
		integ,
	), nil
}

func wiresharkIKEEncryption(encr, keyBits uint16) (string, error) {
	var mode string
	switch encr {
	case transformENCRAESCBC:
		mode = "AES-CBC-%d [RFC3602]"
	case transformENCRAESCTR:
		// RFC 5930 key material includes the 4-byte nonce, as SK_e* does here.
		mode = "AES-CTR-%d [RFC5930]"
	default:
		return "", fmt.Errorf("encryption transform %d has no Wireshark IKEv2 name", encr)
	}
	switch keyBits {
	case transformKeyLenAES128, transformKeyLenAES192, transformKeyLenAES256:
		return fmt.Sprintf(mode, keyBits), nil
	default:
		return "", fmt.Errorf("encryption key length %d has no Wireshark IKEv2 name", keyBits)
	}
}

func wiresharkIKEIntegrity(integ uint16) (string, error) {
	switch integ {
	case transformINTEGHMACMD596:
		return "HMAC_MD5_96 [RFC2403]", nil
	case transformINTEGHMACSHA196:
		return "HMAC_SHA1_96 [RFC2404]", nil
	case transformINTEGHMACSHA256:
		return "HMAC_SHA2_256_128 [RFC4868]", nil
	case transformINTEGHMACSHA384:
		return "HMAC_SHA2_384_192 [RFC4868]", nil
	case transformINTEGHMACSHA512:
		return "HMAC_SHA2_512_256 [RFC4868]", nil
	default:
		return "", fmt.Errorf("integrity transform %d has no Wireshark IKEv2 name", integ)
	}
}
