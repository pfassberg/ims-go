package tunnel

import (
	"bytes"
	"log/slog"
	"testing"
)

func TestIKEKeyLogLine(t *testing.T) {
	keys := ikeKeys{
		SKEI: []byte{0x01, 0x02},
		SKER: []byte{0x03, 0x04},
		SKAI: []byte{0x05},
		SKAR: []byte{0x06},
	}
	tests := []struct {
		name    string
		encr    uint16
		keyBits uint16
		integ   uint16
		want    string
		wantErr bool
	}{
		{
			name: "aes-cbc-128 with sha256", encr: transformENCRAESCBC, keyBits: transformKeyLenAES128, integ: transformINTEGHMACSHA256,
			want: `00000000000000ab,0000000000000cde,0102,0304,"AES-CBC-128 [RFC3602]",05,06,"HMAC_SHA2_256_128 [RFC4868]"`,
		},
		{
			name: "aes-ctr-256 with sha1", encr: transformENCRAESCTR, keyBits: transformKeyLenAES256, integ: transformINTEGHMACSHA196,
			want: `00000000000000ab,0000000000000cde,0102,0304,"AES-CTR-256 [RFC5930]",05,06,"HMAC_SHA1_96 [RFC2404]"`,
		},
		{name: "unknown encryption", encr: 99, keyBits: transformKeyLenAES128, integ: transformINTEGHMACSHA256, wantErr: true},
		{name: "unknown key length", encr: transformENCRAESCBC, keyBits: 64, integ: transformINTEGHMACSHA256, wantErr: true},
		{name: "integrity without wireshark name", encr: transformENCRAESCBC, keyBits: transformKeyLenAES128, integ: transformINTEGAESXCBC96, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &ikeCrypto{encr: tt.encr, encrKeyBits: tt.keyBits, integ: tt.integ, initiatorSPI: 0xab, responderSPI: 0xcde, keys: keys}
			got, err := ikeKeyLogLine(c)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("ikeKeyLogLine() = %q, want error", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("ikeKeyLogLine() error = %v", err)
			}
			if got != tt.want {
				t.Fatalf("ikeKeyLogLine() =\n%s\nwant\n%s", got, tt.want)
			}
		})
	}
}

func TestLogIKEKeysWritesOnlyWhenConfigured(t *testing.T) {
	c := &ikeCrypto{encr: transformENCRAESCBC, encrKeyBits: transformKeyLenAES128, integ: transformINTEGHMACSHA256}

	s := &Session{logger: slog.Default()}
	s.logIKEKeys(c) // must not panic without a writer

	var buf bytes.Buffer
	s = &Session{cfg: Config{KeyLog: &buf}, logger: slog.Default()}
	s.logIKEKeys(c)
	if got := bytes.Count(buf.Bytes(), []byte("\n")); got != 1 {
		t.Fatalf("key log lines = %d, want 1: %q", got, buf.String())
	}
}
