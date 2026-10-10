package gateway

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
)

// ApprovalToken signs one exact change: the policy it starts from, the policy it ends at,
// and the fingerprint of every request whose decision flips. Edit the policy afterwards and
// the digests move, so the token no longer verifies.
func ApprovalToken(key []byte, d DiffReport) string {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(d.FromDigest + "|" + d.ToDigest + "|" + d.Fingerprint))
	return hex.EncodeToString(mac.Sum(nil))
}

func ValidApproval(key []byte, d DiffReport, token string) bool {
	if len(key) == 0 || token == "" {
		return false
	}
	want, err := hex.DecodeString(ApprovalToken(key, d))
	got, err2 := hex.DecodeString(token)
	return err == nil && err2 == nil && hmac.Equal(want, got)
}
