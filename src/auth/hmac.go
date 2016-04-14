package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"log"
)

func ComputeHmac256(message, key string) []byte {
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write([]byte(message))
	expectedMAC := mac.Sum(nil)

	return expectedMAC
}

// CheckMAC reports whether messageHMAC is a valid HMAC tag for message.
func checkMAC(key, message string, messageHMAC []byte) bool {
	expectedMAC := ComputeHmac256(message, key)
	equal := hmac.Equal(messageHMAC, expectedMAC)
	if !equal {
		log.Println("key:", key, "\nmessage:", message, "\nexpected:", expectedMAC, "\nreceived:", messageHMAC)
	}

	return equal
}
