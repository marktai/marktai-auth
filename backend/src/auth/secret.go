package auth

import (
	"crypto/rand"
	"encoding/base64"
	"math/big"
	"time"
)

var secretMap = make(map[uint]*Secret)

type Secret struct {
	value        *big.Int
	expiration   time.Time
	stayLoggedIn bool
}

// secrets are an arbitrary big int number from 0 to 2^512
// to actually use their value, they are converted into base64
// then the base64 string chararcters are used as bytes
// this is to get random bytes and still be able to nicely store them in strings
func (s *Secret) Bytes() []byte {
	return s.value.Bytes()
}

func (s *Secret) Base64() string {
	return base64.StdEncoding.EncodeToString(s.Bytes())
}

func (s *Secret) String() string {
	return s.Base64()
}

func (s *Secret) Expired() bool {
	return time.Now().After(s.expiration)
}

func (s *Secret) ExpirationUTC() string {
	return s.expiration.UTC().Format(time.RFC3339)
}

func (s *Secret) resetExpiration() {
	var newTime time.Time
	if !s.stayLoggedIn {
		newTime = time.Now().Add(30 * time.Minute)
	} else {
		newTime = time.Now().Add(7 * 24 * time.Hour)
	}

	if newTime.After(s.expiration) {
		s.expiration = newTime
	}
}

func (s *Secret) setExpiration(dur time.Duration) {
	s.expiration = time.Now().Add(dur)
}

var bitSize int64 = 512

var limit *big.Int

func newSecret(stayLoggedIn bool) (*Secret, error) {
	if limit == nil {
		limit = big.NewInt(2)
		limit.Exp(big.NewInt(2), big.NewInt(bitSize), nil)
	}

	value, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, err
	}
	retSecret := &Secret{
		value:        value,
		stayLoggedIn: stayLoggedIn,
	}
	retSecret.resetExpiration()

	return retSecret, nil
}
