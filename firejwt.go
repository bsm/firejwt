package firejwt

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/dgrijalva/jwt-go"
)

// Validator validates Firebase JWTs
type Validator struct {
	opt *Options
	htc http.Client

	cancel  context.CancelFunc
	keyset  atomic.Value
	expires int64
}

// New issues a new Validator.
func New(opt *Options) (*Validator, error) {
	v := &Validator{opt: opt.norm()}
	if err := v.Refresh(); err != nil {
		return nil, err
	}

	ctx, cancel := context.WithCancel(context.Background())
	v.cancel = cancel
	go v.loop(ctx)

	return v, nil
}

// Stop stops the validator updates.
func (v *Validator) Stop() {
	v.cancel()
}

// Decode decodes the token
func (v *Validator) Decode(tokenString string) (*jwt.Token, error) {
	return jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		kid, ok := token.Header["kid"].(string)
		if !ok {
			return nil, fmt.Errorf("missing kid header")
		}

		key, ok := v.keyset.Load().(map[string]publicKey)[kid]
		if !ok {
			return nil, fmt.Errorf("unknown kid header %s", kid)
		}

		return key.PublicKey, nil
	})
}

// ExpTime returns the expiration time.
func (v *Validator) ExpTime() time.Time {
	return time.Unix(atomic.LoadInt64(&v.expires), 0)
}

// Refresh retrieves the latest keys.
func (v *Validator) Refresh() error {
	resp, err := v.htc.Get(v.opt.URL)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	exp, err := time.Parse(time.RFC1123, resp.Header.Get("Expires"))
	if err != nil {
		return err
	}

	var keyset map[string]publicKey
	if err := json.NewDecoder(resp.Body).Decode(&keyset); err != nil {
		return err
	}

	v.keyset.Store(keyset)
	atomic.StoreInt64(&v.expires, exp.Unix())
	return nil
}

func (v *Validator) loop(ctx context.Context) {
	t := time.NewTimer(time.Minute)
	defer t.Stop()

	for {
		d := v.ExpTime().Sub(time.Now()) - time.Hour
		if d < time.Minute {
			d = time.Minute
		}
		t.Reset(d)

		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := v.Refresh(); err != nil {
				log.Printf("[firejwt] failed to refresh keyset: %v", err)
			}
		}
	}
}

// --------------------------------------------------------------------

type publicKey struct {
	*rsa.PublicKey
}

func (k *publicKey) UnmarshalText(data []byte) error {
	block, _ := pem.Decode(data)
	if block == nil {
		return fmt.Errorf("invalid certificate")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return err
	}

	if cert.PublicKeyAlgorithm != x509.RSA {
		return fmt.Errorf("unexpected public key algorithm: %s", cert.PublicKeyAlgorithm)
	}

	*k = publicKey{PublicKey: cert.PublicKey.(*rsa.PublicKey)}
	return nil
}
