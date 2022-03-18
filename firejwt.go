package firejwt

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

func init() {
	jwt.MarshalSingleStringAsArray = false
}

const defaultURL = "https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com"

// Validator validates Firebase JWTs
type Validator struct {
	audience string
	issuer   string
	url      string
	htc      http.Client

	cancel  context.CancelFunc
	keyset  atomic.Value
	expires int64
}

// New issues a new Validator with a projectID, a unique identifier for your
// Firebase project, which can be found in the URL of that project's console.
func New(projectID string) (*Validator, error) {
	return newValidator(projectID, defaultURL)
}

func newValidator(projectID, url string) (*Validator, error) {
	v := &Validator{
		audience: projectID,
		issuer:   "https://securetoken.google.com/" + projectID,
		url:      url,
	}
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
func (v *Validator) Decode(tokenString string) (*Claims, error) {
	claims := new(Claims)
	token, err := jwt.ParseWithClaims(tokenString, claims, v.verify)
	if err != nil {
		return nil, err
	} else if !token.Valid {
		return nil, errTokenInvalid
	}
	return claims, nil
}

// ExpTime returns the expiration time.
func (v *Validator) ExpTime() time.Time {
	return time.Unix(atomic.LoadInt64(&v.expires), 0)
}

// Refresh retrieves the latest keys.
func (v *Validator) Refresh() error {
	resp, err := v.htc.Get(v.url)
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

var (
	errKIDMissing   = errors.New("token is missing kid header")
	errNoSubject    = errors.New("token has no subject")
	errAuthFuture   = errors.New("token auth_time not valid")
	errTokenInvalid = errors.New("token is invalid")
)

func (v *Validator) verify(token *jwt.Token) (interface{}, error) {
	kid, ok := token.Header["kid"].(string)
	if !ok {
		return nil, errKIDMissing
	}

	key, ok := v.keyset.Load().(map[string]publicKey)[kid]
	if !ok {
		return nil, fmt.Errorf("invalid kid header %q", kid)
	}

	claims := token.Claims.(*Claims)
	if err := claims.validate(time.Now(), v.audience, v.issuer); err != nil {
		return nil, err
	}
	return key.PublicKey, nil
}

func (v *Validator) loop(ctx context.Context) {
	t := time.NewTimer(time.Minute)
	defer t.Stop()

	for {
		d := time.Until(v.ExpTime()) - time.Hour
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

// --------------------------------------------------------------------

// Claims are included in the token.
type Claims struct {
	Name          string           `json:"name,omitempty"`
	Picture       string           `json:"picture,omitempty"`
	UserID        string           `json:"user_id,omitempty"`
	AuthAt        *jwt.NumericDate `json:"auth_time,omitempty"`
	Email         string           `json:"email,omitempty"`
	EmailVerified bool             `json:"email_verified"`
	Firebase      *FirebaseClaim   `json:"firebase,omitempty"`

	jwt.RegisteredClaims
}

func (c *Claims) validate(now time.Time, audience, issuer string) error {
	if !c.VerifyExpiresAt(now, false) {
		return jwt.ErrTokenExpired
	} else if !c.VerifyIssuedAt(now, false) {
		return jwt.ErrTokenUsedBeforeIssued
	} else if !c.VerifyNotBefore(now, false) {
		return jwt.ErrTokenNotValidYet
	} else if !c.VerifyAudience(audience, true) {
		return jwt.ErrTokenInvalidAudience
	} else if !c.VerifyIssuer(issuer, true) {
		return jwt.ErrTokenInvalidIssuer
	} else if c.Subject == "" {
		return errNoSubject
	} else if c.AuthAt.After(now) {
		return errAuthFuture
	}
	return nil
}

// FirebaseClaim represents firebase specific claim.
type FirebaseClaim struct {
	SignInProvider string              `json:"sign_in_provider,omitempty"`
	Identities     map[string][]string `json:"identities,omitempty"`
}
