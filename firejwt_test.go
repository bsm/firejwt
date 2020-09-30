package firejwt_test

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/bsm/firejwt"
	"github.com/dgrijalva/jwt-go"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Validator", func() {
	var subject *firejwt.Validator
	var server *httptest.Server
	var claims *firejwt.Claims

	generate := func() string {
		token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		token.Header["kid"] = certKID

		data, err := token.SignedString(privKey)
		Expect(err).NotTo(HaveOccurred())
		return data
	}

	BeforeEach(func() {
		server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("expires", "Mon, 20 Jan 2020 23:40:59 GMT")
			json.NewEncoder(w).Encode(map[string]string{
				certKID: string(certPEM),
			})
		}))

		now := time.Now().Unix()
		claims = &firejwt.Claims{
			Name:          "Me",
			Picture:       "https://test.host/me.jpg",
			Subject:       "MDYwNDQwNjUtYWQ0ZC00ZDkwLThl",
			UserID:        "MDYwNDQwNjUtYWQ0ZC00ZDkwLThl",
			Audience:      "mock-project",
			Issuer:        "https://securetoken.google.com/mock-project",
			IssuedAt:      now - 1800,
			ExpiresAt:     now + 3600,
			AuthAt:        now,
			Email:         "me@example.com",
			EmailVerified: true,
			Firebase: &firejwt.FirebaseClaim{
				SignInProvider: "google.com",
				Identities: map[string][]string{
					"google.com": {"123123123123123123123"},
					"email":      {"me@example.com"},
				},
			},
		}

		var err error
		subject, err = firejwt.Mocked(server.URL)
		Expect(err).NotTo(HaveOccurred())
	})

	AfterEach(func() {
		server.Close()
		subject.Stop()
	})

	It("should refresh on init", func() {
		Expect(subject.ExpTime()).To(BeTemporally("==", time.Date(2020, 1, 20, 23, 40, 59, 0, time.UTC)))
	})

	It("should decode tokens", func() {
		token, err := subject.Decode(generate())
		Expect(err).NotTo(HaveOccurred())
		Expect(token.Valid).To(BeTrue())
		Expect(token.Claims).To(Equal(claims))
	})

	It("should reject bad tokens", func() {
		_, err := subject.Decode("BAD")
		Expect(err).To(MatchError(`token contains an invalid number of segments`))
		Expect(err).To(BeAssignableToTypeOf(&jwt.ValidationError{}))
	})

	It("should verify exp", func() {
		claims.ExpiresAt = time.Now().Unix() - 1
		_, err := subject.Decode(generate())
		Expect(err).To(MatchError(`token has expired`))
		Expect(err).To(BeAssignableToTypeOf(&jwt.ValidationError{}))
	})

	It("should verify iat", func() {
		claims.IssuedAt = time.Now().Unix() + 1
		_, err := subject.Decode(generate())
		Expect(err).To(MatchError(`issued in the future`))
		Expect(err).To(BeAssignableToTypeOf(&jwt.ValidationError{}))
	})

	It("should verify aud", func() {
		claims.Audience = "other"
		_, err := subject.Decode(generate())
		Expect(err).To(MatchError(`invalid audience claim "other"`))
		Expect(err).To(BeAssignableToTypeOf(&jwt.ValidationError{}))
	})

	It("should verify iss", func() {
		claims.Issuer = "other"
		_, err := subject.Decode(generate())
		Expect(err).To(MatchError(`invalid issuer claim "other"`))
		Expect(err).To(BeAssignableToTypeOf(&jwt.ValidationError{}))
	})

	It("should verify sub", func() {
		claims.Subject = ""
		_, err := subject.Decode(generate())
		Expect(err).To(MatchError(`subject is missing`))
		Expect(err).To(BeAssignableToTypeOf(&jwt.ValidationError{}))
	})

	It("should verify auth time", func() {
		claims.AuthAt = time.Now().Unix() + 1
		_, err := subject.Decode(generate())
		Expect(err).To(MatchError(`auth-time in the future`))
		Expect(err).To(BeAssignableToTypeOf(&jwt.ValidationError{}))
	})
})

func TestSuite(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "firejwt")
}

// --------------------------------------------------------------------

var (
	certKID string
	certPEM string
	privKey *rsa.PrivateKey
)

var _ = BeforeSuite(func() {
	// seed private key
	var err error
	privKey, err = rsa.GenerateKey(rand.Reader, 2048)
	Expect(err).NotTo(HaveOccurred())

	// seed certificate
	now := time.Now()
	template := x509.Certificate{
		SerialNumber:          big.NewInt(2605014480174073526),
		Subject:               pkix.Name{CommonName: "securetoken.system.gserviceaccount.com"},
		NotBefore:             now,
		NotAfter:              now.Add(23775 * time.Minute),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	cert, err := x509.CreateCertificate(rand.Reader, &template, &template, &privKey.PublicKey, privKey)
	Expect(err).NotTo(HaveOccurred())

	// calculate key ID
	kh := sha1.New()
	_, err = kh.Write(cert)
	Expect(err).NotTo(HaveOccurred())
	certKID = hex.EncodeToString(kh.Sum(nil))

	// convert to PEM
	buf := new(bytes.Buffer)
	Expect(pem.Encode(buf, &pem.Block{Type: "CERTIFICATE", Bytes: cert})).To(Succeed())
	certPEM = buf.String()
})
