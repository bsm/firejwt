package firejwt_test

import (
	"crypto/rsa"
	"encoding/json"
	"io/ioutil"
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

	const kid = "e5a91d9f39fa4de254a1e89df00f05b7e248b985"

	decode := func(method jwt.SigningMethod, claims *jwt.StandardClaims) (*jwt.Token, error) {
		src := jwt.NewWithClaims(method, claims)
		src.Header["kid"] = kid

		str, err := src.SignedString(privKey)
		Expect(err).NotTo(HaveOccurred())

		return subject.Decode(str)
	}

	BeforeEach(func() {
		server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("expires", "Mon, 20 Jan 2020 23:40:59 GMT")
			json.NewEncoder(w).Encode(map[string]string{
				kid: string(certPEM),
			})
		}))

		var err error
		subject, err = firejwt.New(&firejwt.Options{URL: server.URL})
		Expect(err).NotTo(HaveOccurred())
	})

	AfterEach(func() {
		subject.Stop()
	})

	It("should refresh on init", func() {
		Expect(subject.ExpTime()).To(BeTemporally("==", time.Date(2020, 1, 20, 23, 40, 59, 0, time.UTC)))
	})

	It("should decode tokens", func() {
		token, err := decode(jwt.SigningMethodRS256, &jwt.StandardClaims{
			Subject:   "me@example.com",
			Audience:  "you",
			Issuer:    "me",
			ExpiresAt: time.Now().Add(time.Hour).Unix(),
		})
		Expect(err).NotTo(HaveOccurred())
		Expect(token.Valid).To(BeTrue())
		Expect(token.Claims).To(HaveKeyWithValue("sub", "me@example.com"))
	})

	It("should reject bad tokens", func() {
		_, err := subject.Decode("BADTOKEN")
		Expect(err).To(MatchError(`token contains an invalid number of segments`))
	})

	It("should reject expired tokens", func() {
		_, err := decode(jwt.SigningMethodRS256, &jwt.StandardClaims{
			Subject:   "me@example.com",
			ExpiresAt: time.Now().Add(-time.Minute).Unix(),
		})
		Expect(err).To(MatchError(`Token is expired`))
	})
})

func TestSuite(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "firejwt")
}

// --------------------------------------------------------------------

var (
	certPEM []byte
	privKey *rsa.PrivateKey
)

var _ = BeforeSuite(func() {
	var err error

	certPEM, err = ioutil.ReadFile("testdata/cert.pem")
	Expect(err).NotTo(HaveOccurred())

	privPEM, err := ioutil.ReadFile("testdata/priv.pem")
	Expect(err).NotTo(HaveOccurred())

	privKey, err = jwt.ParseRSAPrivateKeyFromPEM(privPEM)
	Expect(err).NotTo(HaveOccurred())
})
