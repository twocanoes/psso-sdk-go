package psso

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"time"

	"github.com/go-jose/go-jose/v3"
	josecipher "github.com/go-jose/go-jose/v3/cipher"
	"github.com/go-jose/go-jose/v3/jwt"
)

type JWKS struct {
	PK         string
	Category   string
	KID        string
	X          string
	Y          string
	D          string
	Pem        string
	privateKey ecdsa.PrivateKey
}
type TokenBody struct {
	JWECrypto struct {
		Alg string `json:"alg"`
		Enc string `json:"enc"`
		Apv string `json:"apv"`
	} `json:"jwe_crypto"`
	Nonce        string `json:"nonce"`
	RequestNonce string `json:"request_nonce"`
	Scope        string `json:"scope"`
	GrantType    string `json:"grant_type"`
	Iss          string `json:"iss"`
	Password     string `json:"password"`
	Sub          string `json:"sub"`
	Aud          string `json:"aud"`
	Username     string `json:"username"`
	ClientID     string `json:"client_id"`
	RefreshToken string `json:"refresh_token"`
}

type KeyRequestBody struct {
	JWECrypto struct {
		Alg string `json:"alg"`
		Enc string `json:"enc"`
		Apv string `json:"apv"`
	} `json:"jwe_crypto"`
	Exp            int    `json:"exp,omitempty"`
	RequestType    string `json:"request_type"`
	Nonce          string `json:"nonce"`
	Version        string `json:"version"`
	RequestNonce   string `json:"request_nonce"`
	RefreshToken   string `json:"refresh_token"`
	Iss            string `json:"iss"`
	KeyPurpose     string `json:"key_purpose"`
	Sub            string `json:"sub"`
	Username       string `json:"username"`
	Iat            int    `json:"iat,omitempty"`
	Aud            string `json:"aud,omitempty"`
	OtherPublicKey string `json:"other_publickey,omitempty"`
	KeyContext     string `json:"key_context,omitempty"`
}

type KeyResponseBody struct {
	Certificate string `json:"certificate,omitempty"`
	Expires     int    `json:"exp"`
	IssuedAt    int    `json:"iat"`
	KeyContext  string `json:"key_context,omitempty"`
	Key         string `json:"key,omitempty"`
}

type IDTokenClaims struct {
	Exp     int      `json:"exp"`
	Iss     string   `json:"iss"`
	Aud     string   `json:"aud"`
	Iat     int      `json:"iat"`
	Nonce   string   `json:"nonce"`
	Groups  []string `json:"groups"`
	Subject string   `json:"sub"`
	UPN     string   `json:"upn"`
	Name    string   `json:"name"`
	Email   string   `json:"email"`
}

type EPK struct {
	Y       string `json:"y"`
	X       string `json:"x"`
	KeyType string `json:"kty"`
	Curve   string `json:"crv"`
}

type LoginResponseHeader struct {
	Encryption         string `json:"enc"`
	KeyID              string `json:"kid"`
	EphemeralPublicKey EPK    `json:"epk"`
	APU                string `json:"apu"`
	Type               string `json:"typ"`
	Algorithm          string `json:"alg"`
	APV                string `json:"apv"`
}

type LoginResponseBody struct {
	IDToken             string `json:"id_token"`
	RefreshToken        string `json:"refresh_token"`
	RefreshTokenExpires int    `json:"refresh_token_expires_in"`
	TokenType           string `json:"token_type"`
}

type TokenType int

const (
	UserAuth    TokenType = iota
	KeyRequest  TokenType = iota
	KeyExchange TokenType = iota
)

func CreateIDToken(issuer string, aud string, shortname string, fullname string, groups []string, nonce string, email string, upn string) *IDTokenClaims {

	exp := int(time.Now().Add(time.Hour).Unix())
	iat := int(time.Now().Unix())

	return createIDTokenWithTime(issuer, aud, shortname, fullname, groups, nonce, email, upn, exp, iat)
}

func createIDTokenWithTime(issuer string, aud string, shortname string, fullname string, groups []string, nonce string, email string, upn string, exp int, iat int) *IDTokenClaims {
	// build up user information to send back
	returnClaims := &IDTokenClaims{
		Exp:     exp,
		Iat:     iat,
		Iss:     issuer,
		Aud:     aud, // "psso",
		Nonce:   nonce,
		Groups:  groups,
		UPN:     upn,
		Subject: shortname,
		Email:   email,
		Name:    fullname,
	}

	return returnClaims
}
func ECPublicKeyFromPEM(publicKeyPEM string) *ecdsa.PublicKey {

	publicKeyPemBytes := []byte(publicKeyPEM)
	publicKeyBlock, _ := pem.Decode(publicKeyPemBytes)
	publicKey, _ := x509.ParsePKIXPublicKey(publicKeyBlock.Bytes)
	return publicKey.(*ecdsa.PublicKey)

}
func ECPrivateKeyFromPEM(privateKeyPEM string) *ecdsa.PrivateKey {
	pemBytes := []byte(privateKeyPEM)
	pemblock, _ := pem.Decode(pemBytes)
	jwksPrivKey, _ := x509.ParseECPrivateKey(pemblock.Bytes)

	return jwksPrivKey
}
func VerifyJWTAndReturnUserClaims(tokenString string, publicKey any) *TokenBody {

	//take the tokenString sent in and parse it into a Go JWT
	token, err := jwt.ParseSigned(tokenString)

	if err != nil {
		panic(err)
	}
	if token == nil {
		panic(token)
	}

	// pull out the body to verify the signature
	//get a new TokenBody Object
	tokenBody := new(TokenBody)

	//Verify signature and populate tokenBody with claims
	if err = token.Claims(publicKey, &tokenBody); err != nil {
		fmt.Println(err)
		panic(err)
	}
	return tokenBody

}
func VerifyJWTAndReturnKeyRequestClaims(tokenString string, publicKey any) *KeyRequestBody {

	//take the tokenString sent in and parse it into a Go JWT
	token, err := jwt.ParseSigned(tokenString)

	if err != nil {
		panic(err)
	}
	if token == nil {
		panic(token)
	}

	// pull out the body to verify the signature
	//get a new TokenBody Object
	tokenBody := new(KeyRequestBody)

	//Verify signature and populate tokenBody with claims
	if err = token.Claims(publicKey, &tokenBody); err != nil {
		fmt.Println(err)
		panic(err)
	}
	return tokenBody

}

// Sign the ID token
func SignToken(privateKey *ecdsa.PrivateKey, keyID string, idClaims interface{}) string {

	var key jose.JSONWebKey
	key.Algorithm = "ES256"
	key.Use = "sig"
	key.KeyID = keyID
	key.Key = privateKey

	signingKey := jose.SigningKey{Algorithm: jose.SignatureAlgorithm(key.Algorithm), Key: key}
	signingOptions := (&jose.SignerOptions{}).WithHeader("kid", key.KeyID).WithType("JWT")
	signer, err := jose.NewSigner(signingKey, signingOptions)

	if err != nil {
		fmt.Printf("%v", err)
		panic(err)
	}
	token, err := jwt.Signed(signer).Claims(idClaims).CompactSerialize()

	if err != nil {
		fmt.Printf("%v", err)
		panic(err)

	}
	return token
}

func login() {

}
func encyptTokenWithA256GCMWithEphemeralKey(token string, tokenType TokenType, refreshToken string, encryptionKey *ecdsa.PublicKey, apv []byte, nonce []byte, ephermalKey *ecdsa.PrivateKey) string {

	//get apu (inform about the key)
	apu := buildAPU(ephermalKey)

	//generate a symeetric key using info about the ephermal key, info about the key on the receiver side,
	// the key on the service side, and the public key of the the receiver.
	sharedSecret := josecipher.DeriveECDHES("A256GCM", apu, apv, ephermalKey, encryptionKey, 32)

	//user the shared secret to create a cipher that will be used to encrypt the user info.
	cipherBlock, _ := aes.NewCipher(sharedSecret)
	aesgcm, _ := cipher.NewGCM(cipherBlock)
	var jweBody any
	var headerType string

	if tokenType == UserAuth {
		headerType = "platformsso-login-response+jwt"

		jweBody = LoginResponseBody{
			IDToken:             token,
			RefreshToken:        refreshToken,
			RefreshTokenExpires: 60000,
			TokenType:           "Bearer",
		}
		//build up the JWE header so receiver knows how to decrypt.

	} else if tokenType == KeyRequest {
		// headerType = "platformsso-login-response+jwt"

		// priv, key := GenCert(username)

		// jweBody = KeyResponseBody{
		// 	Certificate: base64.RawURLEncoding.EncodeToString(key),
		// 	KeyContext:  base64.RawURLEncoding.EncodeToString(priv),
		// 	IssuedAt:    int(time.Now().Unix()),
		// 	Expires:     int(time.Now().Add(time.Minute * 5).Unix()),
		// }

	} else if tokenType == KeyExchange {
		// headerType = "platformsso-login-response+jwt"

		// jweBody = KeyResponseBody{
		// 	Key:        zBytesB64URL,
		// 	IssuedAt:   int(time.Now().Unix()),
		// 	Expires:    int(time.Now().Add(time.Minute * 5).Unix()),
		// 	KeyContext: tokenClaims.KeyContext,
		// }

	} else {
		panic("bad key type")
	}

	jweBodyCompact, err := json.Marshal(jweBody)
	if err != nil {
		panic(err.Error())
	}

	// the JWE header contains the public key portion of the ephermal key. It is in EPK
	//format so we must create JSON that has X, Y, KeyTyupe, and Curve so receiver can
	//user the public key and the receiver private key to derive the correct shared secret
	//on the receiving end.

	newEPK := &EPK{
		X:       base64.RawURLEncoding.EncodeToString(ephermalKey.X.Bytes()),
		Y:       base64.RawURLEncoding.EncodeToString(ephermalKey.Y.Bytes()),
		KeyType: "EC",
		Curve:   "P-256",
	}
	jweHeaders := LoginResponseHeader{
		Encryption:         "A256GCM",
		EphemeralPublicKey: *newEPK,
		Type:               headerType,
		Algorithm:          "ECDH-ES",
		APU:                base64.RawURLEncoding.EncodeToString(apu),
		APV:                string(apv[:]),
	}

	//convert the headers to JSON
	jweHeadersCompact, _ := json.Marshal(jweHeaders)

	//Encrypt. Include the nonce, body, and headers.
	ciphertext := aesgcm.Seal(nil, nonce, jweBodyCompact, []byte(base64.RawURLEncoding.EncodeToString(jweHeadersCompact)))

	//Returned ciphertext has tag (16 bytes) appended to the encrypted data. Separate them out
	tag := ciphertext[len(ciphertext)-16:]
	ciphertext = ciphertext[:len(ciphertext)-16]

	// build token
	return base64.RawURLEncoding.EncodeToString(jweHeadersCompact) + ".." + base64.RawURLEncoding.EncodeToString(nonce) + "." + base64.RawURLEncoding.EncodeToString(ciphertext) + "." + base64.RawURLEncoding.EncodeToString(tag)
}

// The id token is encrypted with a derived key from the private key from the service.
func EncyptTokenWithA256GCM(idToken string, tokenType TokenType, refreshToken string, encryptionKey *ecdsa.PublicKey, apv []byte) string {

	nonce := make([]byte, 12) //all zeros but should be a random 12 bytes.

	//make an ephermal key
	ephermalKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	return encyptTokenWithA256GCMWithEphemeralKey(idToken, tokenType, refreshToken, encryptionKey, apv, nonce, ephermalKey)
}

// APU has information about the service private key
// PSSO expects the prefix to be APPLE (prepended with the length of 5 of "APPLE"), the X and Y values of the service
// key in X9.63 format with prepended length.
func buildAPU(key *ecdsa.PrivateKey) []byte {
	result := lengthPrefixed([]byte("APPLE"))
	x963 := []byte{4}
	x963 = append(x963, key.X.Bytes()...)
	x963 = append(x963, key.Y.Bytes()...)
	result = append(result, lengthPrefixed(x963)...)
	return result
}

// Create data to data with prepended length
func lengthPrefixed(data []byte) []byte {
	out := make([]byte, len(data)+4)
	binary.BigEndian.PutUint32(out, uint32(len(data)))
	copy(out[4:], data)
	return out
}

// func GenCert(user string) ([]byte, []byte) {

// 	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
// 	if err != nil {
// 		panic(err.Error())
// 	}

// 	template := x509.Certificate{
// 		SerialNumber: big.NewInt(1),
// 		Subject: pkix.Name{
// 			Organization: []string{"JumpCloud Labs"},
// 		},
// 		NotBefore: time.Now(),
// 		NotAfter:  time.Now().Add(time.Hour * 24 * 365),

// 		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
// 		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
// 		BasicConstraintsValid: true,
// 	}

// 	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, publicKey(priv), priv)
// 	if err != nil {
// 	}

// 	out := &bytes.Buffer{}
// 	pem.Encode(out, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
// 	out.Reset()
// 	pem.Encode(out, pemBlockForKey(priv))

// 	return out.Bytes(), derBytes
// }
