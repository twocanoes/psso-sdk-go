package psso

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"time"
)

// JSON Webtoken Key Store. An Asymmetric key for signing and encrypting on the server side.
// this key is used to sign data on the service side and decrypt data from the device side
type JWKS struct {
	PK         string
	Category   string
	KID        string
	X          string
	Y          string
	D          string
	Pem        string
	PrivateKey ecdsa.PrivateKey
}

// Token sent from the device for authenticating the user. PSSO v1.
type IDTokenRequestBody struct {
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

// token sent from the device to request to setup Filevault and keychain unlocking or to actually provide key
// to unlock. PSSO v2
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

// token response body sending back the certificate and encrypted private key in the KeyContext. PSSO v2
type KeyResponseBody struct {
	Certificate string `json:"certificate,omitempty"`
	Expires     int    `json:"exp"`
	IssuedAt    int    `json:"iat"`
	KeyContext  string `json:"key_context,omitempty"`
	Key         string `json:"key,omitempty"`
}

// token claims response to return ID token. PSSO v1
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

// Ephemeral key structure. Used to return the ephemeral public key when encrypting data. PSSO v2.
type EphemeralPublicKey struct {
	Y       string `json:"y"`
	X       string `json:"x"`
	KeyType string `json:"kty"`
	Curve   string `json:"crv"`
}

// header for encrypted response from PSSO v2.
type ResponseHeader struct {
	Encryption         string             `json:"enc"`
	KeyID              string             `json:"kid"`
	EphemeralPublicKey EphemeralPublicKey `json:"epk"`
	APU                string             `json:"apu"`
	Type               string             `json:"typ"`
	Algorithm          string             `json:"alg"`
	APV                string             `json:"apv"`
}

// body of ID token response PSSO v1.
type IDTokenResponseBody struct {
	IDToken             string `json:"id_token"`
	RefreshToken        string `json:"refresh_token"`
	RefreshTokenExpires int    `json:"refresh_token_expires_in"`
	TokenType           string `json:"token_type"`
}

// CreateIDTokenResponse
// Purpose: Create an JWE token to a request for an ID Token. PSSO v1.
// Inputs:
// shortname: string. user short name
// fullname: string. user full name
// groups: array of strings. Groups that user is member of.
// email: string. user email
// upn: string. user principal name
// refreshToken: string. A string that can be sent back in a subsequent request
// to authenticate without username or password.
// servicePrivateKey: pointer to an ecdsa PrivateKey. Used to sign response.
// serviceKeyID: string. Key id of servicePrivateKey.
// devicePublicKey: pointer to device encryption ecdsa PublicKey. used to encrypt response.
//
// Return Value: string. JWT token with user ID info in dot notation. Example: "eyJlbmMiOiJBMjU2R0NNIiwia2lkIjoiIiwiZXBrIjp7InkiOiJtYU9RNWRhUVJQWHhTVUZLTmtOSmFOckUzYnlTbFVvTWNoNWt5RVpKUEpJIiwieCI6IjRETFRKNDVtb3pmVjJLTDRJUUJUWGN2R29HSmc0UjRVaDdwRTE5aHVmUzgiLCJrdHkiOiJFQyIsImNydiI6IlAtMjU2In0sImFwdSI6IkFBQUFCVUZRVUV4RkFBQUFRUVRnTXRNbmptYWpOOVhZb3ZnaEFGTmR5OGFnWW1EaEhoU0h1a1RYMkc1OUw1bWprT1hXa0VUMThVbEJTalpEU1dqYXhOMjhrcFZLREhJZVpNaEdTVHlTIiwidHlwIjoicGxhdGZvcm1zc28tbG9naW4tcmVzcG9uc2Urand0IiwiYWxnIjoiRUNESC1FUyIsImFwdiI6IkFBQUFCVUZ3Y0d4bEFBQUFRUVRzVDhYT1dKTkZBRnNjOXlBR21JRUJYak1YLWF6NG5ZcGJ3Qkh1YXZTT3hLQ1IwS2VJVDFyUXpCT1dGcWticmx5MTlEdDJUaFRYd29VZWFBcFU0ZFZTQUFBQUpEZEVOekZHT0VJMExURkVSVGN0TkVZNE9TMDRRek5CTFRJeE1FUXhOakZHTXpoQlF3In0..m3jFtRsFFYCJfEX6.hFd4vIvPfRf87NrOfYUoxIWWevc4cEyj9DOA4w6OXi5rfUeNg0KX9Vwa7ZqAgaHkiO9sdD1NaCNRdZ0Q5rICoNBWEbHKpTFvOpp7j_Aq2hbxwHZV62JG63keMPT17iQ68v7-mN0NB7LXLuhpx95zIQxg5xTTu0JcrsAu1mAvB7iWRBBDhgnk6YtMzlRrMiuuVE-rjx7fSir4ri2f9Km4zvwE6VtDMO6FnwfOMO0TB2wvFEFIkWHpEp0dpgnyLCoK0UeaCbQ0oWVNpOdgNk6vWXak6c9wvhjXJlo4kVfdV5yEQlhL6WquiN9KeEhFro_4BjyBON1Q6_hU8XzzbNtZFyjC31R22ClBNnVG4Z_YaZ67bCTbLijXxFGjsGeDyFYQJWb1p62kJt5Ba3wd9dzV5xer8L86q5L2ZAJizag11kg3mZZaGa_OgrEuew2NlcrwgLhfiroc4fs-p4gfdf3N9ThJIpSQGqvtK0IXE_XzaU9EVICozI__ed9tibsaGrqtpyE4bXK1WkuxLgJI55GbABypS6grdr-gcKjcFB3su_Y--j0ovjpy1hgQahYmYLz5TniTgE7yjmMEEk_arroSpOTxamVx3WbR5ukEO1-PYp9iPaL7jeVxohS9dlVwsYyao5LIvU3Bu4PK4PbwhzBvXhwUp9pBgqjFbdJ44kIftmKNy2obocbdR7t2ZiibkwNUXbY_bYJcy28KZ6QRei1Nl6LvdzHI_maHlIFiVp3nYmD2YQYyntZFvKP-T0GlL0LgxOJr6_vswQ6DvKuJXvs4JjxJAEHrX5yWsfPjQc9l3iTGgb6vPGgh0nx26JND71Ij.6dI5jzJ-ouTEcvbfH34ixw

func CreateIDTokenResponse(requestClaims IDTokenRequestBody, shortname string, fullname string, groups []string, email string, upn string, refreshToken string, servicePrivateKey *ecdsa.PrivateKey, serviceKeyID string, devicePublicKey *ecdsa.PublicKey) string {

	// build up user information to send back
	returnClaims := &IDTokenClaims{
		Exp:     int(time.Now().Unix()),
		Iat:     int(time.Now().Add(time.Minute * 5).Unix()),
		Iss:     requestClaims.Iss,
		Aud:     requestClaims.Aud, // "psso",
		Nonce:   requestClaims.Aud,
		Groups:  groups,
		UPN:     upn,
		Subject: shortname,
		Email:   email,
		Name:    fullname,
	}

	signedReturnClaims := SignClaims(servicePrivateKey, serviceKeyID, returnClaims)

	jweBody := IDTokenResponseBody{
		IDToken:             signedReturnClaims,
		RefreshToken:        refreshToken,
		RefreshTokenExpires: 60000,
		TokenType:           "Bearer",
	}
	jweBodyCompact, _ := json.Marshal(jweBody)

	jwe := EncryptTokenWithA256GCM(jweBodyCompact, devicePublicKey, requestClaims.JWECrypto.Apv)
	return jwe
}

// CreateKeyRequestResponseClaims PSSO v2
// Purpose: When a KeyRequest JWT is requested (filevault/keychain keying setup), these claims are sent back. A certificate is returned. This certificate is used for persistent token authentication on the device.
// Input:
// requestClaims: KeyRequestBody. Incoming request. Used to get the Apv from the request to send back.
// devicePublicKey: pointer to device public key. Used to encrypted response
// Return Value:
// string. Encrypted JWT (JWE) in dot notation.

func CreateKeyRequestResponseClaims(requestClaims KeyRequestBody, devicePublicKey *ecdsa.PublicKey) string {
	certificatePrivateKey, certificate := genCert(requestClaims.Username)

	jweBody := KeyResponseBody{
		Certificate: base64.RawURLEncoding.EncodeToString(certificate),
		KeyContext:  base64.RawURLEncoding.EncodeToString(certificatePrivateKey),
		IssuedAt:    int(time.Now().Unix()),
		Expires:     int(time.Now().Add(time.Minute * 5).Unix()),
	}
	jweBodyCompact, _ := json.Marshal(jweBody)

	jwe := EncryptTokenWithA256GCM(jweBodyCompact, devicePublicKey, requestClaims.JWECrypto.Apv)
	return jwe

}

// CreateKeyExchangeResponseClaims PSSO v2
// Purpose: When a Unlock JWT is requested (filevault/keychain keying unlock), these claims are sent back.
// Input:
// requestClaims: KeyRequestBody. Incoming request. Used to get the Apv from the request to send back.
// devicePublicKey: pointer to device public key. Used to encrypted response
// Return Value:
// string. Encrypted JWT (JWE) in dot notation.

func CreateKeyExchangeResponseClaims(requestClaims KeyRequestBody, devicePublicKey *ecdsa.PublicKey) string {

	// When the unlock operation is requested, an ephemeral key is generated on the device side and used to generate
	// a secret that can be used to unlock FV or keychain. The service side uses the public key of this ephemeral key
	// and the private key associated with the certificate to derive the secret. This secret is then sent back encrypted
	// to unlock the keychain or filevault.

	// Get the private key used to decrypt from the keycontext.
	keyExchangePrivateKeyPEMString, _ := base64.RawURLEncoding.DecodeString(requestClaims.KeyContext)
	keyExchangePrivateKeyBlock, _ := pem.Decode(keyExchangePrivateKeyPEMString)

	//persistant token key
	keyExchangePrivateKey, err := x509.ParseECPrivateKey(keyExchangePrivateKeyBlock.Bytes)
	if err != nil {
		fmt.Println("error rehydrating the device private key")
	}

	//get the public key from the device side
	//public key from FV / Keychain
	deviceEphemeralPublicKey, err := base64.StdEncoding.DecodeString(requestClaims.OtherPublicKey)

	if err != nil {
		panic(err.Error())
	}

	//take device public key (x, y values) and the private key associated with the certificate and get the secret (z)
	// base64 encode this.
	x, y := elliptic.Unmarshal(elliptic.P256(), deviceEphemeralPublicKey)
	z, _ := keyExchangePrivateKey.Curve.ScalarMult(x, y, keyExchangePrivateKey.D.Bytes())
	zBytes := z.Bytes()
	zBytesB64URL := base64.StdEncoding.EncodeToString(zBytes)

	//put the z vaule in the body
	jweBody := KeyResponseBody{
		Key:        zBytesB64URL,
		KeyContext: requestClaims.KeyContext,
		IssuedAt:   int(time.Now().Unix()),
		Expires:    int(time.Now().Add(time.Minute * 5).Unix()),
	}

	//serialize the body to prepare for encryption
	jweBodyCompact, _ := json.Marshal(jweBody)

	//encrypt with the device public key
	jwe := EncryptTokenWithA256GCM(jweBodyCompact, devicePublicKey, requestClaims.JWECrypto.Apv)
	return jwe
}
