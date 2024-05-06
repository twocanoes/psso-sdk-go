package psso

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"testing"
)

// Incoming JWT in /token for PSSO v1
const incomingPSSOV1JWT = "ewogICJ0eXAiIDogInBsYXRmb3Jtc3NvLWxvZ2luLXJlcXVlc3Qrand0IiwKICAiYWxnIiA6ICJFUzI1NiIsCiAgImtpZCIgOiAiZitSbktXcmlra3NUUU5nQnVaaEQ4b01WUkZWUEJicFJTc3JteWJmdkpDMD0iCn0.ewogICJqd2VfY3J5cHRvIiA6IHsKICAgICJhbGciIDogIkVDREgtRVMiLAogICAgImVuYyIgOiAiQTI1NkdDTSIsCiAgICAiYXB2IiA6ICJBQUFBQlVGd2NHeGxBQUFBUVFUc1Q4WE9XSk5GQUZzYzl5QUdtSUVCWGpNWC1hejRuWXBid0JIdWF2U094S0NSMEtlSVQxclF6Qk9XRnFrYnJseTE5RHQyVGhUWHdvVWVhQXBVNGRWU0FBQUFKRGRFTnpGR09FSTBMVEZFUlRjdE5FWTRPUzA0UXpOQkxUSXhNRVF4TmpGR016aEJRdyIKICB9LAogICJleHAiIDogMTcxMzk5ODEwMSwKICAibm9uY2UiIDogIjdENzFGOEI0LTFERTctNEY4OS04QzNBLTIxMEQxNjFGMzhBQyIsCiAgInJlcXVlc3Rfbm9uY2UiIDogIk1TZkVIZ0ROY0ZkSDlHMk84OXVGQlJvQURlSXVqQkxCV0QrMzVpM3MvZWM9IiwKICAic2NvcGUiIDogIm9wZW5pZCBvZmZsaW5lX2FjY2VzcyB1cm46YXBwbGU6cGxhdGZvcm1zc28iLAogICJncmFudF90eXBlIiA6ICJwYXNzd29yZCIsCiAgImlzcyIgOiAicHNzbyIsCiAgInBhc3N3b3JkIiA6ICJ0d29jYW5vZXMiLAogICJzdWIiIDogImxpekB0d29jYW5vZXMuY29tIiwKICAiYW1yIiA6IFsKICAgICJwd2QiCiAgXSwKICAiY2xhaW1zIiA6IHsKICAgICJpZF90b2tlbiIgOiB7CiAgICAgICJncm91cHMiIDogewogICAgICAgICJ2YWx1ZXMiIDogWwogICAgICAgICAgIm5ldC1hZG1pbiIsCiAgICAgICAgICAibm90LWFkbWluIiwKICAgICAgICAgICJzb2Z0d2FyZS1pbnN0YWxsIgogICAgICAgIF0KICAgICAgfQogICAgfQogIH0sCiAgImF1ZCIgOiAiaHR0cHM6Ly9pZHAudHdvY2Fub2VzLmNvbS9wZXN0by90b2tlbiIsCiAgInVzZXJuYW1lIiA6ICJsaXpAdHdvY2Fub2VzLmNvbSIsCiAgImNsaWVudF9pZCIgOiAicHNzbyIsCiAgImlhdCIgOiAxNzEzOTk3ODAxCn0.7wtZJc-G6Trqs7dqxuqjh41mdnaCZWuH2Ywqqbw-Yhb5b3OHe70EmXdOX17l83qTlbzG8cVMVMZltc1pT-H35w"

// Incoming JWT in /token for PSSO v2

// device signing key sent during registration. Used to verify JWT.
var devicePublicKeyPem = `
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAELOFf3yRXGWbDaS339MS2ehFfkC7x
oxR6sWdoIVD5bGcEav9WkZfNFJ1ye4iYqpBB7i0Z/rJuCUQXcXq+OyKZHQ==
-----END PUBLIC KEY-----
		`

// convert key to something usable in Go
// var deviceSigningPublicKeyBlock, _ = pem.Decode(devicePublicKeyPemBytes)
// var deviceSigningPublicKey, _ = x509.ParsePKIXPublicKey(deviceSigningPublicKeyBlock.Bytes)

func staticKeystore() (*JWKS, error) {
	jwks := new(JWKS)
	jwks.D = "kwL0qQQhZWnyJRBoI4e47K_tehCfVuoJsQmZAZPXaBs"
	jwks.KID = "nWRIaub3DgG3w-5vlY-gZxmbPVHsa3Vddph_dBnI1Jc"
	jwks.Pem = `
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIJMC9KkEIWVp8iUQaCOHuOyv7XoQn1bqCbEJmQGT12gboAoGCCqGSM49
AwEHoUQDQgAEnIrkBzeNCAHBGSCTs4lbDGBn4yN7phOkG7XoPFMDykaK6v8S1PlI
2GeXoP4vML+OYOOtN4QRBTxb2abdP103SQ==
-----END EC PRIVATE KEY-----
`

	pemBytes := []byte(jwks.Pem)
	pemblock, p := pem.Decode(pemBytes)
	if p == nil {

		return nil, fmt.Errorf("staticKeystore: bad PEM")

	}
	jwkPrivKey, err := x509.ParseECPrivateKey(pemblock.Bytes)
	if err != nil {
		fmt.Printf("%v", err)
		return nil, err
	}
	jwks.PrivateKey = *jwkPrivKey

	jwks.X = "nIrkBzeNCAHBGSCTs4lbDGBn4yN7phOkG7XoPFMDykY"
	jwks.Y = "iur_EtT5SNhnl6D-LzC_jmDjrTeEEQU8W9mm3T9dN0k"

	return jwks, nil
}

func TestPSSOV1(t *testing.T) {

	deviceSigningPublicKey, err := ECPublicKeyFromPEM(devicePublicKeyPem)
	if err != nil {
		t.FailNow()
	}

	//Verifying incoming JWT signature with deviceSigningPublicKey, pull out username and password from JWT and compare against known valid
	// username and password, create an ID token and refresh tokena and send back JWE (encrypted JWT)

	//get user claims. If signature is invalid, it will not return.
	userClaims, userTokenHeader, err := VerifyJWTAndReturnUserClaims(incomingPSSOV1JWT, deviceSigningPublicKey)

	if err != nil {
		t.FailNow()
	}

	fmt.Println(userTokenHeader)
	//get the username and password sent in thte request
	claimUsername := userClaims.Username
	claimPassword := userClaims.Password

	// compare with what is passed in
	if claimUsername != "liz@twocanoes.com" || claimPassword != "twocanoes" {

		fmt.Println("invalid username or password")
		t.FailNow()
	}
	//encrypt the signed data. Include the APV from the sent in claims and the refresh token. The keystore private key is
	//sent in to generate a shared secret used to encrypt the data.
	// jwe := EncyptIDTokenWithA256GCM(signedToken, "refresh", deviceSigningPublicKey, []byte(userClaims.JWECrypto.Apv))

	jwksKeystore, err := staticKeystore()

	if err != nil {
		t.FailNow()

	}
	jwksPrivateKey := jwksKeystore.PrivateKey
	jwe, err := CreateIDTokenResponse("https://idp.twocanoes.com/psso", *userClaims, "liz", "Liz Appleseed", []string{"admin"}, "liz@twocanoes.com", "liz@twocanoes.com", "refresh", &jwksPrivateKey, jwksKeystore.KID, deviceSigningPublicKey)

	if err != nil {
		t.FailNow()
	}
	fmt.Println(jwe)

}
func TestPSSOV2GenerateCert(t *testing.T) {
	incomingPSSOV2GenerateCertJWT := "ewogICJ0eXAiIDogInBsYXRmb3Jtc3NvLWtleS1yZXF1ZXN0K2p3dCIsCiAgImFsZyIgOiAiRVMyNTYiLAogICJraWQiIDogImYrUm5LV3Jpa2tzVFFOZ0J1WmhEOG9NVlJGVlBCYnBSU3NybXliZnZKQzA9Igp9.ewogICJqd2VfY3J5cHRvIiA6IHsKICAgICJhbGciIDogIkVDREgtRVMiLAogICAgImVuYyIgOiAiQTI1NkdDTSIsCiAgICAiYXB2IiA6ICJBQUFBQlVGd2NHeGxBQUFBUVFUc1Q4WE9XSk5GQUZzYzl5QUdtSUVCWGpNWC1hejRuWXBid0JIdWF2U094S0NSMEtlSVQxclF6Qk9XRnFrYnJseTE5RHQyVGhUWHdvVWVhQXBVNGRWU0FBQUFKRGt6TVRkRk9ERXdMVU0xUlRZdE5ERTJSQzFCUVRRNExUTTFNRU0zTlRBM05VUkVNZyIKICB9LAogICJleHAiIDogMTcxMzk5NzE1NCwKICAicmVxdWVzdF90eXBlIiA6ICJrZXlfcmVxdWVzdCIsCiAgIm5vbmNlIiA6ICI5MzE3RTgxMC1DNUU2LTQxNkQtQUE0OC0zNTBDNzUwNzVERDIiLAogICJ2ZXJzaW9uIiA6ICIxLjAiLAogICJyZXF1ZXN0X25vbmNlIiA6ICI4ekpnVEwrNFJKMFBENWpnZTg0MUloSEh2TjlWZ3JrUGJNTFNLZkttd2k4PSIsCiAgInJlZnJlc2hfdG9rZW4iIDogImI0ZjQ4ODUwLWZhZmItNGMyZi1iYTliLTQ3MmIwNjcxODk4MyIsCiAgImlzcyIgOiAicHNzbyIsCiAgImtleV9wdXJwb3NlIiA6ICJ1c2VyX3VubG9jayIsCiAgInN1YiIgOiAiamFwcGxlc2VlZEB0d29jYW5vZXMuY29tIiwKICAidXNlcm5hbWUiIDogImphcHBsZXNlZWRAdHdvY2Fub2VzLmNvbSIsCiAgImlhdCIgOiAxNzEzOTk2ODU0Cn0.VeRMvt9N86dAiMUCbumKYo4nqniPxVJfnwc_lz1-X7Q2tyg-lXoiRALYP_CLCnzwLTAzBq4jFRXX3kLeEVyqWQ"

	PSSOV2(t, incomingPSSOV2GenerateCertJWT)

}
func TestPSSOV2KeyExchange(t *testing.T) {
	incomingPSSOV2HSMJWT := "ewogICJ0eXAiIDogInBsYXRmb3Jtc3NvLWtleS1yZXF1ZXN0K2p3dCIsCiAgImFsZyIgOiAiRVMyNTYiLAogICJraWQiIDogImYrUm5LV3Jpa2tzVFFOZ0J1WmhEOG9NVlJGVlBCYnBSU3NybXliZnZKQzA9Igp9.ewogICJqd2VfY3J5cHRvIiA6IHsKICAgICJhbGciIDogIkVDREgtRVMiLAogICAgImVuYyIgOiAiQTI1NkdDTSIsCiAgICAiYXB2IiA6ICJBQUFBQlVGd2NHeGxBQUFBUVFUc1Q4WE9XSk5GQUZzYzl5QUdtSUVCWGpNWC1hejRuWXBid0JIdWF2U094S0NSMEtlSVQxclF6Qk9XRnFrYnJseTE5RHQyVGhUWHdvVWVhQXBVNGRWU0FBQUFKREU1T1Rrd1JrVTRMVEU1UVRRdE5FSkJPQzA0TlVWRkxVUXpRall6UVRnd05rSkNNQSIKICB9LAogICJleHAiIDogMTcxMzk5NzE1NCwKICAicmVxdWVzdF90eXBlIiA6ICJrZXlfZXhjaGFuZ2UiLAogICJub25jZSIgOiAiMTk5OTBGRTgtMTlBNC00QkE4LTg1RUUtRDNCNjNBODA2QkIwIiwKICAidmVyc2lvbiIgOiAiMS4wIiwKICAicmVxdWVzdF9ub25jZSIgOiAiWTUvU0ppaFNSdjhBTm1Ja2F5WUNBeU1Yam15VHF4SnJpUndhRVpkR2Nycz0iLAogICJvdGhlcl9wdWJsaWNrZXkiIDogIkJDQngyWitVby9kRmVYbk1TbDA4YkZzbFdDMEs1KzhzRzlzWmNOcXJRT2xibXFUUDRnd1BSWVc4dmorTjNnQk45R3ZoMnVidVF5alVWTEE3Yk12K3Rzaz0iLAogICJyZWZyZXNoX3Rva2VuIiA6ICJiNGY0ODg1MC1mYWZiLTRjMmYtYmE5Yi00NzJiMDY3MTg5ODMiLAogICJrZXlfY29udGV4dCIgOiAiTFMwdExTMUNSVWRKVGlCRlF5QlFVa2xXUVZSRklFdEZXUzB0TFMwdENrMUlZME5CVVVWRlNVSlBObEFyVjNaaVQwUkhSRzFMU0ZsVU5rNXFZa3ROZWxvclowbFBiak5EWlhaeVIyVllSa2wwSzNSdlFXOUhRME54UjFOTk5Ea0tRWGRGU0c5VlVVUlJaMEZGV210RVJXcHJUM0UzUTFjMlRIRkVjVTFGVXpsVVFrSTFiaXQ0YUVJdlVDc3libnBpYVVsclV6QnJWazUxWm5KamVEZFFad28yUjFOaGFWaDFkekpZV0RsRmJubG1UMFJPZDNwNWQzbzFOMkoyTkhRek0yaFJQVDBLTFMwdExTMUZUa1FnUlVNZ1VGSkpWa0ZVUlNCTFJWa3RMUzB0TFFvIiwKICAiaXNzIiA6ICJwc3NvIiwKICAia2V5X3B1cnBvc2UiIDogInVzZXJfdW5sb2NrIiwKICAic3ViIiA6ICJqYXBwbGVzZWVkQHR3b2Nhbm9lcy5jb20iLAogICJ1c2VybmFtZSIgOiAiamFwcGxlc2VlZEB0d29jYW5vZXMuY29tIiwKICAiaWF0IiA6IDE3MTM5OTY4NTQKfQ.8cIB_k54_pwqZmjikqy-HIAicX_ku5xnAW6lAycFUtKvm0qiK1oCdhkMxnZGxiCPlBb2rE1e2uXYuNKGjxM0Wg"

	PSSOV2(t, incomingPSSOV2HSMJWT)

}
func PSSOV2(t *testing.T, requestJWT string) {
	deviceSigningPublicKey, err := ECPublicKeyFromPEM(devicePublicKeyPem)

	if err != nil {
		t.FailNow()
	}

	//Verifying incoming JWT signatur with deviceSigningPublicKey, pull out username and password from JWT and compare against known valid
	// username and password, create an ID token and refresh tokena and send back JWE (encrypted JWT)
	//get user claims. If signature is invalid, it will not return.
	keyRequestClaims, err := VerifyJWTAndReturnKeyRequestClaims(requestJWT, deviceSigningPublicKey)

	if err != nil {
		t.FailNow()

	}

	if keyRequestClaims.RequestType == "key_request" {

		jwe, err := CreateKeyRequestResponseClaims(*keyRequestClaims, deviceSigningPublicKey, []byte("testkey"))
		if err != nil {
			t.FailNow()
		}
		fmt.Println(jwe)

	} else if keyRequestClaims.KeyPurpose == "user_unlock" {

		deviceSigningPublicKey, err := ECPublicKeyFromPEM(devicePublicKeyPem)
		if err != nil {
			t.FailNow()
		}

		jwe, err := CreateKeyExchangeResponseClaims(*keyRequestClaims, deviceSigningPublicKey, []byte("testkey"))

		if err != nil {
			t.FailNow()
		}
		fmt.Println(jwe)
	} else {
		t.FailNow()
	}

}
