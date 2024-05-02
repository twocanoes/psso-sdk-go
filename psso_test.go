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
const incomingPSSOV2GenerateCertJWT = "ewogICJ0eXAiIDogInBsYXRmb3Jtc3NvLWtleS1yZXF1ZXN0K2p3dCIsCiAgImFsZyIgOiAiRVMyNTYiLAogICJraWQiIDogImYrUm5LV3Jpa2tzVFFOZ0J1WmhEOG9NVlJGVlBCYnBSU3NybXliZnZKQzA9Igp9.ewogICJqd2VfY3J5cHRvIiA6IHsKICAgICJhbGciIDogIkVDREgtRVMiLAogICAgImVuYyIgOiAiQTI1NkdDTSIsCiAgICAiYXB2IiA6ICJBQUFBQlVGd2NHeGxBQUFBUVFUc1Q4WE9XSk5GQUZzYzl5QUdtSUVCWGpNWC1hejRuWXBid0JIdWF2U094S0NSMEtlSVQxclF6Qk9XRnFrYnJseTE5RHQyVGhUWHdvVWVhQXBVNGRWU0FBQUFKRGt6TVRkRk9ERXdMVU0xUlRZdE5ERTJSQzFCUVRRNExUTTFNRU0zTlRBM05VUkVNZyIKICB9LAogICJleHAiIDogMTcxMzk5NzE1NCwKICAicmVxdWVzdF90eXBlIiA6ICJrZXlfcmVxdWVzdCIsCiAgIm5vbmNlIiA6ICI5MzE3RTgxMC1DNUU2LTQxNkQtQUE0OC0zNTBDNzUwNzVERDIiLAogICJ2ZXJzaW9uIiA6ICIxLjAiLAogICJyZXF1ZXN0X25vbmNlIiA6ICI4ekpnVEwrNFJKMFBENWpnZTg0MUloSEh2TjlWZ3JrUGJNTFNLZkttd2k4PSIsCiAgInJlZnJlc2hfdG9rZW4iIDogImI0ZjQ4ODUwLWZhZmItNGMyZi1iYTliLTQ3MmIwNjcxODk4MyIsCiAgImlzcyIgOiAicHNzbyIsCiAgImtleV9wdXJwb3NlIiA6ICJ1c2VyX3VubG9jayIsCiAgInN1YiIgOiAiamFwcGxlc2VlZEB0d29jYW5vZXMuY29tIiwKICAidXNlcm5hbWUiIDogImphcHBsZXNlZWRAdHdvY2Fub2VzLmNvbSIsCiAgImlhdCIgOiAxNzEzOTk2ODU0Cn0.VeRMvt9N86dAiMUCbumKYo4nqniPxVJfnwc_lz1-X7Q2tyg-lXoiRALYP_CLCnzwLTAzBq4jFRXX3kLeEVyqWQ"

const incomingPSSOV2HSMJWT = "ewogICJ0eXAiIDogInBsYXRmb3Jtc3NvLWtleS1yZXF1ZXN0K2p3dCIsCiAgImFsZyIgOiAiRVMyNTYiLAogICJraWQiIDogImYrUm5LV3Jpa2tzVFFOZ0J1WmhEOG9NVlJGVlBCYnBSU3NybXliZnZKQzA9Igp9.ewogICJqd2VfY3J5cHRvIiA6IHsKICAgICJhbGciIDogIkVDREgtRVMiLAogICAgImVuYyIgOiAiQTI1NkdDTSIsCiAgICAiYXB2IiA6ICJBQUFBQlVGd2NHeGxBQUFBUVFUc1Q4WE9XSk5GQUZzYzl5QUdtSUVCWGpNWC1hejRuWXBid0JIdWF2U094S0NSMEtlSVQxclF6Qk9XRnFrYnJseTE5RHQyVGhUWHdvVWVhQXBVNGRWU0FBQUFKREU1T1Rrd1JrVTRMVEU1UVRRdE5FSkJPQzA0TlVWRkxVUXpRall6UVRnd05rSkNNQSIKICB9LAogICJleHAiIDogMTcxMzk5NzE1NCwKICAicmVxdWVzdF90eXBlIiA6ICJrZXlfZXhjaGFuZ2UiLAogICJub25jZSIgOiAiMTk5OTBGRTgtMTlBNC00QkE4LTg1RUUtRDNCNjNBODA2QkIwIiwKICAidmVyc2lvbiIgOiAiMS4wIiwKICAicmVxdWVzdF9ub25jZSIgOiAiWTUvU0ppaFNSdjhBTm1Ja2F5WUNBeU1Yam15VHF4SnJpUndhRVpkR2Nycz0iLAogICJvdGhlcl9wdWJsaWNrZXkiIDogIkJDQngyWitVby9kRmVYbk1TbDA4YkZzbFdDMEs1KzhzRzlzWmNOcXJRT2xibXFUUDRnd1BSWVc4dmorTjNnQk45R3ZoMnVidVF5alVWTEE3Yk12K3Rzaz0iLAogICJyZWZyZXNoX3Rva2VuIiA6ICJiNGY0ODg1MC1mYWZiLTRjMmYtYmE5Yi00NzJiMDY3MTg5ODMiLAogICJrZXlfY29udGV4dCIgOiAiTFMwdExTMUNSVWRKVGlCRlF5QlFVa2xXUVZSRklFdEZXUzB0TFMwdENrMUlZME5CVVVWRlNVSlBObEFyVjNaaVQwUkhSRzFMU0ZsVU5rNXFZa3ROZWxvclowbFBiak5EWlhaeVIyVllSa2wwSzNSdlFXOUhRME54UjFOTk5Ea0tRWGRGU0c5VlVVUlJaMEZGV210RVJXcHJUM0UzUTFjMlRIRkVjVTFGVXpsVVFrSTFiaXQ0YUVJdlVDc3libnBpYVVsclV6QnJWazUxWm5KamVEZFFad28yUjFOaGFWaDFkekpZV0RsRmJubG1UMFJPZDNwNWQzbzFOMkoyTkhRek0yaFJQVDBLTFMwdExTMUZUa1FnUlVNZ1VGSkpWa0ZVUlNCTFJWa3RMUzB0TFFvIiwKICAiaXNzIiA6ICJwc3NvIiwKICAia2V5X3B1cnBvc2UiIDogInVzZXJfdW5sb2NrIiwKICAic3ViIiA6ICJqYXBwbGVzZWVkQHR3b2Nhbm9lcy5jb20iLAogICJ1c2VybmFtZSIgOiAiamFwcGxlc2VlZEB0d29jYW5vZXMuY29tIiwKICAiaWF0IiA6IDE3MTM5OTY4NTQKfQ.8cIB_k54_pwqZmjikqy-HIAicX_ku5xnAW6lAycFUtKvm0qiK1oCdhkMxnZGxiCPlBb2rE1e2uXYuNKGjxM0Wg"

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

func staticKeystore() *JWKS {
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
	pemblock, _ := pem.Decode(pemBytes)
	jwkPrivKey, err := x509.ParseECPrivateKey(pemblock.Bytes)
	if err != nil {
		fmt.Printf("%v", err)
		panic(err)
	}
	jwks.privateKey = *jwkPrivKey

	jwks.X = "nIrkBzeNCAHBGSCTs4lbDGBn4yN7phOkG7XoPFMDykY"
	jwks.Y = "iur_EtT5SNhnl6D-LzC_jmDjrTeEEQU8W9mm3T9dN0k"

	return jwks
}

func TestPSSOV1(t *testing.T) {

	deviceSigningPublicKey := ECPublicKeyFromPEM(devicePublicKeyPem)

	//Verifying incoming JWT signatur with deviceSigningPublicKey, pull out username and password from JWT and compare against known valid
	// username and password, create an ID token and refresh tokena and send back JWE (encrypted JWT)

	//get user claims. If signature is invalid, it will not return.
	userClaims := VerifyJWTAndReturnUserClaims(incomingPSSOV1JWT, deviceSigningPublicKey)

	if userClaims == nil {
		t.Fail()
	}

	//get the username and password sent in thte request
	claimUsername := userClaims.Username
	claimPassword := userClaims.Password

	// compare with what is passed in
	if claimUsername != "liz@twocanoes.com" || claimPassword != "twocanoes" {

		fmt.Println("invalid username or password")
		t.Fail()
	}

	userIDToken := createIDTokenWithTime("https://twocanoes.com/psso", "psso", "liz", "Liz Appleseed", []string{"admin"}, userClaims.Nonce, "liz@twocanoes.com", "liz@twocanoes.com", 1714516298, 1714516298)

	//sign it with the services private key and the keyid to the key that signed it.
	signedToken := SignToken(&staticKeystore().privateKey, staticKeystore().KID, userIDToken)

	jwks := staticKeystore()
	jwksPrivKey := ECPrivateKeyFromPEM(jwks.Pem)

	//signedToken: eyJhbGciOiJFUzI1NiIsImtpZCI6Im5XUklhdWIzRGdHM3ctNXZsWS1nWnhtYlBWSHNhM1ZkZHBoX2RCbkkxSmMiLCJ0eXAiOiJKV1QifQ.eyJhdWQiOiJwc3NvIiwiZW1haWwiOiJsaXpAdHdvY2Fub2VzLmNvbSIsImV4cCI6MTcxNDUxNjI5OCwiZ3JvdXBzIjpbImFkbWluIl0sImlhdCI6MTcxNDUxNjI5OCwiaXNzIjoiaHR0cHM6Ly90d29jYW5vZXMuY29tL3Bzc28iLCJuYW1lIjoiTGl6IEFwcGxlc2VlZCIsIm5vbmNlIjoiN0Q3MUY4QjQtMURFNy00Rjg5LThDM0EtMjEwRDE2MUYzOEFDIiwic3ViIjoibGl6IiwidXBuIjoibGl6QHR3b2Nhbm9lcy5jb20ifQ.KHUDMXDefwGBjpmUh5JDLp7aVIyYgQDOxD-u09oFiXFZrMPyD4tHl1h-QtO5yTqX4sBAiA1iF4moRLwYnzeXmA

	if VerifyJWTAndReturnUserClaims(signedToken, jwksPrivKey.Public()) == nil {
		t.Fail()
	}

	//encrypt the signed data. Include the APV from the sent in claims and the refresh token. The keystore private key is
	//sent in to generate a shared secret used to encrypt the data.
	jwe := EncyptTokenWithA256GCM(signedToken, UserAuth, "refresh", deviceSigningPublicKey, []byte(userClaims.JWECrypto.Apv))
	if jwe == "" {

		t.Fail()

	}
	/*
		jwe:eyJlbmMiOiJBMjU2R0NNIiwia2lkIjoiIiwiZXBrIjp7InkiOiJHX2dobU1kWFhWU0tmVFk0eEh3bDR6T3VUd2ZmbkhFelNlY21BR0o3Q3hzIiwieCI6IkVpb1ZaNW9GS21EYjNDMlJuX3BHWnFQMlJ4SWhmeXRLcEJDZHprUlhWUWMiLCJrdHkiOiJFQyIsImNydiI6IlAtMjU2In0sImFwdSI6IkFBQUFCVUZRVUV4RkFBQUFRUVFTS2hWbm1nVXFZTnZjTFpHZi1rWm1vX1pIRWlGX0swcWtFSjNPUkZkVkJ4djRJWmpIVjExVWluMDJPTVI4SmVNenJrOEgzNXh4TTBubkpnQmlld3NiIiwidHlwIjoicGxhdGZvcm1zc28tbG9naW4tcmVzcG9uc2Urand0IiwiYWxnIjoiRUNESC1FUyIsImFwdiI6IkFBQUFCVUZ3Y0d4bEFBQUFRUVRzVDhYT1dKTkZBRnNjOXlBR21JRUJYak1YLWF6NG5ZcGJ3Qkh1YXZTT3hLQ1IwS2VJVDFyUXpCT1dGcWticmx5MTlEdDJUaFRYd29VZWFBcFU0ZFZTQUFBQUpEZEVOekZHT0VJMExURkVSVGN0TkVZNE9TMDRRek5CTFRJeE1FUXhOakZHTXpoQlF3In0..AAAAAAAAAAAAAAAA.uCla4YTjjJyzlGxTJzYD7MFhasom8-YUzSnZ0TdFZw1k2zpDtva_OQs0QPNXnbgDAncFp0_9Z2ngMHffJlL9cLAGti8iqR80B5qEEvzGWDuzCfAhsTzk79QrCqPAizKp_bd-zxrump-TB-zRixCam-f_pS03v-WWz5bGZfQENwoHInraHnr14pgI4M-rx3yZztoIH9hKi1pRKQ3_WGIx9BgOhb6po3dtOCFS2c1CBDCdEUAUJznmoAAgKopcRHupClfzLi5EAWYTgVnwfB3QZ6g8JYyjeVB8qMxKzOdIj07ndmSO1HE_aimnSBIZ6DpgrMWzvnGuA7hIvT6HwijXSEk3K6jhqvQITH5lc8ZXM7_vXbjJre6V_cm9qjIYGB6o3m1WiXjJU9v0kBDGS4rUtKZvvU7YzOnEwo4LVcdaw0fDBlS3s8_UxiygHmLiw4KMzBMyIGUnynwnVG9MwzM1FK5vHONBARNHnlA98bk0eBI6foX0d2qjnlqw-RlX1LbBOM1bELrl8ubdW2vVN5qeQ7-oEX-FSCn8T5dQROD5wtl8SOxX8oAvlYN8msLdc5sjnTEhlfeWpEaWvBVihUCc7YixXtND3hh_C5PLzuIw8euH9tV9Sa3hR3ISp69QEn3GZUr5VFkyGfDUMOXC57DrXrFBbrDxMLj1lu8xojiw-VKOTLoHEfGaa4c5209ZMrVGNARqzBNB7pvAQvrQs8QON5xTnvU4SNegI_d2MTXFyjJEgwT1T-qWbVc-xHGKVvbuq23HvM_gioF-SaUCVWj4L1SO2-M5e6yALPILKZirvXY.lABln0gMxk8aHXNMa6Z04w
	*/
}

func TestPSSOV2(t *testing.T) {
	deviceSigningPublicKey := ECPublicKeyFromPEM(devicePublicKeyPem)

	//Verifying incoming JWT signatur with deviceSigningPublicKey, pull out username and password from JWT and compare against known valid
	// username and password, create an ID token and refresh tokena and send back JWE (encrypted JWT)

	//get user claims. If signature is invalid, it will not return.
	keyRequestClaims := VerifyJWTAndReturnKeyRequestClaims(incomingPSSOV2HSMJWT, deviceSigningPublicKey)

	if keyRequestClaims == nil {
		t.Fail()
	}

	if keyRequestClaims.RequestType == "key_request" {

	} else if keyRequestClaims.KeyPurpose == "key_exchange" {

	} else {

	}
	// _ = SignToken(&staticKeystore().privateKey, staticKeystore().KID, userIDToken)

	// jwks := staticKeystore()
	// jwksPrivKey := ECPrivateKeyFromPEM(jwks.Pem)

	// //signedToken: eyJhbGciOiJFUzI1NiIsImtpZCI6Im5XUklhdWIzRGdHM3ctNXZsWS1nWnhtYlBWSHNhM1ZkZHBoX2RCbkkxSmMiLCJ0eXAiOiJKV1QifQ.eyJhdWQiOiJwc3NvIiwiZW1haWwiOiJsaXpAdHdvY2Fub2VzLmNvbSIsImV4cCI6MTcxNDUxNjI5OCwiZ3JvdXBzIjpbImFkbWluIl0sImlhdCI6MTcxNDUxNjI5OCwiaXNzIjoiaHR0cHM6Ly90d29jYW5vZXMuY29tL3Bzc28iLCJuYW1lIjoiTGl6IEFwcGxlc2VlZCIsIm5vbmNlIjoiN0Q3MUY4QjQtMURFNy00Rjg5LThDM0EtMjEwRDE2MUYzOEFDIiwic3ViIjoibGl6IiwidXBuIjoibGl6QHR3b2Nhbm9lcy5jb20ifQ.KHUDMXDefwGBjpmUh5JDLp7aVIyYgQDOxD-u09oFiXFZrMPyD4tHl1h-QtO5yTqX4sBAiA1iF4moRLwYnzeXmA

	// if VerifyJWTAndReturnUserClaims(signedToken, jwksPrivKey.Public()) == nil {
	// 	t.Fail()
	// }

	// //encrypt the signed data. Include the APV from the sent in claims and the refresh token. The keystore private key is
	// //sent in to generate a shared secret used to encrypt the data.
	// jwe := EncyptTokenWithA256GCM(signedToken, "refresh", &staticKeystore().privateKey, []byte(userClaims.JWECrypto.Apv))
	// if jwe == "" {

	// 	t.Fail()

	// }

}
