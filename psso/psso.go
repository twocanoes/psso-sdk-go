package psso

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/go-jose/go-jose/v3"
	"github.com/go-jose/go-jose/v3/jwt"
	josecipher "github.com/square/go-jose/cipher"
)

//VerifyJWTAndReturnUserClaims
//Purpose: Take the token posted to the token endpoint, verify the signature, and return the claims. This request is for verifying the
//username and password and returning user infomation.
// input:
// requestPSSOV1JWT: String. Token sent to the token endpoint as a string. Example:
// "ewogICJ0eXAiIDogInBsYXRmb3Jtc3NvLWxvZ2luLXJlcXVlc3Qrand0IiwKICAiYWxnIiA6ICJFUzI1NiIsCiAgImtpZCIgOiAiZitSbktXcmlra3NUUU5nQnVaaEQ4b01WUkZWUEJicFJTc3JteWJmdkpDMD0iCn0.ewogICJqd2VfY3J5cHRvIiA6IHsKICAgICJhbGciIDogIkVDREgtRVMiLAogICAgImVuYyIgOiAiQTI1NkdDTSIsCiAgICAiYXB2IiA6ICJBQUFBQlVGd2NHeGxBQUFBUVFUc1Q4WE9XSk5GQUZzYzl5QUdtSUVCWGpNWC1hejRuWXBid0JIdWF2U094S0NSMEtlSVQxclF6Qk9XRnFrYnJseTE5RHQyVGhUWHdvVWVhQXBVNGRWU0FBQUFKRGRFTnpGR09FSTBMVEZFUlRjdE5FWTRPUzA0UXpOQkxUSXhNRVF4TmpGR016aEJRdyIKICB9LAogICJleHAiIDogMTcxMzk5ODEwMSwKICAibm9uY2UiIDogIjdENzFGOEI0LTFERTctNEY4OS04QzNBLTIxMEQxNjFGMzhBQyIsCiAgInJlcXVlc3Rfbm9uY2UiIDogIk1TZkVIZ0ROY0ZkSDlHMk84OXVGQlJvQURlSXVqQkxCV0QrMzVpM3MvZWM9IiwKICAic2NvcGUiIDogIm9wZW5pZCBvZmZsaW5lX2FjY2VzcyB1cm46YXBwbGU6cGxhdGZvcm1zc28iLAogICJncmFudF90eXBlIiA6ICJwYXNzd29yZCIsCiAgImlzcyIgOiAicHNzbyIsCiAgInBhc3N3b3JkIiA6ICJ0d29jYW5vZXMiLAogICJzdWIiIDogImxpekB0d29jYW5vZXMuY29tIiwKICAiYW1yIiA6IFsKICAgICJwd2QiCiAgXSwKICAiY2xhaW1zIiA6IHsKICAgICJpZF90b2tlbiIgOiB7CiAgICAgICJncm91cHMiIDogewogICAgICAgICJ2YWx1ZXMiIDogWwogICAgICAgICAgIm5ldC1hZG1pbiIsCiAgICAgICAgICAibm90LWFkbWluIiwKICAgICAgICAgICJzb2Z0d2FyZS1pbnN0YWxsIgogICAgICAgIF0KICAgICAgfQogICAgfQogIH0sCiAgImF1ZCIgOiAiaHR0cHM6Ly9pZHAudHdvY2Fub2VzLmNvbS9wZXN0by90b2tlbiIsCiAgInVzZXJuYW1lIiA6ICJsaXpAdHdvY2Fub2VzLmNvbSIsCiAgImNsaWVudF9pZCIgOiAicHNzbyIsCiAgImlhdCIgOiAxNzEzOTk3ODAxCn0.7wtZJc-G6Trqs7dqxuqjh41mdnaCZWuH2Ywqqbw-Yhb5b3OHe70EmXdOX17l83qTlbzG8cVMVMZltc1pT-H35w"
// deviceSigningPublicKey: any. The public key portion of the device signing key during device provisioning. Uploaded by the device. Example:
// -----BEGIN PUBLIC KEY-----
//MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAELOFf3yRXGWbDaS339MS2ehFfkC7x
//oxR6sWdoIVD5bGcEav9WkZfNFJ1ye4iYqpBB7i0Z/rJuCUQXcXq+OyKZHQ==
//-----END PUBLIC KEY-----

// Output: TokenBody struct. This is claims in the request JWT.
func VerifyJWTAndReturnUserClaims(requestPSSOV1JWT string, deviceSigningPublicKey any) (*IDTokenRequestBody, []jose.Header, error) {

	//take the tokenString sent in and parse it into a Go JWT
	token, err := jwt.ParseSigned(requestPSSOV1JWT)

	if err != nil {
		return nil, nil, err
	}

	// pull out the body to verify the signature
	//get a new TokenBody Object
	tokenBody := new(IDTokenRequestBody)

	//Verify signature and populate TokenBody with claims
	if err = token.Claims(deviceSigningPublicKey, &tokenBody); err != nil {
		fmt.Println(err)
		return nil, nil, err
	}
	return tokenBody, token.Headers, nil

}

// VerifyJWTAndReturnKeyRequestClaims
// Purpose: When a token is posted to the token endpoint and it is version 2 of the PSSO Api, the request JWT signature is checked and
// the claims are returned. In version 2 of the PSSO protocol, the request can either be for provision Filevault / keychain unlock (with
// a smart card certificate and private key), or a authentication operation to unlock Filevault or keychain. This function
// returns the claims to determine which operation is requested.

// Input:
// requestPSSOV2JWT: String. Token sent to the token endpoint as a string. Example:
//
// deviceSigningPublicKey: any. The public key portion of the device signing key during device provisioning. Uploaded by the device. Example:
// -----BEGIN PUBLIC KEY-----
//MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAELOFf3yRXGWbDaS339MS2ehFfkC7x
//oxR6sWdoIVD5bGcEav9WkZfNFJ1ye4iYqpBB7i0Z/rJuCUQXcXq+OyKZHQ==
//-----END PUBLIC KEY-----

// Output: TokenBody struct. This is claims in the request JWT.
func VerifyJWTAndReturnKeyRequestClaims(requestPSSOV2JWT string, deviceSigningPublicKey any) (*KeyRequestBody, error) {

	//take the tokenString sent in and parse it into a Go JWT
	claims, err := jwt.ParseSigned(requestPSSOV2JWT)

	if err != nil {
		return nil, err
	}

	// pull out the body to verify the signature
	//get a new TokenBody Object
	keyRequestBody := new(KeyRequestBody)

	//Verify signature and populate TokenBody with claims
	if err = claims.Claims(deviceSigningPublicKey, &keyRequestBody); err != nil {
		fmt.Println(err)
		return nil, err
	}
	return keyRequestBody, nil

}

// SignClaims()
// Sign the ID token with the service privatekey.
// Input:
// servicePrivateKey: private key from the key created on service first startup. Typically in the JWKS.
// keyID: The ID of the key so that device can look up the public key on the device side to verify the signature. Example: nWRIaub3DgG3w-5vlY-gZxmbPVHsa3Vddph_dBnI1Jc.
// idClaims: the identity claims to be signed. Example:
/*
Exp: 1714761261
Iss: "psso"
Aud: "https://idp.twocanoes.com/pesto/token"
Iat: 1714761561
Nonce: "https://idp.twocanoes.com/pesto/token"
Groups: []string len: 1, cap: 1, ["admin"]
[0]: "admin"
Subject: "liz"
UPN: "liz@twocanoes.com"
Name: "Liz Appleseed"
Email: "liz@twocanoes.com"
*/

// Output: string. JWT in serialized / dot notation format. Example output:
// eyJhbGciOiJFUzI1NiIsImtpZCI6Im5XUklhdWIzRGdHM3ctNXZsWS1nWnhtYlBWSHNhM1ZkZHBoX2RCbkkxSmMiLCJ0eXAiOiJKV1QifQ.eyJhdWQiOiJodHRwczovL2lkcC50d29jYW5vZXMuY29tL3Blc3RvL3Rva2VuIiwiZW1haWwiOiJsaXpAdHdvY2Fub2VzLmNvbSIsImV4cCI6MTcxNDc2MTI2MSwiZ3JvdXBzIjpbImFkbWluIl0sImlhdCI6MTcxNDc2MTU2MSwiaXNzIjoicHNzbyIsIm5hbWUiOiJMaXogQXBwbGVzZWVkIiwibm9uY2UiOiJodHRwczovL2lkcC50d29jYW5vZXMuY29tL3Blc3RvL3Rva2VuIiwic3ViIjoibGl6IiwidXBuIjoibGl6QHR3b2Nhbm9lcy5jb20ifQ.A7_TWJrDY_So_bqEEzndiuoLRnWuuRFmHOBr_ocnyMMLb49Tb6yXO81TYf3_3ajvemxL04AhgPhIH_HVLs-aPg

func SignClaims(servicePrivateKey *ecdsa.PrivateKey, keyID string, idClaims interface{}) (string, error) {

	//setup key used for signing.
	var key jose.JSONWebKey
	key.Algorithm = "ES256"
	key.Use = "sig"
	key.KeyID = keyID
	key.Key = servicePrivateKey

	signingKey := jose.SigningKey{Algorithm: jose.SignatureAlgorithm(key.Algorithm), Key: key}
	signingOptions := (&jose.SignerOptions{}).WithHeader("kid", key.KeyID).WithType("JWT")
	signer, err := jose.NewSigner(signingKey, signingOptions)

	if err != nil {
		fmt.Printf("%v", err)
		return "", err
	}

	//sign the id claims and put in dot format
	jwt, err := jwt.Signed(signer).Claims(idClaims).CompactSerialize()

	if err != nil {
		fmt.Printf("%v", err)
		return "", err

	}
	return jwt, nil
}

// EncryptTokenWithA256GCM
// Purpose: encrypt a token. can be signed or unsigned.
// Input:
// jweBodyCompact token bytes. Can be signed or unsigned, but must be bytes to be encrypted. Example: "{\"certificate\":\"MIIBajCCARCgAwIBAgIBATAKBggqhkjOPQQDAjAjMSEwHwYDVQQKDBhqYXBwbGVzZWVkQHR3b2Nhbm9lcy5jb20wHhcNMjQwNTAzMTk0MDIyWhcNMjUwNTAzMTk0MDIyWjAjMSEwHwYDVQQKDBhqYXBwbGVzZWVkQHR3b2Nhbm9lcy5jb20wWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQfdD7iqtOrdoQwmNrynRlkGUKxS6D6xTJQF4t9LK_NwQwUEg2Rvmb7dNHXL9c_yuYUMCtY5WVWfggdKqfWK4TPozUwMzAOBgNVHQ8BAf8EBAMCBaAwEwYDVR0lBAwwCgYIKwYBBQUHAwEwDAYDVR0TAQH_BAIwADAKBggqhkjOPQQDAgNIADBFAiEAkemdC3ylpHldim-IvZzj39wNqKgyhNBg78ioX8LEJEICIFne6SeHSVt8GH7JIE2BREjWPl1NFw_CxgivDU3a3vXa\",\"exp\":...+348 more"

// deviceEncryptionPublicKey. pointer to ecdsa.PublicKey. Device public encryption key for signing.
// apv: string. From request claims. Example: AAAABUFwcGxlAAAAQQTsT8XOWJNFAFsc9yAGmIEBXjMX-az4nYpbwBHuavSOxKCR0KeIT1rQzBOWFqkbrly19Dt2ThTXwoUeaApU4dVSAAAAJDkzMTdFODEwLUM1RTYtNDE2RC1BQTQ4LTM1MEM3NTA3NUREMg
// Output: JWE in dot notation format. Example: eyJlbmMiOiJBMjU2R0NNIiwia2lkIjoiIiwiZXBrIjp7InkiOiJfa1RMNmpfb3dCVG5DMnhpNUxYYTMzTmhZVXhuQ015M0ZUdVI4NVYzc3E0IiwieCI6IkJDbjhvWFVURXV0QUJ6T1A3ME1EYmRFNzFNVHRJUTdvdUtaS2xBclB0Uk0iLCJrdHkiOiJFQyIsImNydiI6IlAtMjU2In0sImFwdSI6IkFBQUFCVUZRVUV4RkFBQUFRUVFFS2Z5aGRSTVM2MEFITTRfdlF3TnQwVHZVeE8waER1aTRwa3FVQ3MtMUVfNUV5LW9fNk1BVTV3dHNZdVMxMnQ5ellXRk1ad2pNdHhVN2tmT1ZkN0t1IiwidHlwIjoicGxhdGZvcm1zc28tbG9naW4tcmVzcG9uc2Urand0IiwiYWxnIjoiRUNESC1FUyIsImFwdiI6IkFBQUFCVUZ3Y0d4bEFBQUFRUVRzVDhYT1dKTkZBRnNjOXlBR21JRUJYak1YLWF6NG5ZcGJ3Qkh1YXZTT3hLQ1IwS2VJVDFyUXpCT1dGcWticmx5MTlEdDJUaFRYd29VZWFBcFU0ZFZTQUFBQUpEa3pNVGRGT0RFd0xVTTFSVFl0TkRFMlJDMUJRVFE0TFRNMU1FTTNOVEEzTlVSRU1nIn0..AAAAAAAAAAAAAAAA.u9i9co8lNsbBF8b3PbjO95c47Xq2E4O-jeK5cTk6oIs3DSQ24s3KRXgH5MY_lpMbo8UVpAsoyie7S6kBQj1w2wMNo2wkCSGhk6hpjvcTr6PbT653uK9MRNyg1cJ_WfaVPxYS801mO2-DLOUSkXM_44pTWAMslLIFyfu8mxwuaQt7VjXhrUV0VpszXVXBMpEzjFiNasOxTDrk_wz-9GpzjDYYEzAWep39UbsRPwFTJ2LrWzyDuVbQHYYf9fJRYc11XQ6cdQJRW4HGW_j84kvbd2PwOAo_rFLczfj-Meaq1D_4XdecG-Hwf8p-FXuVW5tsgWFt6OLAjT6Zjkhm0QV_nBHw3R5NNHbnNNuOdQkyVUPhxvCrG6j4mmQ2T_40rh1ymK0jOg19fTMYCFUEzWycTurA53UNh-NcTJQWQruAELml91cx_qhgyE7T1o6O6RVua7qBOIqc04BjT_60ePDqj_tj5q9Kla5xPG3KC7UeP5uKbUtp7bFm8tImMCUPchB4ukc3HK8TCux6f1GH4BD3sJbXlE5UnWxS3j01BIh62Eh2HkMLzAdZHtVT_XBIxZdbeUbgcz1DygV0CQHM-DufvTpDX6X0fOvRbt3mLth9B126IP6-2tjxOp8oT_cgNrhVe_knM4FZ5tzpcp6v_I2bYn-HVBqavSNLu30ka7GcVIBO5hKi_c7TYuq6gcGUGfkfVfeLHcqLKKM-q26cugsiF4cWOEf_a6j0b9aUdw3B7Ny8EUsGQOa_-_Z8LcmgeshxRWPRuSAOMqa32nJo6Usk27BlxOIRkN679K2i7PZ7_Es5iqPn9vm8dHJIWFpoyKlZ3bEgVvCClosgDpQ5ZWt2g8_BJmAvkF2M8mgH0AGfOWQPJ5kPKBrZFUBBvuEE1PTf2mhtjCNUpzu85B7LmoV8WRNEZxykcaXunMJQijsryanW0n4MfFDJ6kx_cJ8UMj-kVoF2W5K7jCXtsv3omBVV3Sgd1U_YZb9NcB8_o6k0NIZrhiqAmhpthn7_lKfjuI_NaK4wXEZCLQeUisWIiWjaJ9KZ-Gc_ZKyOpXSMIkpA1K85RBrlI2hZ2VGNLfOLB9YWyvOLt-Bs2Ky4fBbtRCnreLUyow1SfDnHq9CbA-PQr9939F7pXqegYa5AEA.PSsZVUIKU1UrvAfOHmZaGA
func EncryptTokenWithA256GCM(jweBodyCompact []byte, deviceEncryptionPublicKey *ecdsa.PublicKey, apv string) (string, error) {

	//To encrypt the input bytes, the encryption key needs to be shared by both sides (service and the device). To achieve this,
	//ECDH-ES (Eliptic Curve Diffe-Heindmen Ephemeral Static) is used to generate the symmetric key. On the service side,
	// a new ECC key is created. This ephermalKey key is used with the public key from the device encrption key to generate
	// a symmetric key for encryption.

	// On the device side when the encrypted data is received, the device encryption key and the public key of the ephemeral key
	// is used to derive the same shared secret. This share secret is then used for decrypting the data.

	//generate the ephemeral key using P256. This will be used to generate the shared secret and then discarded.
	ephemeral, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	if err != nil {
		fmt.Println("error making ephemeral key")
		return "", err
	}

	//get apu (inform about the key)
	apu := buildAPU(ephemeral)

	//generate a symmetric key using info about the ephermal key, info about the key on the receiver side,
	// the key on the service side, and the public key of the the receiver.
	apvRaw, _ := base64.RawURLEncoding.DecodeString(apv)

	sharedSecret := josecipher.DeriveECDHES("A256GCM", apu, apvRaw, ephemeral, deviceEncryptionPublicKey, 32)

	//user the shared secret to create a cipher that will be used to encrypt the user info.
	cipherBlock, _ := aes.NewCipher(sharedSecret)
	aesgcm, err := cipher.NewGCM(cipherBlock)

	if err != nil {
		return "", err
	}

	//We need to send the public key part of the ephemeral key to the device side. This needs to be in the header and in JSON.
	ephemeralPublicKey := &EphemeralPublicKey{
		X:       base64.RawURLEncoding.EncodeToString(ephemeral.X.Bytes()),
		Y:       base64.RawURLEncoding.EncodeToString(ephemeral.Y.Bytes()),
		KeyType: "EC",
		Curve:   "P-256",
	}
	jweHeaders := ResponseHeader{
		Encryption:         "A256GCM",
		KeyID:              "ephemeralKey",
		EphemeralPublicKey: *ephemeralPublicKey,
		Type:               "platformsso-login-response+jwt",
		Algorithm:          "ECDH-ES",
		APU:                base64.RawURLEncoding.EncodeToString(apu),
		APV:                apv,
	}

	//convert the headers to JSON
	jweHeadersCompact, err := json.Marshal(jweHeaders)

	if err != nil {
		return "", err
	}

	//a Nonce is included both in the encryption process and in the return toke so the receive can decrypt the data successfully.
	nonce := createNonce()

	//Encrypt. Include the nonce, body, and headers.
	ciphertext := aesgcm.Seal(nil, nonce, jweBodyCompact, []byte(base64.RawURLEncoding.EncodeToString(jweHeadersCompact)))

	//Returned ciphertext has tag (16 bytes) appended to the encrypted data. Separate them out
	tag := ciphertext[len(ciphertext)-16:]
	ciphertext = ciphertext[:len(ciphertext)-16]

	// build token
	return base64.RawURLEncoding.EncodeToString(jweHeadersCompact) + ".." + base64.RawURLEncoding.EncodeToString(nonce) + "." + base64.RawURLEncoding.EncodeToString(ciphertext) + "." + base64.RawURLEncoding.EncodeToString(tag), nil
}

// return a random, 12 byte nonce.
func createNonce() []byte {
	data := make([]byte, 12)
	rand.Read(data)
	return data
}
