## func VerifyJWTAndReturnUserClaims(requestPSSOV1JWT string, deviceSigningPublicKey any) (*IDTokenRequestBody, []jose.Header, error)

Purpose: Take the token posted to the token endpoint, verify the signature, and return the claims. This request is for verifying the
username and password and returning user infomation.

### Input:
 
#### requestPSSOV1JWT: String. Token sent to the token endpoint as a string. Example:
	"ewogICJ0eXAiIDogInBsYXRmb3Jtc3NvLWxvZ2luLXJlcXVlc3Qrand0IiwKICAiYWxnIiA6ICJFUzI1NiIsCiAgImtpZCIgOiAiZitSbktXcmlra3NUUU5nQnVaaEQ4b01WUkZWUEJicFJTc3JteWJmdkpDMD0iCn0.ewogICJqd2VfY3J5cHRvIiA6IHsKICAgICJhbGciIDogIkVDREgtRVMiLAogICAgImVuYyIgOiAiQTI1NkdDTSIsCiAgICAiYXB2IiA6ICJBQUFBQlVGd2NHeGxBQUFBUVFUc1Q4WE9XSk5GQUZzYzl5QUdtSUVCWGpNWC1hejRuWXBid0JIdWF2U094S0NSMEtlSVQxclF6Qk9XRnFrYnJseTE5RHQyVGhUWHdvVWVhQXBVNGRWU0FBQUFKRGRFTnpGR09FSTBMVEZFUlRjdE5FWTRPUzA0UXpOQkxUSXhNRVF4TmpGR016aEJRdyIKICB9LAogICJleHAiIDogMTcxMzk5ODEwMSwKICAibm9uY2UiIDogIjdENzFGOEI0LTFERTctNEY4OS04QzNBLTIxMEQxNjFGMzhBQyIsCiAgInJlcXVlc3Rfbm9uY2UiIDogIk1TZkVIZ0ROY0ZkSDlHMk84OXVGQlJvQURlSXVqQkxCV0QrMzVpM3MvZWM9IiwKICAic2NvcGUiIDogIm9wZW5pZCBvZmZsaW5lX2FjY2VzcyB1cm46YXBwbGU6cGxhdGZvcm1zc28iLAogICJncmFudF90eXBlIiA6ICJwYXNzd29yZCIsCiAgImlzcyIgOiAicHNzbyIsCiAgInBhc3N3b3JkIiA6ICJ0d29jYW5vZXMiLAogICJzdWIiIDogImxpekB0d29jYW5vZXMuY29tIiwKICAiYW1yIiA6IFsKICAgICJwd2QiCiAgXSwKICAiY2xhaW1zIiA6IHsKICAgICJpZF90b2tlbiIgOiB7CiAgICAgICJncm91cHMiIDogewogICAgICAgICJ2YWx1ZXMiIDogWwogICAgICAgICAgIm5ldC1hZG1pbiIsCiAgICAgICAgICAibm90LWFkbWluIiwKICAgICAgICAgICJzb2Z0d2FyZS1pbnN0YWxsIgogICAgICAgIF0KICAgICAgfQogICAgfQogIH0sCiAgImF1ZCIgOiAiaHR0cHM6Ly9pZHAudHdvY2Fub2VzLmNvbS9wZXN0by90b2tlbiIsCiAgInVzZXJuYW1lIiA6ICJsaXpAdHdvY2Fub2VzLmNvbSIsCiAgImNsaWVudF9pZCIgOiAicHNzbyIsCiAgImlhdCIgOiAxNzEzOTk3ODAxCn0.7wtZJc-G6Trqs7dqxuqjh41mdnaCZWuH2Ywqqbw-Yhb5b3OHe70EmXdOX17l83qTlbzG8cVMVMZltc1pT-H35w"

#### deviceSigningPublicKey: any. The public key portion of the device signing key during device provisioning. Uploaded by the device. Example:
	
	-----BEGIN PUBLIC KEY-----
	MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAELOFf3yRXGWbDaS339MS2ehFfkC7x
	oxR6sWdoIVD5bGcEav9WkZfNFJ1ye4iYqpBB7i0Z/rJuCUQXcXq+OyKZHQ==
	-----END PUBLIC KEY-----

#### Output: TokenBody struct. This is claims in the request JWT.


## func CreateIDTokenResponse(issuerAPIHostName string, requestClaims IDTokenRequestBody, shortname string, fullname string, groups []string, email string, upn string, refreshToken string, servicePrivateKey *ecdsa.PrivateKey, serviceKeyID string, devicePublicKey *ecdsa.PublicKey) (string, error)

### Purpose: Create an JWE token to a request for an ID Token. PSSO v1.

### Inputs:
	shortname: string. user short name
	fullname: string. user full name
	groups: array of strings. Groups that user is member of.
	email: string. user email
	upn: string. user principal name
	refreshToken: string. A string that can be sent back in a subsequent request
	to authenticate without username or password.
	servicePrivateKey: pointer to an ecdsa PrivateKey. Used to sign response.
	serviceKeyID: string. Key id of servicePrivateKey.
	devicePublicKey: pointer to device encryption ecdsa PublicKey. used to encrypt response.

### Return Value: string. JWT token with user ID info in dot notation. Example: 
	"eyJlbmMiOiJBMjU2R0NNIiwia2lkIjoiIiwiZXBrIjp7InkiOiJtYU9RNWRhUVJQWHhTVUZLTmtOSmFOckUzYnlTbFVvTWNoNWt5RVpKUEpJIiwieCI6IjRETFRKNDVtb3pmVjJLTDRJUUJUWGN2R29HSmc0UjRVaDdwRTE5aHVmUzgiLCJrdHkiOiJFQyIsImNydiI6IlAtMjU2In0sImFwdSI6IkFBQUFCVUZRVUV4RkFBQUFRUVRnTXRNbmptYWpOOVhZb3ZnaEFGTmR5OGFnWW1EaEhoU0h1a1RYMkc1OUw1bWprT1hXa0VUMThVbEJTalpEU1dqYXhOMjhrcFZLREhJZVpNaEdTVHlTIiwidHlwIjoicGxhdGZvcm1zc28tbG9naW4tcmVzcG9uc2Urand0IiwiYWxnIjoiRUNESC1FUyIsImFwdiI6IkFBQUFCVUZ3Y0d4bEFBQUFRUVRzVDhYT1dKTkZBRnNjOXlBR21JRUJYak1YLWF6NG5ZcGJ3Qkh1YXZTT3hLQ1IwS2VJVDFyUXpCT1dGcWticmx5MTlEdDJUaFRYd29VZWFBcFU0ZFZTQUFBQUpEZEVOekZHT0VJMExURkVSVGN0TkVZNE9TMDRRek5CTFRJeE1FUXhOakZHTXpoQlF3In0..m3jFtRsFFYCJfEX6.hFd4vIvPfRf87NrOfYUoxIWWevc4cEyj9DOA4w6OXi5rfUeNg0KX9Vwa7ZqAgaHkiO9sdD1NaCNRdZ0Q5rICoNBWEbHKpTFvOpp7j_Aq2hbxwHZV62JG63keMPT17iQ68v7-mN0NB7LXLuhpx95zIQxg5xTTu0JcrsAu1mAvB7iWRBBDhgnk6YtMzlRrMiuuVE-rjx7fSir4ri2f9Km4zvwE6VtDMO6FnwfOMO0TB2wvFEFIkWHpEp0dpgnyLCoK0UeaCbQ0oWVNpOdgNk6vWXak6c9wvhjXJlo4kVfdV5yEQlhL6WquiN9KeEhFro_4BjyBON1Q6_hU8XzzbNtZFyjC31R22ClBNnVG4Z_YaZ67bCTbLijXxFGjsGeDyFYQJWb1p62kJt5Ba3wd9dzV5xer8L86q5L2ZAJizag11kg3mZZaGa_OgrEuew2NlcrwgLhfiroc4fs-p4gfdf3N9ThJIpSQGqvtK0IXE_XzaU9EVICozI__ed9tibsaGrqtpyE4bXK1WkuxLgJI55GbABypS6grdr-gcKjcFB3su_Y--j0ovjpy1hgQahYmYLz5TniTgE7yjmMEEk_arroSpOTxamVx3WbR5ukEO1-PYp9iPaL7jeVxohS9dlVwsYyao5LIvU3Bu4PK4PbwhzBvXhwUp9pBgqjFbdJ44kIftmKNy2obocbdR7t2ZiibkwNUXbY_bYJcy28KZ6QRei1Nl6LvdzHI_maHlIFiVp3nYmD2YQYyntZFvKP-T0GlL0LgxOJr6_vswQ6DvKuJXvs4JjxJAEHrX5yWsfPjQc9l3iTGgb6vPGgh0nx26JND71Ij.6dI5jzJ-ouTEcvbfH34ixw




## func VerifyJWTAndReturnKeyRequestClaims(requestPSSOV2JWT string, deviceSigningPublicKey any) (*KeyRequestBody, error) 

###Purpose: When a token is posted to the token endpoint and it is version 2 of the PSSO Api, the request JWT signature is checked and the claims are returned. In version 2 of the PSSO protocol, the request can either be for provision Filevault / keychain unlock (with a smart card certificate and private key), or a authentication operation to unlock Filevault or keychain. This function returns the claims to determine which operation is requested.

### Input:

#### requestPSSOV2JWT: String. Token sent to the token endpoint as a string. Example:
#### deviceSigningPublicKey: any. The public key portion of the device signing key during device provisioning. Uploaded by the device. Example:
	-----BEGIN PUBLIC KEY-----
	FkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAELOFf3yRXGWbDaS339MS2ehFfkC7x
	xR6sWdoIVD5bGcEav9WkZfNFJ1ye4iYqpBB7i0Z/rJuCUQXcXq+OyKZHQ==
	----END PUBLIC KEY-----

#### Output: TokenBody struct. This is claims in the request JWT.


## func CreateKeyRequestResponseClaims(requestClaims KeyRequestBody, devicePublicKey *ecdsa.PublicKey) (string, error) {
certificatePrivateKey, certificate, err := genCert(requestClaims.Username)

### Purpose: When a KeyRequest JWT is requested (filevault/keychain keying setup), these claims are sent back. A certificate is returned. This certificate is used for persistent token authentication on the device.

### Input:
#### requestClaims: KeyRequestBody. Incoming request. Used to get the Apv from the request to send back.
devicePublicKey: pointer to device public key. Used to encrypted response

####Return Value:
string. Encrypted JWT (JWE) in dot notation.

	

## func CreateKeyExchangeResponseClaims(requestClaims KeyRequestBody, devicePublicKey *ecdsa.PublicKey) (string, error)// Purpose: When a Unlock JWT is requested (filevault/keychain keying unlock), these claims are sent back.

### Input:

### requestClaims: KeyRequestBody. Incoming request. Used to get the Apv from the request to send back.

###devicePublicKey: pointer to device public key. Used to encrypted response

###Return Value:
string. Encrypted JWT (JWE) in dot notation.

