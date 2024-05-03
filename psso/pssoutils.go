package psso

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"math/big"
	"time"
)

// ECPublicKeyFromPEM
// Purpose: take PEM ECC public key and turn into a pointer to an ecdsa Public key in go. Used for getting key from db and turning
// into something useful in Go
// Input:
// PEM:String. PEM value of public key.
// Returns:
// pointer to ecdsa.PublicKey

func ECPublicKeyFromPEM(publicKeyPEM string) *ecdsa.PublicKey {

	publicKeyPemBytes := []byte(publicKeyPEM)
	publicKeyBlock, _ := pem.Decode(publicKeyPemBytes)
	publicKey, _ := x509.ParsePKIXPublicKey(publicKeyBlock.Bytes)
	return publicKey.(*ecdsa.PublicKey)

}

/// ECPrivateKeyFromPEM
// Purpose: take PEM ECC private key and turn into a pointer to an ecdsa Private key in go. Used for getting key from db and turning
// into something useful in Go
// Input:
// PEM:String. PEM value of private key.
// Returns:
// pointer to ecdsa.PublicKey

func ECPrivateKeyFromPEM(privateKeyPEM string) *ecdsa.PrivateKey {
	pemBytes := []byte(privateKeyPEM)
	pemblock, _ := pem.Decode(pemBytes)
	jwksPrivKey, _ := x509.ParseECPrivateKey(pemblock.Bytes)

	return jwksPrivKey
}

// Certificate used for persistent token on device. Certificate is require due to how persistent tokens are implemented.
// Input:
// User: string. value for subject in the certificate. Not used, but required for a X.509 cert.
// Return:
// tuple of an array of bytes. First value is the ECC private key generated. Second value is the certificate with the public key associated with the private key generated.

func genCert(user string) ([]byte, []byte) {

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err.Error())
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{user},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(time.Hour * 24 * 365),

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	derBytes, _ := x509.CreateCertificate(rand.Reader, &template, &template, publicKey(priv), priv)

	out := &bytes.Buffer{}
	pem.Encode(out, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	out.Reset()
	pem.Encode(out, pemBlockForKey(priv))

	return out.Bytes(), derBytes
}

// publicKey()
// Purpose: return public key from pointer to an ECC private key.
// Input:
// priv: pointer to ecdsa private key
// Output:
// pointer to ecdsa public key

func publicKey(priv interface{}) interface{} {
	switch k := priv.(type) {
	case *ecdsa.PrivateKey:
		return &k.PublicKey
	default:
		return nil
	}
}

// pemBlockForKey()
// Purpose: return a PEM string from pointer to an ECC private key.
// Input:
// priv: pointer to ecdsa private key
// Output:
// PEM block
func pemBlockForKey(priv interface{}) *pem.Block {
	switch k := priv.(type) {
	case *ecdsa.PrivateKey:
		b, err := x509.MarshalECPrivateKey(k)
		if err != nil {
		}
		return &pem.Block{Type: "EC PRIVATE KEY", Bytes: b}
	default:
		return nil
	}
}

// buildAPU()
// Purpose: APU (information about the key on the sender side) is in X9.63 format. This function converts a pointer to an ECDSA private key
// to a private key in x9.63 format.
// Input:
// priv: pointer to ecdsa private key
// Output:
// array of bytes in X963 format.

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

// lengthPrefixed()
// Purpose: take an array of bytes and prepend with the length.
// Input:
// data: array of bytes.
// Output:
// array of bytes prepended with 4 bytes of length

// Create data to data with prepended length in big endian format.
func lengthPrefixed(data []byte) []byte {
	out := make([]byte, len(data)+4)
	binary.BigEndian.PutUint32(out, uint32(len(data)))
	copy(out[4:], data)
	return out
}
