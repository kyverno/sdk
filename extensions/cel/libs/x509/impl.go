package x509

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/kyverno/sdk/extensions/cel/utils"
)

type impl struct {
	types.Adapter
}

// PublicKey is the encoded form of an RSA public key in x509.decode output.
type PublicKey struct {
	N string
	E int
}

// ECDSAPublicKey is the encoded form of an ECDSA public key: the curve name
// and the point in uncompressed SEC 1 form.
type ECDSAPublicKey struct {
	Curve string
	Point []byte
}

// Ed25519PublicKey is the encoded form of an Ed25519 public key.
type Ed25519PublicKey struct {
	Key []byte
}

type CertificateOutput struct {
	Raw                         string
	RawTBSCertificate           string
	RawSubjectPublicKeyInfo     string
	RawSubject                  string
	RawIssuer                   string
	Signature                   string
	PublicKeyAlgorithm          x509.PublicKeyAlgorithm
	PublicKey                   any
	SerialNumber                int64
	Issuer                      pkix.Name
	NotBefore                   string
	NotAfter                    string
	KeyUsage                    x509.KeyUsage
	Extensions                  []pkix.Extension
	ExtraExtensions             []pkix.Extension
	ExtKeyUsage                 []x509.ExtKeyUsage
	BasicConstraintsValid       bool
	IsCA                        bool
	MaxPathLen                  int
	MaxPathLenZero              bool
	AuthorityKeyId              []byte
	OCSPServer                  []string
	IssuingCertificateURL       []string
	DNSNames                    []string
	EmailAddresses              []string
	IPAddresses                 []net.IP
	PermittedDNSDomainsCritical bool
	PermittedDNSDomains         []string
	ExcludedDNSDomains          []string
	PermittedIPRanges           []*net.IPNet
	ExcludedIPRanges            []*net.IPNet
	PermittedEmailAddresses     []string
	ExcludedEmailAddresses      []string
	PermittedURIDomains         []string
	ExcludedURIDomains          []string
	CRLDistributionPoints       []string
	PolicyIdentifiers           []asn1.ObjectIdentifier
}

func encodeCertificate(cert *x509.Certificate) (map[string]any, error) {
	output := CertificateOutput{
		Raw:                         base64Encode(cert.Raw),
		RawTBSCertificate:           base64Encode(cert.RawTBSCertificate),
		RawSubjectPublicKeyInfo:     base64Encode(cert.RawSubjectPublicKeyInfo),
		RawSubject:                  base64Encode(cert.RawSubject),
		RawIssuer:                   base64Encode(cert.RawIssuer),
		Signature:                   base64Encode(cert.Signature),
		PublicKeyAlgorithm:          cert.PublicKeyAlgorithm,
		PublicKey:                   cert.PublicKey,
		SerialNumber:                cert.SerialNumber.Int64(),
		Issuer:                      cert.Issuer,
		NotBefore:                   cert.NotBefore.Format(time.RFC3339),
		NotAfter:                    cert.NotAfter.Format(time.RFC3339),
		KeyUsage:                    cert.KeyUsage,
		Extensions:                  cert.Extensions,
		ExtraExtensions:             cert.ExtraExtensions,
		ExtKeyUsage:                 cert.ExtKeyUsage,
		BasicConstraintsValid:       cert.BasicConstraintsValid,
		IsCA:                        cert.IsCA,
		MaxPathLen:                  cert.MaxPathLen,
		MaxPathLenZero:              cert.MaxPathLenZero,
		AuthorityKeyId:              cert.AuthorityKeyId,
		OCSPServer:                  cert.OCSPServer,
		IssuingCertificateURL:       cert.IssuingCertificateURL,
		DNSNames:                    cert.DNSNames,
		EmailAddresses:              cert.EmailAddresses,
		IPAddresses:                 cert.IPAddresses,
		PermittedDNSDomainsCritical: cert.PermittedDNSDomainsCritical,
		PermittedDNSDomains:         cert.PermittedDNSDomains,
		ExcludedDNSDomains:          cert.ExcludedDNSDomains,
		PermittedIPRanges:           cert.PermittedIPRanges,
		ExcludedIPRanges:            cert.ExcludedIPRanges,
		PermittedEmailAddresses:     cert.PermittedEmailAddresses,
		ExcludedEmailAddresses:      cert.ExcludedEmailAddresses,
		PermittedURIDomains:         cert.PermittedURIDomains,
		ExcludedURIDomains:          cert.ExcludedURIDomains,
		CRLDistributionPoints:       cert.CRLDistributionPoints,
		PolicyIdentifiers:           cert.PolicyIdentifiers,
	}

	buf := new(bytes.Buffer)
	enc := json.NewEncoder(buf)
	if err := enc.Encode(output); err != nil {
		return nil, err
	}
	res := map[string]any{}
	if err := json.Unmarshal(buf.Bytes(), &res); err != nil {
		return nil, err
	}
	return res, nil
}

func base64Encode(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

func encode[T any](in T) (map[string]any, error) {
	buf := new(bytes.Buffer)
	enc := json.NewEncoder(buf)
	if err := enc.Encode(in); err != nil {
		return nil, err
	}
	res := map[string]any{}
	if err := json.Unmarshal(buf.Bytes(), &res); err != nil {
		return nil, err
	}
	return res, nil
}

func (c *impl) decode(val ref.Val) ref.Val {
	input, err := utils.ConvertToNative[string](val)
	if err != nil {
		return types.WrapErr(err)
	}

	block, _ := pem.Decode([]byte(input))
	if block == nil {
		return types.WrapErr(errors.New("failed to decode PEM block"))
	}

	switch block.Type {
	case "CERTIFICATE":
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return types.WrapErr(err)
		}
		if cert.PublicKey, err = encodePublicKey(cert.PublicKey); err != nil {
			return types.WrapErr(err)
		}
		result, err := encodeCertificate(cert)
		if err != nil {
			return types.WrapErr(err)
		}
		return c.NativeToValue(result)

	case "CERTIFICATE REQUEST":
		csr, err := x509.ParseCertificateRequest(block.Bytes)
		if err != nil {
			return types.WrapErr(err)
		}
		if csr.PublicKey, err = encodePublicKey(csr.PublicKey); err != nil {
			return types.WrapErr(err)
		}
		result, err := encode(csr)
		if err != nil {
			return types.WrapErr(err)
		}
		return c.NativeToValue(result)

	default:
		return types.WrapErr(errors.New("PEM block neither contains a CERTIFICATE or CERTIFICATE REQUEST"))
	}
}

func encodePublicKey(key any) (any, error) {
	switch k := key.(type) {
	case *rsa.PublicKey:
		return PublicKey{N: k.N.String(), E: k.E}, nil
	case *ecdsa.PublicKey:
		point, err := k.Bytes()
		if err != nil {
			return nil, err
		}
		return ECDSAPublicKey{Curve: k.Curve.Params().Name, Point: point}, nil
	case ed25519.PublicKey:
		return Ed25519PublicKey{Key: k}, nil
	default:
		return nil, fmt.Errorf("unsupported public key type %T", key)
	}
}
