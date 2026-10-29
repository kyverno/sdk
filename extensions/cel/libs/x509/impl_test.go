package x509

import (
	"crypto/x509"
	"encoding/json"
	"testing"

	"github.com/google/cel-go/cel"
	"github.com/kyverno/sdk/extensions/cel/compiler"
	"github.com/stretchr/testify/assert"
)

const testCert = `-----BEGIN CERTIFICATE-----
MIIC7TCCAdWgAwIBAgIBADANBgkqhkiG9w0BAQsFADAYMRYwFAYDVQQDDA0qLmt5
dmVybm8uc3ZjMB4XDTIyMTAxMDExNDYzMloXDTIzMTAxMDEyNDYzMlowGDEWMBQG
A1UEAwwNKi5reXZlcm5vLnN2YzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoC
ggEBAOKF+2P0Ufp855hpdsGD4lYkd6oU7HZAOWm1XskAMwrdsqWwTNNAinyHRoPQ
IbNbGDQ+r6Cggc2mlxHJ90PnC2weHj5otaD17Z+ARZpJZ4HMWkEfFt8sxwo9vuQJ
RWihqNwFheowjswoSB1DHnPufrZHfztkMoRx278ZfHaIMdlSTg50ektkNDoHA3OJ
sxxw54X3HR1iq6SZwN8xNT0TI6B6BbfAYWMNmKCiZ2iV6kW//XnTEqGd2WcmhuP0
SjwO4tCJbj9oV6+Bj/uhFr7J4foErMaodYDBtQs/ul2tcAwSBHfnC2KcLbiZTZsC
0Rs0WPJ4YwF/cOsD7Z/RmLs4FHsCAwEAAaNCMEAwDgYDVR0PAQH/BAQDAgKkMA8G
A1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFJaK+3Wfnf7rVkYBzMCLSaV56NMqMA0G
CSqGSIb3DQEBCwUAA4IBAQDY7F6b+t9BX7098JyGk6zeT39MoLdSv+8IaKXn+m8G
yOKn3CZkruko57ycvPd4taC0gggtmUYynFhwPMQr+boNrrK9rat8Jw3yPPsBq/8D
/s6tvwxSNXBfPUI5OvNIB/hA5XpJpdHQaCkYm+FWkcJsolkkbSOfVjUjImW26JHB
nnPPtR4Y7dx0SVoPS19IC0T5RmdvgqlXj4XbhTnX3QOujVHn8u+wQ8po7EngHDQs
+onfkp8ipe0QpEJL1ZdW2LhyDXGKrZ2y8UPZ9wYNzxHWaj1Thu4B9YFdsPUwWqSx
n9e+FygpoktlD8YgT7jwgiVKX7Koz++zyvMIdhvRrtgS
-----END CERTIFICATE-----`

func Test_decode(t *testing.T) {
	base, err := compiler.NewBaseEnv()
	assert.NoError(t, err)
	assert.NotNil(t, base)

	env, err := base.Extend(cel.Variable("cert", cel.StringType))
	assert.NoError(t, err)
	assert.NotNil(t, env)

	env, err = env.Extend(Lib(Latest()))
	assert.NoError(t, err)
	assert.NotNil(t, env)

	t.Run("decode_certificate", func(t *testing.T) {
		ast, issues := env.Compile(`x509.decode(cert)`)
		if issues != nil {
			t.Logf("Compilation issues: %v", issues.Err())
		}
		assert.Nil(t, issues)
		assert.NotNil(t, ast)
		prog, err := env.Program(ast)
		assert.NoError(t, err)
		assert.NotNil(t, prog)
		out, _, err := prog.Eval(map[string]any{
			"cert": testCert,
		})
		assert.NoError(t, err)
		assert.NotNil(t, out)

		result := out.Value().(map[string]any)

		assert.Equal(t, true, result["IsCA"])
		assert.Equal(t, true, result["BasicConstraintsValid"])
		assert.Equal(t, float64(37), result["KeyUsage"])
		assert.Equal(t, float64(0), result["SerialNumber"])
		assert.Equal(t, float64(1), result["PublicKeyAlgorithm"])
		assert.Equal(t, float64(-1), result["MaxPathLen"])
		assert.Equal(t, false, result["MaxPathLenZero"])
		assert.Equal(t, "2022-10-10T11:46:32Z", result["NotBefore"])
		assert.Equal(t, "2023-10-10T12:46:32Z", result["NotAfter"])

		issuer := result["Issuer"].(map[string]any)
		assert.Equal(t, "*.kyverno.svc", issuer["CommonName"])
		assert.Equal(t, "", issuer["SerialNumber"])

		publicKey := result["PublicKey"].(map[string]any)
		assert.Equal(t, float64(65537), publicKey["E"])
		assert.Equal(t, "28595925905962223424520947352207105451744616797088171943239289907331901888529856098458304611629660120574607501039902142361333982065793213267074854658525100799280158707840279479550961169213763526857247298653141711003931642606662052674943191476488665842309583311097351331994267413776792462637192775240062778036062353517979538994974045127175206597906751521558536719043095219698535279694800624795673809356898452438518041024126624051887044932164506019573725987204208750674129677584956156611454245004918943771571492757639432459688931855526941886354880727024912384140238027697348634609952850513122734230521040730560514233467", publicKey["N"])

		extensions := result["Extensions"].([]any)
		assert.Equal(t, 3, len(extensions))

		ext0 := extensions[0].(map[string]any)
		assert.Equal(t, true, ext0["Critical"])

		assert.NotNil(t, result["Raw"])
		assert.NotNil(t, result["RawIssuer"])
		assert.NotNil(t, result["RawSubject"])
		assert.NotNil(t, result["RawSubjectPublicKeyInfo"])
		assert.NotNil(t, result["RawTBSCertificate"])
		assert.NotNil(t, result["Signature"])

		jsonBytes, err := json.MarshalIndent(result, "", "  ")
		assert.NoError(t, err)
		t.Logf("Decoded certificate JSON:\n%s", string(jsonBytes))
	})

	t.Run("decode_invalid_pem", func(t *testing.T) {
		ast, issues := env.Compile(`x509.decode(cert)`)
		assert.Nil(t, issues)
		assert.NotNil(t, ast)
		prog, err := env.Program(ast)
		assert.NoError(t, err)
		assert.NotNil(t, prog)
		_, _, err = prog.Eval(map[string]any{
			"cert": "not a valid PEM",
		})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to decode PEM block")
	})
}

func Test_decodeKeyTypes(t *testing.T) {
	ecdsaCert := `-----BEGIN CERTIFICATE-----
MIIBqDCCAS+gAwIBAgIUW1FBrhAyjGuPjj0ibwzGkv9VFwwwCgYIKoZIzj0EAwIw
HDEaMBgGA1UEAwwRZWNkc2Eua3l2ZXJuby5zdmMwHhcNMjYxMDE5MjExMDQyWhcN
MzYxMDE2MjExMDQyWjAcMRowGAYDVQQDDBFlY2RzYS5reXZlcm5vLnN2YzB2MBAG
ByqGSM49AgEGBSuBBAAiA2IABLdT6uPozqJcfEDMWZ67We/NeBvGSWtr5/+of8Xd
PUTaAgiew9MnMt+5csbe8YO15eLRukXD0vtkC6oe5E3fzjb/c/0w9s0vXfhhzZxn
K30VZ/qSHKBSVJtm0Fk45Fk1cqMyMDAwHQYDVR0OBBYEFNjnO1FXblirMJhFDirH
wAesM06PMA8GA1UdEwEB/wQFMAMBAf8wCgYIKoZIzj0EAwIDZwAwZAIwNUC+rA+B
DsMas6ulFde+lQl75b9+PhanS12klLMxEW+xeQrZQp0TQWAY4ttTGDxkAjBsqywB
rhl665l2+SE5AsFevn7NA+aJFavdpkuiUKOkJ7yztkUaByndsnkaiTjdOrs=
-----END CERTIFICATE-----
`
	ed25519Cert := `-----BEGIN CERTIFICATE-----
MIIBLzCB4qADAgECAhRwu9HilalRUghukoCw8abzvt2ihjAFBgMrZXAwHjEcMBoG
A1UEAwwTZWQyNTUxOS5reXZlcm5vLnN2YzAeFw0yNjEwMTkyMTEwNDJaFw0zNjEw
MTYyMTEwNDJaMB4xHDAaBgNVBAMME2VkMjU1MTkua3l2ZXJuby5zdmMwKjAFBgMr
ZXADIQB13f7C0MDNSP69gkHHHJ9852OZ1wqIdvlhxeBTVpMYqqMyMDAwHQYDVR0O
BBYEFJYyU6pyJlAM9N5B+m/9BNDbWfE7MA8GA1UdEwEB/wQFMAMBAf8wBQYDK2Vw
A0EAH/Ny5Afwvyb1j7aiP9ZP4AZL8pOoVe8FhJgZPIIPinQ0iZZCeFrr233BK2De
cF5nv3ACd1zw8EaPy87uM0XHAA==
-----END CERTIFICATE-----
`
	ecdsaCSR := `-----BEGIN CERTIFICATE REQUEST-----
MIHUMHwCAQAwGjEYMBYGA1UEAwwPY3NyLmt5dmVybm8uc3ZjMFkwEwYHKoZIzj0C
AQYIKoZIzj0DAQcDQgAE4R47v163Y4eiFCNKGEwMhiqJcjXCjBV0uXVpxAY61ojb
bjVDvH75Q+hwomlkXqjaHZM9+kXS+UtIL2YC6N/BKKAAMAoGCCqGSM49BAMCA0gA
MEUCIQD8BztUkjjMDBTmdEObMfl+9X2Deh8caxMBKEUXGLmqAQIgGPS55kPVsNjX
AUhevj83b2V8mcslx1oNLx6TBOt1ueA=
-----END CERTIFICATE REQUEST-----
`
	base, err := compiler.NewBaseEnv()
	assert.NoError(t, err)
	env, err := base.Extend(cel.Variable("cert", cel.StringType))
	assert.NoError(t, err)
	env, err = env.Extend(Lib(Latest()))
	assert.NoError(t, err)
	ast, issues := env.Compile(`x509.decode(cert)`)
	assert.Nil(t, issues)
	prog, err := env.Program(ast)
	assert.NoError(t, err)

	testCases := []struct {
		name      string
		pem       string
		algorithm float64
		publicKey map[string]any
	}{{
		name:      "ECDSA P-384 certificate",
		pem:       ecdsaCert,
		algorithm: float64(x509.ECDSA),
		publicKey: map[string]any{
			"Curve": "P-384",
			"Point": "BLdT6uPozqJcfEDMWZ67We/NeBvGSWtr5/+of8XdPUTaAgiew9MnMt+5csbe8YO15eLRukXD0vtkC6oe5E3fzjb/c/0w9s0vXfhhzZxnK30VZ/qSHKBSVJtm0Fk45Fk1cg==",
		},
	}, {
		name:      "Ed25519 certificate",
		pem:       ed25519Cert,
		algorithm: float64(x509.Ed25519),
		publicKey: map[string]any{
			"Key": "dd3+wtDAzUj+vYJBxxyffOdjmdcKiHb5YcXgU1aTGKo=",
		},
	}, {
		name:      "ECDSA P-256 certificate request",
		pem:       ecdsaCSR,
		algorithm: float64(x509.ECDSA),
	}}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			out, _, err := prog.Eval(map[string]any{"cert": tc.pem})
			assert.NoError(t, err)
			result := out.Value().(map[string]any)
			assert.Equal(t, tc.algorithm, result["PublicKeyAlgorithm"])
			publicKey := result["PublicKey"].(map[string]any)
			if tc.publicKey != nil {
				assert.Equal(t, tc.publicKey, publicKey)
			} else {
				assert.Equal(t, "P-256", publicKey["Curve"])
			}
		})
	}
}
