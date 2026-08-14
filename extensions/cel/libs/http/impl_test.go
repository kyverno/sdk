package http

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/kyverno/sdk/extensions/cel/compiler"
	"github.com/stretchr/testify/assert"
	"k8s.io/apimachinery/pkg/util/version"
)

var pemExample = `-----BEGIN CERTIFICATE-----
MIICMzCCAZygAwIBAgIJALiPnVsvq8dsMA0GCSqGSIb3DQEBBQUAMFMxCzAJBgNV
BAYTAlVTMQwwCgYDVQQIEwNmb28xDDAKBgNVBAcTA2ZvbzEMMAoGA1UEChMDZm9v
MQwwCgYDVQQLEwNmb28xDDAKBgNVBAMTA2ZvbzAeFw0xMzAzMTkxNTQwMTlaFw0x
ODAzMTgxNTQwMTlaMFMxCzAJBgNVBAYTAlVTMQwwCgYDVQQIEwNmb28xDDAKBgNV
BAcTA2ZvbzEMMAoGA1UEChMDZm9vMQwwCgYDVQQLEwNmb28xDDAKBgNVBAMTA2Zv
bzCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEAzdGfxi9CNbMf1UUcvDQh7MYB
OveIHyc0E0KIbhjK5FkCBU4CiZrbfHagaW7ZEcN0tt3EvpbOMxxc/ZQU2WN/s/wP
xph0pSfsfFsTKM4RhTWD2v4fgk+xZiKd1p0+L4hTtpwnEw0uXRVd0ki6muwV5y/P
+5FHUeldq+pgTcgzuK8CAwEAAaMPMA0wCwYDVR0PBAQDAgLkMA0GCSqGSIb3DQEB
BQUAA4GBAJiDAAtY0mQQeuxWdzLRzXmjvdSuL9GoyT3BF/jSnpxz5/58dba8pWen
v3pj4P3w5DoOso0rzkZy2jEsEitlVM2mLSbQpMM+MUVQCQoiG6W9xuCFuxSrwPIS
pAqEAuV4DNoxQKKWmhVv+J0ptMWD25Pnpxeq5sXzghfJnslJlQND
-----END CERTIFICATE-----`

type testClient struct {
	doFunc func(req *http.Request) (*http.Response, error)
}

func (t testClient) Do(req *http.Request) (*http.Response, error) {
	return t.doFunc(req)
}

func Test_impl_get_request(t *testing.T) {
	base, err := compiler.NewBaseEnv()
	assert.NoError(t, err)
	assert.NotNil(t, base)

	ctx := Context{&contextImpl{
		client: testClient{
			doFunc: func(req *http.Request) (*http.Response, error) {
				assert.Equal(t, req.URL.String(), "http://localhost:8080")
				assert.Equal(t, req.Method, "GET")

				return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(`{"body": "ok"}`))}, nil
			},
		},
	}}

	// lowercase functions have been introduced since version 2.0 of the library
	env, err := base.Extend(
		Lib(&ctx, version.MajorMinor(1, 18)),
	)
	assert.NoError(t, err)
	assert.NotNil(t, env)
	ast, issues := env.Compile(`http.get("http://localhost:8080")`)
	fmt.Println(issues.String())
	assert.Nil(t, issues)
	assert.NotNil(t, ast)
	prog, err := env.Program(ast)
	assert.NoError(t, err)
	assert.NotNil(t, prog)
	out, _, err := prog.Eval(map[string]any{
		"http": Context{&contextImpl{
			client: testClient{
				doFunc: func(req *http.Request) (*http.Response, error) {
					assert.Equal(t, req.URL.String(), "http://localhost:8080")
					assert.Equal(t, req.Method, "GET")

					return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(`{"body": "ok"}`))}, nil
				},
			},
		}},
	})
	assert.NoError(t, err)
	body := out.Value().(map[string]any)
	assert.Equal(t, body["body"], "ok")
	assert.Equal(t, body["statusCode"], http.StatusOK)
}

func Test_impl_get_request_with_headers(t *testing.T) {
	base, err := compiler.NewBaseEnv()
	assert.NoError(t, err)
	assert.NotNil(t, base)

	ctx := Context{&contextImpl{
		client: testClient{
			doFunc: func(req *http.Request) (*http.Response, error) {
				assert.Equal(t, req.URL.String(), "http://localhost:8080")
				assert.Equal(t, req.Method, "GET")
				assert.Equal(t, req.Header.Get("Authorization"), "Bearer token")

				return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(`{"body": "ok"}`))}, nil
			},
		},
	}}

	env, err := base.Extend(
		Lib(&ctx, version.MajorMinor(1, 18)),
	)
	assert.NoError(t, err)
	assert.NotNil(t, env)
	ast, issues := env.Compile(`http.get("http://localhost:8080", {"Authorization": "Bearer token"})`)
	fmt.Println(issues.String())
	assert.Nil(t, issues)
	assert.NotNil(t, ast)
	prog, err := env.Program(ast)
	assert.NoError(t, err)
	assert.NotNil(t, prog)
	out, _, err := prog.Eval(map[string]any{
		"http": Context{&contextImpl{
			client: testClient{
				doFunc: func(req *http.Request) (*http.Response, error) {
					assert.Equal(t, req.URL.String(), "http://localhost:8080")
					assert.Equal(t, req.Method, "GET")
					assert.Equal(t, req.Header.Get("Authorization"), "Bearer token")

					return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(`{"body": "ok"}`))}, nil
				},
			},
		}},
	})
	assert.NoError(t, err)
	body := out.Value().(map[string]any)
	assert.Equal(t, body["body"], "ok")
	assert.Equal(t, body["statusCode"], http.StatusOK)
}

func Test_impl_get_request_with_client_string_error(t *testing.T) {
	base, err := compiler.NewBaseEnv()
	assert.NoError(t, err)
	assert.NotNil(t, base)

	env, err := base.Extend(
		Lib(nil, version.MajorMinor(1, 18)),
	)
	assert.NoError(t, err)
	assert.NotNil(t, env)
	tests := []struct {
		name string
		args []ref.Val
		want ref.Val
	}{{
		name: "not enough args",
		args: nil,
		want: types.NewErr("expected 3 arguments, got %d", 0),
	}, {
		name: "bad arg 1",
		args: []ref.Val{types.String("foo"), types.String("http://localhost:8080"), env.CELTypeAdapter().NativeToValue(make(map[string]string, 0))},
		want: types.NewErr("invalid arg 0: unsupported native conversion from string to 'http.Context'"),
	}, {
		name: "bad arg 2",
		args: []ref.Val{env.CELTypeAdapter().NativeToValue(Context{}), types.Bool(false), env.CELTypeAdapter().NativeToValue(make(map[string]string, 0))},
		want: types.NewErr("invalid arg 1: type conversion error from bool to 'string'"),
	}, {
		name: "bad arg 3",
		args: []ref.Val{env.CELTypeAdapter().NativeToValue(Context{}), types.String("http://localhost:8080"), types.Bool(false)},
		want: types.NewErr("invalid arg 2: type conversion error from bool to 'map[string]string'"),
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &impl{}
			got := c.get_request_with_client_string(tt.args...)
			assert.Equal(t, tt.want, got)
		})
	}
}

func Test_impl_post_request(t *testing.T) {
	base, err := compiler.NewBaseEnv()
	assert.NoError(t, err)
	assert.NotNil(t, base)

	ctx := Context{&contextImpl{
		client: testClient{
			doFunc: func(req *http.Request) (*http.Response, error) {
				assert.Equal(t, req.URL.String(), "http://localhost:8080")
				assert.Equal(t, req.Method, "POST")

				var data any
				err := json.NewDecoder(req.Body).Decode(&data)
				assert.NoError(t, err)
				assert.Equal(t, data.(map[string]any)["key"], "value")
				assert.Equal(t, data.(map[string]any)["foo"], float64(2))

				return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(`{"body": "ok"}`))}, nil
			},
		},
	}}

	env, err := base.Extend(
		Lib(&ctx, version.MajorMinor(1, 18)),
	)
	assert.NoError(t, err)
	assert.NotNil(t, env)
	ast, issues := env.Compile(`http.post("http://localhost:8080", { "key": dyn("value"), "foo": dyn(2) })`)
	fmt.Println(issues.String())
	assert.Nil(t, issues)
	assert.NotNil(t, ast)
	prog, err := env.Program(ast)
	assert.NoError(t, err)
	assert.NotNil(t, prog)

	out, _, err := prog.Eval(map[string]any{})
	assert.NoError(t, err)
	body := out.Value().(map[string]any)
	assert.Equal(t, body["body"], "ok")
	assert.Equal(t, body["statusCode"], http.StatusOK)
}

func Test_impl_post_request_with_headers(t *testing.T) {
	base, err := compiler.NewBaseEnv()
	assert.NoError(t, err)
	assert.NotNil(t, base)

	ctx := Context{&contextImpl{
		client: testClient{
			doFunc: func(req *http.Request) (*http.Response, error) {
				assert.Equal(t, req.URL.String(), "http://localhost:8080")
				assert.Equal(t, req.Method, "POST")
				assert.Equal(t, req.Header.Get("Authorization"), "Bearer token")

				var data any
				err := json.NewDecoder(req.Body).Decode(&data)
				assert.NoError(t, err)
				assert.Equal(t, data.(map[string]any)["key"], "value")

				return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(`{"body": "ok"}`))}, nil
			},
		},
	}}

	env, err := base.Extend(
		Lib(&ctx, version.MajorMinor(1, 18)),
	)
	assert.NoError(t, err)
	assert.NotNil(t, env)
	ast, issues := env.Compile(`http.post("http://localhost:8080", {"key": "value"}, {"Authorization": "Bearer token"})`)
	fmt.Println(issues.String())
	assert.Nil(t, issues)
	assert.NotNil(t, ast)
	prog, err := env.Program(ast)
	assert.NoError(t, err)
	assert.NotNil(t, prog)

	out, _, err := prog.Eval(map[string]any{})
	assert.NoError(t, err)
	body := out.Value().(map[string]any)
	assert.Equal(t, body["body"], "ok")
	assert.Equal(t, body["statusCode"], http.StatusOK)
}

func Test_impl_post_request_string_with_client_error(t *testing.T) {
	base, err := compiler.NewBaseEnv()
	assert.NoError(t, err)
	assert.NotNil(t, base)

	env, err := base.Extend(
		Lib(nil, version.MajorMinor(1, 18)),
	)
	assert.NoError(t, err)
	assert.NotNil(t, env)
	tests := []struct {
		name string
		args []ref.Val
		want ref.Val
	}{{
		name: "not enough args",
		args: nil,
		want: types.NewErr("expected 4 arguments, got %d", 0),
	}, {
		name: "bad arg 1",
		args: []ref.Val{types.String("foo"), types.String("http://localhost:8080"), types.String("payload"), env.CELTypeAdapter().NativeToValue(make(map[string]string, 0))},
		want: types.NewErr("invalid arg 0: unsupported native conversion from string to 'http.Context'"),
	}, {
		name: "bad arg 2",
		args: []ref.Val{env.CELTypeAdapter().NativeToValue(Context{}), types.Bool(false), types.String("payload"), env.CELTypeAdapter().NativeToValue(make(map[string]string, 0))},
		want: types.NewErr("invalid arg 1: type conversion error from bool to 'string'"),
		// }, {
		// 	name: "bad arg 3",
		// 	args: []ref.Val{env.CELTypeAdapter().NativeToValue(Context{}), types.String("http://localhost:8080"), env.CELTypeAdapter().NativeToValue(Context{}), env.CELTypeAdapter().NativeToValue(make(map[string]string, 0))},
		// 	want: types.NewErr("invalid arg 3: type conversion error from bool to 'map[string]string'"),
	}, {
		name: "bad arg 4",
		args: []ref.Val{env.CELTypeAdapter().NativeToValue(Context{}), types.String("http://localhost:8080"), types.String("payload"), types.Bool(false)},
		want: types.NewErr("invalid arg 3: type conversion error from bool to 'map[string]string'"),
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &impl{}
			got := c.post_request_string_with_client(tt.args...)
			assert.Equal(t, tt.want, got)
		})
	}
}

func Test_impl_http_client_string(t *testing.T) {
	base, err := compiler.NewBaseEnv()
	assert.NoError(t, err)
	assert.NotNil(t, base)

	ctx := Context{&contextImpl{}}

	env, err := base.Extend(
		cel.Variable("pem", types.StringType),
		Lib(&ctx, version.MajorMinor(1, 18)),
	)
	assert.NoError(t, err)
	assert.NotNil(t, env)
	ast, issues := env.Compile(`http.client(pem)`)
	fmt.Println(issues.String())
	assert.Nil(t, issues)
	assert.NotNil(t, ast)
	prog, err := env.Program(ast)
	assert.NoError(t, err)
	assert.NotNil(t, prog)

	out, _, err := prog.Eval(map[string]any{
		"pem": pemExample,
	})
	assert.NoError(t, err)
	reqProvider := out.Value().(*contextImpl)
	assert.NotNil(t, reqProvider)
}

func Test_impl_http_client_string_error(t *testing.T) {
	base, err := compiler.NewBaseEnv()
	assert.NoError(t, err)
	assert.NotNil(t, base)

	env, err := base.Extend(
		Lib(nil, version.MajorMinor(1, 18)),
	)
	assert.NoError(t, err)
	assert.NotNil(t, env)
	tests := []struct {
		name string
		args []ref.Val
		want ref.Val
	}{{
		name: "bad arg 1",
		args: []ref.Val{types.String("foo"), types.String("http://localhost:8080"), types.String("caBundle")},
		want: types.NewErr("invalid arg 0: unsupported native conversion from string to 'http.Context'"),
	}, {
		name: "bad arg 2",
		args: []ref.Val{env.CELTypeAdapter().NativeToValue(Context{}), types.Bool(false)},
		want: types.NewErr("invalid arg 1: type conversion error from bool to 'string'"),
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &impl{}
			got := c.http_client_string(tt.args[0], tt.args[1])
			assert.Equal(t, tt.want, got)
		})
	}
}

func Test_impl_get_request_with_404_status_code(t *testing.T) {
	base, err := compiler.NewBaseEnv()
	assert.NoError(t, err)
	assert.NotNil(t, base)
	options := []cel.EnvOption{
		cel.Variable("http", ContextType),
		Lib(nil, version.MajorMinor(1, 18)),
	}
	env, err := base.Extend(options...)
	assert.NoError(t, err)
	assert.NotNil(t, env)
	ast, issues := env.Compile(`http.get("http://localhost:8080/notfound")`)
	assert.Nil(t, issues)
	assert.NotNil(t, ast)
	prog, err := env.Program(ast)
	assert.NoError(t, err)
	assert.NotNil(t, prog)
	out, _, err := prog.Eval(map[string]any{
		"http": Context{&contextImpl{
			client: testClient{
				doFunc: func(req *http.Request) (*http.Response, error) {
					return &http.Response{
						StatusCode: http.StatusNotFound,
						Body:       io.NopCloser(strings.NewReader(`{"error": "not found"}`)),
					}, nil
				},
			},
		}},
	})
	assert.NoError(t, err)
	body := out.Value().(map[string]any)
	assert.Equal(t, body["error"], "not found")
	assert.Equal(t, body["statusCode"], http.StatusNotFound)
}

func Test_impl_get_request_with_500_status_code(t *testing.T) {
	base, err := compiler.NewBaseEnv()
	assert.NoError(t, err)
	assert.NotNil(t, base)
	options := []cel.EnvOption{
		cel.Variable("http", ContextType),
		Lib(nil, version.MajorMinor(1, 18)),
	}
	env, err := base.Extend(options...)
	assert.NoError(t, err)
	assert.NotNil(t, env)
	ast, issues := env.Compile(`http.get("http://localhost:8080/error")`)
	assert.Nil(t, issues)
	assert.NotNil(t, ast)
	prog, err := env.Program(ast)
	assert.NoError(t, err)
	assert.NotNil(t, prog)
	out, _, err := prog.Eval(map[string]any{
		"http": Context{&contextImpl{
			client: testClient{
				doFunc: func(req *http.Request) (*http.Response, error) {
					return &http.Response{
						StatusCode: http.StatusInternalServerError,
						Body:       io.NopCloser(strings.NewReader(`{"error": "internal server error"}`)),
					}, nil
				},
			},
		}},
	})
	assert.NoError(t, err)
	body := out.Value().(map[string]any)
	assert.Equal(t, body["error"], "internal server error")
	assert.Equal(t, body["statusCode"], http.StatusInternalServerError)
}

func Test_impl_post_request_with_201_status_code(t *testing.T) {
	base, err := compiler.NewBaseEnv()
	assert.NoError(t, err)
	assert.NotNil(t, base)
	options := []cel.EnvOption{
		cel.Variable("http", ContextType),
		Lib(nil, version.MajorMinor(1, 18)),
	}
	env, err := base.Extend(options...)
	assert.NoError(t, err)
	assert.NotNil(t, env)
	ast, issues := env.Compile(`http.post("http://localhost:8080", {"key": "value"})`)
	assert.Nil(t, issues)
	assert.NotNil(t, ast)
	prog, err := env.Program(ast)
	assert.NoError(t, err)
	assert.NotNil(t, prog)
	out, _, err := prog.Eval(map[string]any{
		"http": Context{&contextImpl{
			client: testClient{
				doFunc: func(req *http.Request) (*http.Response, error) {
					return &http.Response{
						StatusCode: http.StatusCreated,
						Body:       io.NopCloser(strings.NewReader(`{"id": "123"}`)),
					}, nil
				},
			},
		}},
	})
	assert.NoError(t, err)
	body := out.Value().(map[string]any)
	assert.Equal(t, body["id"], "123")
	assert.Equal(t, body["statusCode"], http.StatusCreated)
}

func Test_impl_get_request_with_non_json_body(t *testing.T) {
	base, err := compiler.NewBaseEnv()
	assert.NoError(t, err)
	assert.NotNil(t, base)
	options := []cel.EnvOption{
		cel.Variable("http", ContextType),
		Lib(nil, version.MajorMinor(1, 18)),
	}
	env, err := base.Extend(options...)
	assert.NoError(t, err)
	assert.NotNil(t, env)
	ast, issues := env.Compile(`http.get("http://localhost:8080/text")`)
	assert.Nil(t, issues)
	assert.NotNil(t, ast)
	prog, err := env.Program(ast)
	assert.NoError(t, err)
	assert.NotNil(t, prog)
	out, _, err := prog.Eval(map[string]any{
		"http": Context{&contextImpl{
			client: testClient{
				doFunc: func(req *http.Request) (*http.Response, error) {
					return &http.Response{
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(strings.NewReader(`this is not json`)),
					}, nil
				},
			},
		}},
	})
	assert.NoError(t, err)
	body := out.Value().(map[string]any)
	// When body parsing fails, body is nil and we wrap it
	assert.Nil(t, body["body"])
	assert.Equal(t, body["statusCode"], http.StatusOK)
}

func Test_impl_get_request_with_array_response(t *testing.T) {
	base, err := compiler.NewBaseEnv()
	assert.NoError(t, err)
	assert.NotNil(t, base)
	options := []cel.EnvOption{
		cel.Variable("http", ContextType),
		Lib(nil, version.MajorMinor(1, 18)),
	}
	env, err := base.Extend(options...)
	assert.NoError(t, err)
	assert.NotNil(t, env)
	ast, issues := env.Compile(`http.get("http://localhost:8080/array")`)
	assert.Nil(t, issues)
	assert.NotNil(t, ast)
	prog, err := env.Program(ast)
	assert.NoError(t, err)
	assert.NotNil(t, prog)
	out, _, err := prog.Eval(map[string]any{
		"http": Context{&contextImpl{
			client: testClient{
				doFunc: func(req *http.Request) (*http.Response, error) {
					return &http.Response{
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(strings.NewReader(`[{"item": 1}, {"item": 2}]`)),
					}, nil
				},
			},
		}},
	})
	assert.NoError(t, err)
	result := out.Value().(map[string]any)
	// Array responses are wrapped
	assert.Equal(t, result["statusCode"], http.StatusOK)
	bodyArray := result["body"].([]any)
	assert.Len(t, bodyArray, 2)
	assert.Equal(t, bodyArray[0].(map[string]any)["item"], float64(1))
}

func Test_NewHTTPWithBlocklist_invalid_cidr(t *testing.T) {
	_, err := NewHTTPWithBlocklist([]string{"not-a-cidr/bad"}, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid CIDR")
}

func Test_NewHTTPWithBlocklist_invalid_allowlist(t *testing.T) {
	_, err := NewHTTPWithBlocklist(nil, []string{"no-scheme-or-host"})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "must include scheme and host")
}

func Test_validateURL_blocks_loopback_ip(t *testing.T) {
	ctx, err := NewHTTPWithBlocklist(DefaultBlockedCIDRs, nil)
	assert.NoError(t, err)
	_, err = ctx.Get("http://127.0.0.1/secret", nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "blocked")
}

func Test_validateURL_blocks_link_local_ip(t *testing.T) {
	// 169.254.169.254 is the canonical cloud metadata IP (AWS, GCP, Azure, DigitalOcean).
	ctx, err := NewHTTPWithBlocklist(DefaultBlockedCIDRs, nil)
	assert.NoError(t, err)
	_, err = ctx.Get("http://169.254.169.254/latest/meta-data/iam/security-credentials/", nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "blocked")
}

func Test_validateURL_blocks_rfc1918_ip(t *testing.T) {
	ctx, err := NewHTTPWithBlocklist(DefaultBlockedCIDRs, nil)
	assert.NoError(t, err)
	_, err = ctx.Get("http://10.0.0.1/internal", nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "blocked")
}

func Test_validateURL_blocks_hostname(t *testing.T) {
	ctx, err := NewHTTPWithBlocklist(nil, []string{"https://allowed.example.com"})
	// empty blocklist, non-matching allowlist
	assert.NoError(t, err)
	_, err = ctx.Get("https://other.example.com/path", nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not permitted")
}

func Test_validateURL_allowlist_permits_matching_url(t *testing.T) {
	doFunc := func(req *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(`{"ok": true}`))}, nil
	}
	allowEntry, _ := url.Parse("https://api.example.com")
	ctx := &contextImpl{
		client:             testClient{doFunc: doFunc},
		allowedURLPrefixes: []*url.URL{allowEntry},
	}
	result, err := ctx.Get("https://api.example.com/v1/resource", nil)
	assert.NoError(t, err)
	assert.NotNil(t, result)
}

func Test_validateURL_allowlist_rejects_different_host(t *testing.T) {
	ctx, err := NewHTTPWithBlocklist(nil, []string{"https://api.example.com"})
	assert.NoError(t, err)
	// Attacker tries to abuse prefix matching by using api.example.com.evil.com
	_, err = ctx.Get("https://api.example.com.evil.com/steal", nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not permitted")
}

func Test_validateURL_blocklist_carried_through_client(t *testing.T) {
	ctx, err := NewHTTPWithBlocklist(DefaultBlockedCIDRs, nil)
	assert.NoError(t, err)
	// Client() with empty caBundle returns same ctx
	derived, err := ctx.Client("")
	assert.NoError(t, err)
	_, err = derived.Get("http://127.0.0.1/secret", nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "blocked")
}

func Test_validateURL_no_blocklist_allows_any(t *testing.T) {
	doFunc := func(req *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(`{}`))}, nil
	}
	// contextImpl with no blocklist — even internal IPs are allowed (test/internal use)
	ctx := &contextImpl{client: testClient{doFunc: doFunc}}
	result, err := ctx.Get("http://127.0.0.1/test", nil)
	assert.NoError(t, err)
	assert.NotNil(t, result)
}

func Test_validateURL_blocked_hostname(t *testing.T) {
	ctx, err := NewHTTPWithBlocklist(DefaultBlockedHosts, nil)
	assert.NoError(t, err)
	_, err = ctx.Get("http://metadata.google.internal/computeMetadata/v1/", nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "blocked")
}

func Test_validateURL_blocks_hostname_uppercase(t *testing.T) {
	// Hostname comparisons must be case-insensitive: blocklist entry stored as
	// lowercase should still block an uppercase request hostname.
	ctx, err := NewHTTPWithBlocklist(DefaultBlockedHosts, nil)
	assert.NoError(t, err)
	_, err = ctx.Get("http://METADATA.GOOGLE.INTERNAL/computeMetadata/v1/", nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "blocked")
}

func Test_validateURL_blocks_hostname_trailing_dot(t *testing.T) {
	// The trailing-dot FQDN form is equivalent to the bare hostname; both must be blocked.
	ctx, err := NewHTTPWithBlocklist(DefaultBlockedHosts, nil)
	assert.NoError(t, err)
	_, err = ctx.Get("http://metadata.google.internal./computeMetadata/v1/", nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "blocked")
}

func Test_validateURL_allowlist_matches_explicit_default_port(t *testing.T) {
	// An allowlist entry without a port must match a request URL that includes
	// the default port for its scheme (e.g. :443 for https).
	doFunc := func(req *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(`{"ok": true}`))}, nil
	}
	allowEntry, _ := url.Parse("https://api.example.com")
	ctx := &contextImpl{
		client:             testClient{doFunc: doFunc},
		allowedURLPrefixes: []*url.URL{allowEntry},
	}
	result, err := ctx.Get("https://api.example.com:443/v1/resource", nil)
	assert.NoError(t, err)
	assert.NotNil(t, result)
}

func Test_validateURL_allowlist_matches_implicit_port_from_scheme(t *testing.T) {
	// A request URL without an explicit port must match an allowlist entry that
	// includes the default port for the scheme.
	doFunc := func(req *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(`{"ok": true}`))}, nil
	}
	allowEntry, _ := url.Parse("https://api.example.com:443")
	ctx := &contextImpl{
		client:             testClient{doFunc: doFunc},
		allowedURLPrefixes: []*url.URL{allowEntry},
	}
	result, err := ctx.Get("https://api.example.com/v1/resource", nil)
	assert.NoError(t, err)
	assert.NotNil(t, result)
}

func Test_impl_post_request_with_400_bad_request(t *testing.T) {
	base, err := compiler.NewBaseEnv()
	assert.NoError(t, err)
	assert.NotNil(t, base)
	options := []cel.EnvOption{
		cel.Variable("http", ContextType),
		Lib(nil, version.MajorMinor(1, 18)),
	}
	env, err := base.Extend(options...)
	assert.NoError(t, err)
	assert.NotNil(t, env)
	ast, issues := env.Compile(`http.post("http://localhost:8080", {"invalid": "data"})`)
	assert.Nil(t, issues)
	assert.NotNil(t, ast)
	prog, err := env.Program(ast)
	assert.NoError(t, err)
	assert.NotNil(t, prog)
	out, _, err := prog.Eval(map[string]any{
		"http": Context{&contextImpl{
			client: testClient{
				doFunc: func(req *http.Request) (*http.Response, error) {
					return &http.Response{
						StatusCode: http.StatusBadRequest,
						Body:       io.NopCloser(strings.NewReader(`{"error": "invalid request", "code": "INVALID_DATA"}`)),
					}, nil
				},
			},
		}},
	})
	assert.NoError(t, err)
	body := out.Value().(map[string]any)
	assert.Equal(t, body["error"], "invalid request")
	assert.Equal(t, body["code"], "INVALID_DATA")
	assert.Equal(t, body["statusCode"], http.StatusBadRequest)
}

func Test_impl_put_request(t *testing.T) {
	base, err := compiler.NewBaseEnv()
	assert.NoError(t, err)
	assert.NotNil(t, base)

	ctx := Context{&contextImpl{
		client: testClient{
			doFunc: func(req *http.Request) (*http.Response, error) {
				assert.Equal(t, req.URL.String(), "http://localhost:8080")
				assert.Equal(t, req.Method, "PUT")

				var data any
				err := json.NewDecoder(req.Body).Decode(&data)
				assert.NoError(t, err)
				assert.Equal(t, data.(map[string]any)["key"], "value")
				assert.Equal(t, data.(map[string]any)["foo"], float64(2))

				return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(`{"body": "updated"}`))}, nil
			},
		},
	}}

	env, err := base.Extend(
		Lib(&ctx, version.MajorMinor(1, 18)),
	)
	assert.NoError(t, err)
	assert.NotNil(t, env)
	ast, issues := env.Compile(`http.Put("http://localhost:8080", { "key": dyn("value"), "foo": dyn(2) })`)
	fmt.Println(issues.String())
	assert.Nil(t, issues)
	assert.NotNil(t, ast)
	prog, err := env.Program(ast)
	assert.NoError(t, err)
	assert.NotNil(t, prog)

	out, _, err := prog.Eval(map[string]any{})
	assert.NoError(t, err)
	body := out.Value().(map[string]any)
	assert.Equal(t, body["body"], "updated")
	assert.Equal(t, body["statusCode"], http.StatusOK)
}

func Test_impl_put_request_with_headers(t *testing.T) {
	base, err := compiler.NewBaseEnv()
	assert.NoError(t, err)
	assert.NotNil(t, base)

	ctx := Context{&contextImpl{
		client: testClient{
			doFunc: func(req *http.Request) (*http.Response, error) {
				assert.Equal(t, req.URL.String(), "http://localhost:8080")
				assert.Equal(t, req.Method, "PUT")
				assert.Equal(t, req.Header.Get("Authorization"), "Bearer token")

				var data any
				err := json.NewDecoder(req.Body).Decode(&data)
				assert.NoError(t, err)
				assert.Equal(t, data.(map[string]any)["key"], "value")

				return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(`{"body": "updated"}`))}, nil
			},
		},
	}}

	env, err := base.Extend(
		Lib(&ctx, version.MajorMinor(1, 18)),
	)
	assert.NoError(t, err)
	assert.NotNil(t, env)
	ast, issues := env.Compile(`http.Put("http://localhost:8080", {"key": "value"}, {"Authorization": "Bearer token"})`)
	fmt.Println(issues.String())
	assert.Nil(t, issues)
	assert.NotNil(t, ast)
	prog, err := env.Program(ast)
	assert.NoError(t, err)
	assert.NotNil(t, prog)

	out, _, err := prog.Eval(map[string]any{})
	assert.NoError(t, err)
	body := out.Value().(map[string]any)
	assert.Equal(t, body["body"], "updated")
	assert.Equal(t, body["statusCode"], http.StatusOK)
}

func Test_impl_put_request_string_with_client_error(t *testing.T) {
	base, err := compiler.NewBaseEnv()
	assert.NoError(t, err)
	assert.NotNil(t, base)

	env, err := base.Extend(
		Lib(nil, version.MajorMinor(1, 18)),
	)
	assert.NoError(t, err)
	assert.NotNil(t, env)
	tests := []struct {
		name string
		args []ref.Val
		want ref.Val
	}{{
		name: "not enough args",
		args: nil,
		want: types.NewErr("expected 4 arguments, got %d", 0),
	}, {
		name: "bad arg 1",
		args: []ref.Val{types.String("foo"), types.String("http://localhost:8080"), types.String("payload"), env.CELTypeAdapter().NativeToValue(make(map[string]string, 0))},
		want: types.NewErr("invalid arg 0: unsupported native conversion from string to 'http.Context'"),
	}, {
		name: "bad arg 2",
		args: []ref.Val{env.CELTypeAdapter().NativeToValue(Context{}), types.Bool(false), types.String("payload"), env.CELTypeAdapter().NativeToValue(make(map[string]string, 0))},
		want: types.NewErr("invalid arg 1: type conversion error from bool to 'string'"),
	}, {
		name: "bad arg 4",
		args: []ref.Val{env.CELTypeAdapter().NativeToValue(Context{}), types.String("http://localhost:8080"), types.String("payload"), types.Bool(false)},
		want: types.NewErr("invalid arg 3: type conversion error from bool to 'map[string]string'"),
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &impl{}
			got := c.put_request_string_with_client(tt.args...)
			assert.Equal(t, tt.want, got)
		})
	}
}
