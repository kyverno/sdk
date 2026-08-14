package http

import (
	"fmt"
	"reflect"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/ext"
	"github.com/kyverno/sdk/extensions/cel/libs/versions"
	"k8s.io/apimachinery/pkg/util/version"
)

const libraryName = "kyverno.http"

type lib struct {
	httpIface ContextInterface
	version   *version.Version
}

func Latest() *version.Version {
	return versions.KyvernoLatest
}

func Lib(httpCtx ContextInterface, v *version.Version) cel.EnvOption {
	if v == nil {
		panic(libraryName + ": library version must not be nil")
	}
	// create the cel lib env option
	return cel.Lib(&lib{httpIface: httpCtx, version: v})
}

func (*lib) LibraryName() string {
	return libraryName
}

func (c *lib) CompileOptions() []cel.EnvOption {
	return []cel.EnvOption{
		cel.Variable("http", ContextType),
		ext.NativeTypes(reflect.TypeFor[Context]()),
		c.extendEnv,
	}
}

func (l *lib) ProgramOptions() []cel.ProgramOption {
	return []cel.ProgramOption{
		cel.Globals(
			map[string]any{
				"http": l.httpIface,
			},
		),
	}
}

func (c *lib) extendEnv(env *cel.Env) (*cel.Env, error) {
	impl := impl{
		Adapter: env.CELTypeAdapter(),
	}

	buildGetOverloads := func(suffix string) []cel.FunctionOpt {
		return []cel.FunctionOpt{
			cel.MemberOverload(
				fmt.Sprintf("http_get_string_%s", suffix),
				[]*cel.Type{ContextType, types.StringType},
				types.AnyType,
				cel.BinaryBinding(impl.get_request_string),
			),
			cel.MemberOverload(
				fmt.Sprintf("http_get_string_headers_%s", suffix),
				[]*cel.Type{ContextType, types.StringType, types.NewMapType(types.StringType, types.StringType)},
				types.AnyType,
				cel.FunctionBinding(impl.get_request_with_headers_string),
			),
		}
	}

	buildPostOverloads := func(suffix string) []cel.FunctionOpt {
		return []cel.FunctionOpt{
			cel.MemberOverload(
				fmt.Sprintf("http_post_string_any_%s", suffix),
				[]*cel.Type{ContextType, types.StringType, types.AnyType},
				types.AnyType,
				cel.FunctionBinding(impl.post_request_string),
			),
			cel.MemberOverload(
				fmt.Sprintf("http_post_string_any_headers_%s", suffix),
				[]*cel.Type{ContextType, types.StringType, types.AnyType, types.NewMapType(types.StringType, types.StringType)},
				types.AnyType,
				cel.FunctionBinding(impl.post_request_with_headers_string),
			),
		}
	}

	buildPutOverloads := func(suffix string) []cel.FunctionOpt {
		return []cel.FunctionOpt{
			cel.MemberOverload(
				fmt.Sprintf("http_put_string_any_%s", suffix),
				[]*cel.Type{ContextType, types.StringType, types.AnyType},
				types.AnyType,
				cel.FunctionBinding(impl.put_request_string),
			),
			cel.MemberOverload(
				fmt.Sprintf("http_put_string_any_headers_%s", suffix),
				[]*cel.Type{ContextType, types.StringType, types.AnyType, types.NewMapType(types.StringType, types.StringType)},
				types.AnyType,
				cel.FunctionBinding(impl.put_request_with_headers_string),
			),
		}
	}

	buildPatchOverloads := func(suffix string) []cel.FunctionOpt {
		return []cel.FunctionOpt{
			cel.MemberOverload(
				fmt.Sprintf("http_patch_string_any_%s", suffix),
				[]*cel.Type{ContextType, types.StringType, types.AnyType},
				types.AnyType,
				cel.FunctionBinding(impl.patch_request_string),
			),
			cel.MemberOverload(
				fmt.Sprintf("http_patch_string_any_headers_%s", suffix),
				[]*cel.Type{ContextType, types.StringType, types.AnyType, types.NewMapType(types.StringType, types.StringType)},
				types.AnyType,
				cel.FunctionBinding(impl.patch_request_with_headers_string),
			),
		}
	}

	buildDeleteOverloads := func(suffix string) []cel.FunctionOpt {
		return []cel.FunctionOpt{
			cel.MemberOverload(
				fmt.Sprintf("http_delete_string_%s", suffix),
				[]*cel.Type{ContextType, types.StringType},
				types.AnyType,
				cel.BinaryBinding(impl.delete_request_string),
			),
			cel.MemberOverload(
				fmt.Sprintf("http_delete_string_headers_%s", suffix),
				[]*cel.Type{ContextType, types.StringType, types.NewMapType(types.StringType, types.StringType)},
				types.AnyType,
				cel.FunctionBinding(impl.delete_request_with_headers_string),
			),
		}
	}

	buildClientOverloads := func(suffix string) []cel.FunctionOpt {
		return []cel.FunctionOpt{
			cel.MemberOverload(
				fmt.Sprintf("http_client_string_%s", suffix),
				[]*cel.Type{ContextType, types.StringType},
				ContextType,
				cel.BinaryBinding(impl.http_client_string),
			),
		}
	}
	// build our function overloads
	libraryDecls := map[string][]cel.FunctionOpt{
		"Get":    buildGetOverloads("pascal"),
		"Post":   buildPostOverloads("pascal"),
		"Put":    buildPutOverloads("pascal"),
		"Patch":  buildPatchOverloads("pascal"),
		"Delete": buildDeleteOverloads("pascal"),
		"Client": buildClientOverloads("pascal"),
	}

	if c.version.AtLeast(version.MajorMinor(1, 18)) {
		libraryDecls["get"] = buildGetOverloads("camel")
		libraryDecls["post"] = buildPostOverloads("camel")
		libraryDecls["put"] = buildPutOverloads("camel")
		libraryDecls["patch"] = buildPatchOverloads("camel")
		libraryDecls["delete"] = buildDeleteOverloads("camel")
		libraryDecls["client"] = buildClientOverloads("camel")
	}
	// create env options corresponding to our function overloads
	options := []cel.EnvOption{}
	for name, overloads := range libraryDecls {
		options = append(options, cel.Function(name, overloads...))
	}
	// extend environment with our function overloads
	return env.Extend(options...)
}
