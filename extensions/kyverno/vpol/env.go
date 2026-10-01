package vpol

import (
	"github.com/google/cel-go/cel"
	"github.com/kyverno/sdk/extensions/cel/compiler"
	"github.com/kyverno/sdk/extensions/cel/libs/globalcontext"
	"github.com/kyverno/sdk/extensions/cel/libs/gzip"
	"github.com/kyverno/sdk/extensions/cel/libs/hash"
	"github.com/kyverno/sdk/extensions/cel/libs/http"
	"github.com/kyverno/sdk/extensions/cel/libs/image"
	"github.com/kyverno/sdk/extensions/cel/libs/imagedata"
	"github.com/kyverno/sdk/extensions/cel/libs/json"
	"github.com/kyverno/sdk/extensions/cel/libs/math"
	"github.com/kyverno/sdk/extensions/cel/libs/random"
	"github.com/kyverno/sdk/extensions/cel/libs/resource"
	"github.com/kyverno/sdk/extensions/cel/libs/time"
	"github.com/kyverno/sdk/extensions/cel/libs/transform"
	"github.com/kyverno/sdk/extensions/cel/libs/user"
	"github.com/kyverno/sdk/extensions/cel/libs/x509"
	"github.com/kyverno/sdk/extensions/cel/libs/yaml"
	"k8s.io/apimachinery/pkg/util/version"
	apiservercel "k8s.io/apiserver/pkg/cel"
	"k8s.io/apiserver/pkg/cel/environment"
)

var (
	vpolCompilerVersion = version.MajorMinor(1, 0)
	// compileError        = "validating policy compiler " + vpolCompilerVersion.String() + " error: %s"
)

func NewEnv() (*environment.EnvSet, *compiler.VariablesProvider, error) {
	baseOpts := compiler.DefaultEnvOptions()
	baseOpts = append(baseOpts,
		cel.Variable(compiler.NamespaceObjectKey, compiler.NamespaceType.CelType()),
		cel.Variable(compiler.ObjectKey, cel.DynType),
		cel.Variable(compiler.OldObjectKey, cel.DynType),
		cel.Variable(compiler.RequestKey, compiler.RequestType.CelType()),
		cel.Types(compiler.NamespaceType.CelType()),
		cel.Types(compiler.RequestType.CelType()),
		cel.Variable(compiler.VariablesKey, compiler.VariablesType),
	)
	base := environment.MustBaseEnvSet(vpolCompilerVersion)
	env, err := base.Env(environment.StoredExpressions)
	if err != nil {
		return nil, nil, err
	}
	variablesProvider := compiler.NewVariablesProvider(env.CELTypeProvider())
	declProvider := apiservercel.NewDeclTypeProvider(compiler.NamespaceType, compiler.RequestType)
	declOptions, err := declProvider.EnvOptions(variablesProvider)
	if err != nil {
		return nil, nil, err
	}
	baseOpts = append(baseOpts, declOptions...)
	// the custom types have to be registered after the decl options have been registered, because these are what allow
	// go struct type resolution
	extendedBase, err := base.Extend(
		environment.VersionedOptions{
			IntroducedVersion: vpolCompilerVersion,
			EnvOptions:        baseOpts,
		},
		// libaries
		environment.VersionedOptions{
			IntroducedVersion: vpolCompilerVersion,
			EnvOptions: []cel.EnvOption{
				// ext.NativeTypes(reflect.TypeFor[libs.Exception](), ext.ParseStructTags(true)),
				// cel.Variable(compiler.ExceptionsKey, types.NewObjectType("libs.Exception")),
				globalcontext.Lib(
					nil,
					globalcontext.Latest(),
				),
				http.Lib(
					http.Context{ContextInterface: http.NewHTTP()},
					http.Latest(),
				),
				resource.Lib(
					nil,
					// TODO: namespace
					"",
					resource.Latest(),
				),
				image.Lib(
					image.Latest(),
				),
				imagedata.Lib(
					nil,
					imagedata.Latest(),
					nil,
				),
				user.Lib(
					user.Latest(),
				),
				hash.Lib(
					hash.Latest(),
				),
				math.Lib(
					math.Latest(),
				),
				json.Lib(
					&json.JsonImpl{},
					json.Latest(),
				),
				yaml.Lib(
					&yaml.YamlImpl{},
					yaml.Latest(),
				),
				random.Lib(
					random.Latest(),
				),
				x509.Lib(
					x509.Latest(),
				),
				time.Lib(
					time.Latest(),
				),
				transform.Lib(
					transform.Latest(),
				),
				gzip.Lib(
					gzip.Latest(),
				),
			},
		},
	)
	if err != nil {
		return nil, nil, err
	}
	return extendedBase, variablesProvider, nil
}
