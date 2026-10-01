package dpol

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

var dpolCompilerVersion = version.MajorMinor(1, 0)

func NewEnv() (*environment.EnvSet, *compiler.VariablesProvider, error) {
	baseOpts := compiler.DefaultEnvOptions()
	baseOpts = append(baseOpts,
		cel.Variable(compiler.ObjectKey, cel.DynType),
		cel.Variable(compiler.VariablesKey, compiler.VariablesType),
	)
	base := environment.MustBaseEnvSet(dpolCompilerVersion)
	env, err := base.Env(environment.StoredExpressions)
	if err != nil {
		return nil, nil, err
	}
	variablesProvider := compiler.NewVariablesProvider(env.CELTypeProvider())
	declProvider := apiservercel.NewDeclTypeProvider()
	declOptions, err := declProvider.EnvOptions(variablesProvider)
	if err != nil {
		return nil, nil, err
	}
	baseOpts = append(baseOpts, declOptions...)
	extendedBase, err := base.Extend(
		environment.VersionedOptions{
			IntroducedVersion: dpolCompilerVersion,
			EnvOptions:        baseOpts,
		},
		environment.VersionedOptions{
			IntroducedVersion: dpolCompilerVersion,
			EnvOptions: []cel.EnvOption{
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
