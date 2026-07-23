package generator

import (
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/kyverno/sdk/extensions/cel/utils"
	"google.golang.org/protobuf/types/known/structpb"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
)

type namespacedImpl struct {
	namespace string
	types.Adapter
}

func (c *namespacedImpl) apply_generator_list(args ...ref.Val) ref.Val {
	if self, err := utils.GetArg[Context](args, 0); err != nil {
		return err
	} else if dataList, err := utils.GetArg[[]*structpb.Struct](args, 1); err != nil {
		return err
	} else {
		var resources []map[string]any
		for _, data := range dataList {
			resources = append(resources, data.AsMap())
		}
		if err := self.GenerateResources(c.namespace, resources); err != nil {
			if apierrors.IsForbidden(err) || apierrors.IsUnauthorized(err) {
				return types.NewErr("failed to generate resources: permission denied: %v", err)
			}
			return types.NewErr("failed to generate resources: %v", err)
		}
		return types.True
	}
}
