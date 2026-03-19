package gzip

import (
	"bytes"
	"compress/gzip"
	"io"
	"time"

	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/kyverno/sdk/cel/utils"
)

type impl struct {
	types.Adapter
}

func (i *impl) decompress_string(gzBytes ref.Val) ref.Val {
	if data, err := utils.ConvertToNative[[]byte](gzBytes); err != nil {
		return types.WrapErr(err)
	} else {
		r, err := gzip.NewReader(bytes.NewReader(data))
		if err != nil {
			return types.WrapErr(err)
		}
		defer r.Close() //nolint:errcheck

		out, err := io.ReadAll(r)
		if err != nil {
			return types.WrapErr(err)
		}

		return i.NativeToValue(string(out))
	}
}

func (i *impl) compress(value ref.Val) ref.Val {
	if native, err := utils.ConvertToNative[string](value); err != nil {
		return types.WrapErr(err)
	} else {
		var buf bytes.Buffer
		w := gzip.NewWriter(&buf)
		w.Header.ModTime = time.Unix(0, 0) // to make compression deterministic

		_, err = w.Write([]byte(native))
		if err != nil {
			return types.WrapErr(err)
		}

		err = w.Close()
		if err != nil {
			return types.WrapErr(err)
		}

		return i.NativeToValue(buf.Bytes())
	}
}
