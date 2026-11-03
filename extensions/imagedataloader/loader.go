package imagedataloader

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"sync"

	"github.com/google/go-containerregistry/pkg/name"
	gcrv1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/kyverno/api/api/policies.kyverno.io/v1beta1"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	corev1listers "k8s.io/client-go/listers/core/v1"
)

const (
	maxReferrersCount = 50
	// defaultPayloadLimit bounds a referrer payload read. It is a limit on
	// decompressed bytes, so a payload that compresses well -- an SBOM attestation
	// is the usual case -- can exceed it while still being small on the wire.
	defaultPayloadLimit = int64(10 * 1000 * 1000) // 10 MB
	// maxReferrersIndexSize bounds the referrers index body before it is
	// unmarshalled. go-containerregistry has already fetched and buffered the body
	// by the time Referrers returns, so this cannot stop the download -- what it
	// stops is the unmarshal, which is where the cost lands: a 34 MB index expands
	// to roughly 400 MB of Go structs. A legitimate index of maxReferrersCount
	// entries is a few tens of kilobytes.
	maxReferrersIndexSize = int64(1000 * 1000) // 1 MB
)

// payloadLimit is configuration for callers whose payloads do not fit the
// default. Bounding these reads is what stops a decompression bomb, so the limit
// can be changed but never disabled.
var payloadLimit = defaultPayloadLimit

// PayloadLimit returns the configured bound for referrer payload reads.
func PayloadLimit() int64 {
	return payloadLimit
}

// SetPayloadLimit overrides the payload bound. Call it once at startup, before
// any fetch. A non-positive value leaves the current limit in place, so the bound
// cannot be disabled; a smaller positive value tightens it, which will refuse
// payloads that previously read.
func SetPayloadLimit(n int64) {
	if n > 0 {
		payloadLimit = n
	}
}

type Fetcher interface {
	FetchImageData(ctx context.Context, image string, authOpts []remote.Option, nameOpts []name.Option) (*ImageData, error)
}

type imagedatafetcher struct {
	lister          corev1listers.SecretLister
	defaultOptions  []remote.Option
	defaultNameOpts []name.Option
}

func New(lister corev1listers.SecretLister, defaultAuthOpts []remote.Option, defaultNameOpts []name.Option) (*imagedatafetcher, error) {
	return &imagedatafetcher{
		lister:          lister,
		defaultOptions:  defaultAuthOpts,
		defaultNameOpts: defaultNameOpts,
	}, nil
}

func (i *imagedatafetcher) FetchImageData(ctx context.Context, image string, authOpts []remote.Option, nameOpts []name.Option) (*ImageData, error) {
	img := ImageData{
		nameOpts: nameOpts,
	}

	// create the initial set of remote options and add to them the auth options
	img.remoteOpts = i.remoteOptions(ctx)
	img.remoteOpts = append(img.remoteOpts, authOpts...)

	imgRef, err := ParseImageReference(image, img.nameOpts)
	if err != nil {
		return nil, err
	}

	img.ImageReference = imgRef

	ref, err := name.ParseReference(image, img.nameOpts...)
	if err != nil {
		return nil, err
	}
	img.nameRef = ref

	// fetch the descriptor rather than the image. remote.Image would resolve an index down to
	// a single platform here, defaulting to linux/amd64, whereas a descriptor leaves the index
	// intact so the child can be chosen below. it also carries the digest recorded on the
	// result, and the raw index manifest exposed to policies.
	desc, err := remote.Get(ref, img.remoteOpts...)
	if err != nil {
		return nil, err
	}
	img.desc = desc

	remoteImg, err := imageForDescriptor(desc)
	if err != nil {
		return nil, err
	}

	img.Manifest, err = remoteImg.Manifest()
	if err != nil {
		return nil, err
	}

	// an attacker-authored config descriptor otherwise sizes this read
	if img.Manifest.Config.Size > defaultPayloadLimit {
		return nil, fmt.Errorf("config size %d exceeds %d", img.Manifest.Config.Size, defaultPayloadLimit)
	}

	img.ConfigData, err = remoteImg.ConfigFile()
	if err != nil {
		return nil, err
	}

	if len(img.Digest) == 0 {
		img.Digest = desc.Digest.String()
	}

	if len(img.Tag) > 0 {
		img.ResolvedImage = fmt.Sprintf("%s:%s@%s", ref.Context().Name(), img.Tag, img.Digest)
	} else {
		img.ResolvedImage = fmt.Sprintf("%s@%s", ref.Context().Name(), img.Digest)
	}

	// error returned means no image index
	imgIndex, _ := desc.ImageIndex()
	if imgIndex != nil {
		imgIndexBytes, err := imgIndex.RawManifest()
		if err != nil {
			return nil, err
		}
		if err := json.Unmarshal(imgIndexBytes, &img.ImageIndex); err != nil {
			return nil, err
		}
	}

	return &img, nil
}

func (i *imagedatafetcher) remoteOptions(ctx context.Context) []remote.Option {
	var opts []remote.Option
	opts = append(opts, i.defaultOptions...) // append the options we created in new

	opts = append(opts, remote.WithContext(ctx))
	opts = append(opts, remote.WithRetryStatusCodes(
		http.StatusRequestTimeout,
		http.StatusInternalServerError,
		http.StatusBadGateway,
		http.StatusServiceUnavailable,
		http.StatusGatewayTimeout,
		499, // nginx-specific, client closed request
		522, // Cloudflare-specific, connection timeout
		429, // Too Many Requests
	))

	return opts
}

type ImageDescriptor struct {
	ImageReference `json:",inline"`
	ImageIndex     any               `json:"imageIndex,omitempty"`
	Manifest       *gcrv1.Manifest   `json:"manifest,omitempty"`
	ConfigData     *gcrv1.ConfigFile `json:"config,omitempty"`
}

type referrerData struct {
	layerDescriptor *gcrv1.Descriptor
	data            []byte
}

// ImageData is safe for concurrent use. The referrers it caches and the payloads
// recorded as verified are guarded by a mutex that is never held across a
// registry call, so two callers missing the cache at once may both fetch.
//
// That does not make one ImageData safe to share across policies: what one
// policy records as verified would be returned to another's GetPayload. Keep a
// separate ImageData, and so a separate ImageContext, per policy.
type ImageData struct {
	ImageDescriptor        `json:",inline"`
	remoteOpts             []remote.Option
	nameOpts               []name.Option
	nameRef                name.Reference
	desc                   *remote.Descriptor
	mu                     sync.Mutex // guards the fields below
	referrersManifest      *gcrv1.IndexManifest
	referrersData          map[string]referrerData
	verifiedReferrers      map[string][]gcrv1.Descriptor
	verifiedIntotoPayloads map[string][]byte
}

func (i *ImageData) FetchReference(identifier string) (ocispec.Descriptor, error) {
	if identifier == i.Digest {
		return GCRtoOCISpecDesc(i.desc.Descriptor), nil
	}
	i.mu.Lock()
	referrers := i.referrersManifest
	i.mu.Unlock()
	if referrers != nil {
		for _, m := range referrers.Manifests {
			if identifier == m.Digest.String() {
				return GCRtoOCISpecDesc(m), nil
			}
		}
	}
	d, err := remote.Head(i.nameRef.Context().Digest(identifier), i.remoteOpts...)
	if err != nil {
		return ocispec.Descriptor{}, err
	}
	return GCRtoOCISpecDesc(*d), nil
}

func (i *ImageData) WithDigest(digest string) string {
	return i.nameRef.Context().Digest(digest).String()
}

func (i *ImageData) Data() ImageDescriptor {
	return i.ImageDescriptor
}

func (i *ImageData) RemoteOpts() []remote.Option {
	return i.remoteOpts
}

func (i *ImageData) NameOpts() []name.Option {
	return i.nameOpts
}

func (i *ImageData) NameRef() name.Reference {
	return i.nameRef
}

func (i *ImageData) FetchReferrersForDigest(digest string, artifactType string) ([]gcrv1.Descriptor, error) {
	// If the call is for image referrers, return prefetched referrers
	if digest == i.Digest {
		return i.FetchReferrers(artifactType)
	}

	// this is most likely a call to fetch notary signatures for an attesatation
	idx, err := i.fetchReferrersFromRemote(digest)
	if err != nil {
		return nil, err
	}

	refList := make([]gcrv1.Descriptor, 0)
	for _, ref := range idx.Manifests {
		if ref.ArtifactType == artifactType {
			refList = append(refList, ref)
		}
	}

	return refList, nil
}

func (i *ImageData) FetchReferrers(artifactType string) ([]gcrv1.Descriptor, error) {
	referrers, err := i.loadReferrers()
	if err != nil {
		return nil, err
	}

	refList := make([]gcrv1.Descriptor, 0)
	for _, ref := range referrers.Manifests {
		if ref.ArtifactType == artifactType {
			refList = append(refList, ref)
		}
	}

	return refList, nil
}

func (i *ImageData) FetchReferrerData(desc gcrv1.Descriptor) ([]byte, *gcrv1.Descriptor, error) {
	key := desc.Digest.String()
	i.mu.Lock()
	v, found := i.referrersData[key]
	i.mu.Unlock()
	if found {
		return v.data, v.layerDescriptor, nil
	}

	img, err := remote.Image(i.nameRef.Context().Digest(key), i.remoteOpts...)
	if err != nil {
		return nil, nil, err
	}

	layers, err := img.Layers()
	if err != nil {
		return nil, nil, err
	}

	if len(layers) != 1 {
		return nil, nil, fmt.Errorf("invalid referrer descriptor, must have only one layer")
	}
	layer := layers[0]

	size, err := layer.Size()
	if err != nil {
		return nil, nil, err
	}
	digest, err := layer.Digest()
	if err != nil {
		return nil, nil, err
	}
	mediaType, err := layer.MediaType()
	if err != nil {
		return nil, nil, err
	}

	layerDesc := &gcrv1.Descriptor{
		MediaType: mediaType,
		Digest:    digest,
		Size:      size,
	}

	b, err := readLayerLimited(layer, payloadLimit)
	if err != nil {
		return nil, nil, err
	}

	i.mu.Lock()
	defer i.mu.Unlock()
	// keep data stored by a concurrent miss, so the bytes a caller verified are
	// the bytes GetPayload returns later
	if v, found := i.referrersData[key]; found {
		return v.data, v.layerDescriptor, nil
	}
	if i.referrersData == nil {
		i.referrersData = make(map[string]referrerData)
	}
	i.referrersData[key] = referrerData{
		data:            b,
		layerDescriptor: layerDesc,
	}
	return b, layerDesc, nil
}

// AddVerifiedReferrer records desc as verified for its artifact type. Several
// referrers of the same type can be recorded; a digest already recorded is ignored.
func (i *ImageData) AddVerifiedReferrer(desc gcrv1.Descriptor) {
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.verifiedReferrers == nil {
		i.verifiedReferrers = make(map[string][]gcrv1.Descriptor, 0)
	}

	for _, d := range i.verifiedReferrers[desc.ArtifactType] {
		if d.Digest == desc.Digest {
			return
		}
	}
	i.verifiedReferrers[desc.ArtifactType] = append(i.verifiedReferrers[desc.ArtifactType], desc)
}

// SetVerifiedReferrers reorders or narrows the referrers recorded as verified
// for artifactType to those in descs, in the order given. GetPayload reads the
// first, so a caller can use this to choose which verified referrer it returns.
// It never marks anything verified: a digest not already recorded through
// AddVerifiedReferrer is ignored, and if none of descs is recorded the type is
// cleared.
func (i *ImageData) SetVerifiedReferrers(artifactType string, descs []gcrv1.Descriptor) {
	i.mu.Lock()
	defer i.mu.Unlock()
	recorded := i.verifiedReferrers[artifactType]
	verified := make([]gcrv1.Descriptor, 0, len(recorded))
	for _, desc := range descs {
		sameDigest := func(d gcrv1.Descriptor) bool { return d.Digest == desc.Digest }
		if n := slices.IndexFunc(recorded, sameDigest); n >= 0 && !slices.ContainsFunc(verified, sameDigest) {
			verified = append(verified, recorded[n])
		}
	}
	if len(verified) == 0 {
		delete(i.verifiedReferrers, artifactType)
		return
	}
	i.verifiedReferrers[artifactType] = verified
}

// VerifiedReferrers returns a copy of the referrers recorded as verified for artifactType.
func (i *ImageData) VerifiedReferrers(artifactType string) []gcrv1.Descriptor {
	i.mu.Lock()
	defer i.mu.Unlock()
	return slices.Clone(i.verifiedReferrers[artifactType])
}

func (i *ImageData) AddVerifiedIntotoPayloads(predicateType string, data []byte) {
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.verifiedIntotoPayloads == nil {
		i.verifiedIntotoPayloads = make(map[string][]byte, 0)
	}

	i.verifiedIntotoPayloads[predicateType] = data
}

func (i *ImageData) GetPayload(a v1beta1.Attestation) (any, error) {
	var b []byte
	if a.IsInToto() {
		var ok bool
		i.mu.Lock()
		b, ok = i.verifiedIntotoPayloads[a.InToto.Type]
		i.mu.Unlock()
		if !ok {
			// download this using cosign cli
			return nil, fmt.Errorf("intoto attestation payload cannot be fetch before verifying intoto attestation")
		}
	} else if a.IsReferrer() {
		descs := i.VerifiedReferrers(a.Referrer.Type)
		if len(descs) == 0 {
			return nil, fmt.Errorf("referrer attestation payload of type %s cannot be fetched before verifying referrer attestation", a.Referrer.Type)
		}
		var err error
		b, _, err = i.FetchReferrerData(descs[0])
		if err != nil {
			return nil, err
		}
	}

	if len(b) == 0 {
		return nil, fmt.Errorf("could not find attestation %s", a.GetKey())
	}

	var payload any

	if err := json.Unmarshal(b, &payload); err != nil {
		return nil, fmt.Errorf("failed to unmarshal json for attestation %s", a.GetKey())
	}

	return payload, nil
}

// loadReferrers returns the image's referrers, fetching them on first use. The
// returned index is never modified, so it can be read without the lock.
func (i *ImageData) loadReferrers() (*gcrv1.IndexManifest, error) {
	i.mu.Lock()
	referrers := i.referrersManifest
	i.mu.Unlock()
	if referrers != nil {
		return referrers, nil
	}

	referrers, err := i.fetchReferrersFromRemote(i.Digest)
	if err != nil {
		return nil, err
	}

	i.mu.Lock()
	defer i.mu.Unlock()
	if i.referrersManifest == nil {
		i.referrersManifest = referrers
	}
	return i.referrersManifest, nil
}

func (i *ImageData) fetchReferrersFromRemote(digest string) (*gcrv1.IndexManifest, error) {
	referrers, err := remote.Referrers(i.nameRef.Context().Digest(digest), i.remoteOpts...)
	if err != nil {
		return nil, err
	}

	referrersDescs, err := referrersIndexManifest(referrers)
	if err != nil {
		return nil, err
	}

	// This check ensures that the manifest does not have an abnormal amount of referrers attached to it to protect against compromised images
	if len(referrersDescs.Manifests) > maxReferrersCount {
		return nil, fmt.Errorf("failed to fetch referrers: to many referrers found, max limit is %d", maxReferrersCount)
	}

	return referrersDescs, nil
}

// referrersIndex is the part of gcrv1.ImageIndex the bound needs: the buffered
// body and the unmarshal it guards.
type referrersIndex interface {
	RawManifest() ([]byte, error)
	IndexManifest() (*gcrv1.IndexManifest, error)
}

// referrersIndexManifest unmarshals a referrers index only after its body fits
// the limit. The count cap in fetchReferrersFromRemote runs on the parsed index,
// so it cannot prevent the allocation it exists to prevent; this can.
func referrersIndexManifest(index referrersIndex) (*gcrv1.IndexManifest, error) {
	raw, err := index.RawManifest()
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > maxReferrersIndexSize {
		return nil, fmt.Errorf("failed to fetch referrers: index size %d exceeds %d", len(raw), maxReferrersIndexSize)
	}
	return index.IndexManifest()
}
