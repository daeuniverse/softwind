package obfs

import (
	rand "github.com/mzz2017/softwind/pkg/fastrand"
)

func init() {
	register("http_post", newHttpPost)
}

// newHttpPost create a http_post object
func newHttpPost() IObfs {
	// newHttpSimple create a http_simple object

	t := &httpSimplePost{
		userAgentIndex: rand.Intn(len(requestUserAgent)),
		methodGet:      false,
	}
	return t
}
