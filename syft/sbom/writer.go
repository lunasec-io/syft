package sbom

import "io"

type Writer interface {
	Write(SBOM) error
	io.Closer
}
