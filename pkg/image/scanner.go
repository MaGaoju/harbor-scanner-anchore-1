package image

import "github.com/cafeliker/harbor-scanner-anchore/pkg/model/harbor"

// Scanner defines methods for scanning container images.
type Scanner interface {
	Scan(req harbor.ScanRequest) (*harbor.ScanResponse, error)
	GetResult(digest string) (*harbor.ScanResult, error)
}
