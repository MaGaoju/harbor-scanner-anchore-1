package anchore

//update this to match the anchroe API response body
type ScanResult struct {
	ImageDigest          string     `json:"imageDigest"`
	Vulnerabilities []Vulnerability `json:"Vulnerabilities"`
}

type Vulnerability struct {
	VulnerabilityID  string `json:"vuln"`
	PkgName          string `json:"package_name"`
	InstalledVersion string `json:"package_version"`
	Package_type     string `json:"package_type"`
	Package          string `json:"package"`
	URL      		 string `json:"url"`
	// HIGH / MEDIUM / LOW
	Severity   string   `json:"severity"`
	References []string `json:"References"`
}

type ScanImagePostReq struct {
	P_dockerfile  string   `json:"dockerfile"`
	P_digest      string   `json:"digest"`
	P_tag         string   `json:"tag"`
	P_created_at  string   `json:"created_at"`
	P_image_type  string   `json:"image_type"`
	P_annotations []string `json:"annotations"`
}
