package anchore

//update this to match the anchroe API response body
type ScanResult struct {
	ImageDigest     string          `json:"imageDigest"`
	Vulnerabilities []Vulnerability `json:"Vulnerabilities"`
}

type Vulnerability struct {
	VulnerabilityID  string `json:"vuln"`
	PkgName          string `json:"package_name"`
	InstalledVersion string `json:"package_version"`
	Package_type     string `json:"package_type"`
	Package          string `json:"package"`
	URL              string `json:"url"`
	Fix              string `json:"fix"`
	// HIGH / MEDIUM / LOW
	Severity string `json:"severity"`
}
