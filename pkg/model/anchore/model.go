package anchore

type ScanResult struct {
	Target          string          `json:"Target"`
	Vulnerabilities []Vulnerability `json:"Vulnerabilities"`
}

type Vulnerability struct {
	VulnerabilityID  string `json:"VulnerabilityID"`
	PkgName          string `json:"PkgName"`
	InstalledVersion string `json:"InstalledVersion"`
	Title            string `json:"Title"`
	Description      string `json:"Description"`
	// HIGH / MEDIUM / LOW
	Severity   string   `json:"Severity"`
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

type ScanImagePostRsponse struct {
	resdigest string
}

type ScanImagesGegReq struct {
	G_tag    string `json:"tag"`
	G_digest string `json:"digest"`
}
