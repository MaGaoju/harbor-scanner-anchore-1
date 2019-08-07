package anchore

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"github.com/cafeliker/harbor-scanner-anchore/pkg/etc"
	"github.com/cafeliker/harbor-scanner-anchore/pkg/image"
	"github.com/cafeliker/harbor-scanner-anchore/pkg/model/anchore"
	"github.com/cafeliker/harbor-scanner-anchore/pkg/model/harbor"
	"github.com/google/uuid"
	"github.com/parnurzeal/gorequest"
)

type imageScanner struct {
	cfg *etc.Config
}

type ScanImagePostRsponse struct {
	imageDigest  string
}

// NewScanner constructs new Scanner with the given Config.
func NewScanner(cfg *etc.Config) (image.Scanner, error) {
	if cfg == nil {
		return nil, errors.New("cfg must not be nil")
	}
	return &imageScanner{
		cfg: cfg,
	}, nil
}

func (s *imageScanner) Scan(req harbor.ScanRequest) (*harbor.ScanResponse, error) {
	scanID, err := uuid.NewRandom()
	if err != nil {
		return nil, err
	}

	log.Printf("RegistryURL: %s", req.RegistryURL)
	log.Printf("Repository: %s", req.Repository)
	log.Printf("Tag: %s", req.Tag)
	log.Printf("Digest: %s", req.Digest)
	log.Printf("Scan request: %s", scanID.String())

	registryURL := req.RegistryURL
	if s.cfg.Addr != "" {
		log.Printf("Overwriting registry URL %s with %s", req.RegistryURL, s.cfg.Addr)
		registryURL = s.cfg.Addr
	}

	imageToScan := fmt.Sprintf("%s/%s:%s", registryURL, req.Repository, req.Tag)

	log.Printf("Started scanning %s ...", imageToScan)

	/*executable, err := exec.LookPath("trivy")
	if err != nil {
		return nil, err
	}*/

	/*get image brfore post it*/

	request := gorequest.New().SetBasicAuth(s.cfg.ScannerUsername, s.cfg.ScannerPassword)
	resp, body, errs := request.Get(s.cfg.Addr+"/images").Param(
		"imageDigest", req.Digest,
	).End()
	if errs != nil {
		log.Printf("Http code: %d", resp.StatusCode)
		log.Printf("Http body: %d", body)
	}

	imageToScanReq := &anchore.ScanImagePostReq{
		P_dockerfile: imageToScan,
		P_digest:     req.Digest,
		P_tag:        req.Tag,
	}

	resp, body, errs = request.Post(registryURL + "/iamges").Send(imageToScanReq).End()

	log.Println(body)

	var data []ScanImagePostRsponse
	err = json.NewDecoder(resp.Body).Decode(&data)
	//update return data later: need return ID which can help to pass to GetResult method
	log.Println(data)
	return &harbor.ScanResponse{
		DetailsKey: scanID.String()
	}, nil
}

// update method and paramenter passed in
func (s *imageScanner) GetResult(imageDigest string) (*harbor.ScanResult, error) {

	if imageDigest == "" {
		return nil, errors.New("response body is empty")
	}
	var data []anchore.ScanResult
	request := gorequest.New().SetBasicAuth(s.cfg.ScannerUsername, s.cfg.ScannerPassword)
	resp, body, errs := request.Get(s.cfg.Addr+"/images").Param(
		"imageDigest", imageDigest,
	).End()
	//check ancher return restul structure, update result struct in file model.go
	json.NewDecoder(resp.Body).Decode(&data)

	return s.toHarborScanResult(data)
}

func (s *imageScanner) toHarborScanResult(srs []anchore.ScanResult) (*harbor.ScanResult, error) {
	var vulnerabilities []*harbor.VulnerabilityItem

	for _, sr := range srs {
		for _, v := range sr.Vulnerabilities {
			vulnerabilities = append(vulnerabilities, &harbor.VulnerabilityItem{
				ID:          v.VulnerabilityID,
				Severity:    s.toHarborSeverity(v.Severity),
				Pkg:         v.PkgName,
				Version:     v.InstalledVersion,
				Description: v.Description,
			})
		}
	}

	severity, overview := s.toComponentsOverview(srs)

	return &harbor.ScanResult{
		Severity:        severity,
		Overview:        overview,
		Vulnerabilities: vulnerabilities,
	}, nil
}

func (s *imageScanner) toHarborSeverity(severity string) harbor.Severity {
	switch severity {
	case "HIGH", "CRITICAL":
		return harbor.SevHigh
	case "MEDIUM":
		return harbor.SevMedium
	case "LOW":
		return harbor.SevLow
	case "UNKNOWN":
		return harbor.SevUnknown
	default:
		log.Printf("Unknown xxxx severity %s", severity)
		return harbor.SevUnknown
	}
}

func (s *imageScanner) toComponentsOverview(srs []anchore.ScanResult) (harbor.Severity, *harbor.ComponentsOverview) {
	overallSev := harbor.SevNone
	total := 0
	sevToCount := map[harbor.Severity]int{
		harbor.SevHigh:    0,
		harbor.SevMedium:  0,
		harbor.SevLow:     0,
		harbor.SevUnknown: 0,
		harbor.SevNone:    0,
	}

	for _, sr := range srs {
		for _, vln := range sr.Vulnerabilities {
			sev := s.toHarborSeverity(vln.Severity)
			sevToCount[sev]++
			total++
			if sev > overallSev {
				overallSev = sev
			}
		}
	}

	var summary []*harbor.ComponentsOverviewEntry
	for k, v := range sevToCount {
		summary = append(summary, &harbor.ComponentsOverviewEntry{
			Sev:   int(k),
			Count: v,
		})
	}

	return overallSev, &harbor.ComponentsOverview{
		Total:   total,
		Summary: summary,
	}
}
