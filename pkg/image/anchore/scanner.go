package anchore

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"time"

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

type ScanImageStatus struct {
	Target_imageDigest     string `json:"imageDigest"`
	Target_analysis_status string `json:"analysis_status"`
}

type ScanImages []ScanImageStatus

type ScanResultGroup []anchore.ScanResult

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
		log.Printf("Overwriting registry URL %s with %s", req.RegistryURL, s.cfg.RegistryAddress)
		registryURL = s.cfg.RegistryAddress
	}

	imageToScan := fmt.Sprintf("%s/%s:%s", registryURL, req.Repository, req.Tag)

	log.Printf("Started scanning %s ...", imageToScan)

	var scannerAPI = s.cfg.ScannerAddress + "/images"
	log.Printf("anchore-engine add image URL: %s", scannerAPI)

	var imageToScanReq = `{"tag":"` + imageToScan + `"}`
	log.Printf("anchore-engine add image payload: %s", imageToScanReq)

	request := gorequest.New().SetBasicAuth(s.cfg.ScannerUsername, s.cfg.ScannerPassword)
	resp, body, errs := request.Post(scannerAPI).Send(imageToScanReq).End()
	log.Println(resp.Status)

	if errs != nil {
		log.Println(errs)
		log.Println(body)
	}

	var data ScanImages
	readErr := json.NewDecoder(resp.Body).Decode(&data)

	if readErr != nil {
		log.Printf("convert json struc error: " + readErr.Error())
	}
	//update return data later: need return ID which can help to pass to GetResult method
	log.Println("scan targt (imageDigest): ", data[0].Target_imageDigest)

	return &harbor.ScanResponse{
		DetailsKey: req.Digest,
	}, nil
}

// update method and paramenter passed in
func (s *imageScanner) GetResult(imageDigest string) (*harbor.ScanResult, error) {

	log.Println("scan targt (imageDigest): ", imageDigest)
	if imageDigest == "" {
		return nil, errors.New("imageDigest is empty")
	}

	var ScanResultdata ScanResultGroup
	var tempscandata ScanImages

	request := gorequest.New().SetBasicAuth(s.cfg.ScannerUsername, s.cfg.ScannerPassword)
	// cal API get the full report until "analysis_status": "analyzed"
	resp, body, errs := request.Get(s.cfg.ScannerAddress + "/images/" + imageDigest).End()
	log.Println(resp.Status)
	if errs != nil {
		log.Println(errs)
	}
	readErr := json.NewDecoder(resp.Body).Decode(&tempscandata)

	if readErr != nil {
		log.Printf("convert json struc error: " + readErr.Error())
	}

	for tempscandata[0].Target_analysis_status != "analyzed" {
		if tempscandata[0].Target_analysis_status == "analysis_failed" {
			//to do: define return result once it failed
			log.Println("analysis_status = analysis_failed")
			break

		} else {
			time.Sleep(10 * time.Second)
			resp, _, errs = request.Get(s.cfg.ScannerAddress + "/images/" + imageDigest).End()
			readErr := json.NewDecoder(resp.Body).Decode(&tempscandata)
			if readErr != nil {
				log.Printf("convert json struc error: " + readErr.Error())
			}
			if errs != nil {
				log.Println(errs)
			}
		}
	}

	resp, body, errs = request.Get(s.cfg.ScannerAddress + "/images/" + imageDigest + "/vuln/all").End()
	log.Println(resp.Status)
	if errs != nil {
		log.Println(errs)
		log.Println(body)
	}
	readErr = json.NewDecoder(resp.Body).Decode(&ScanResultdata)

	if readErr != nil {
		log.Printf("convert scanresult to json error: " + readErr.Error())
	}

	log.Println("scan targt (imageDigest): ", ScanResultdata[0].Vulnerabilities)

	return s.toHarborScanResult(ScanResultdata)

}

func (s *imageScanner) toHarborScanResult(srs []anchore.ScanResult) (*harbor.ScanResult, error) {
	var vulnerabilities []*harbor.VulnerabilityItem

	for _, sr := range srs {
		for _, v := range sr.Vulnerabilities {
			vulnerabilities = append(vulnerabilities, &harbor.VulnerabilityItem{
				ID:       v.VulnerabilityID,
				Severity: s.toHarborSeverity(v.Severity),
				Pkg:      v.PkgName,
				Version:  v.InstalledVersion,
				//Description: v.Package,
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
	case "High", "CRITICAL":
		return harbor.SevHigh
	case "Medium":
		return harbor.SevMedium
	case "Low":
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

func checkStatus(resp gorequest.Response, body string, errs []error) {
	if resp.StatusCode != 200 {
		log.Println("Http Error code : " + resp.Status)

	}
}
