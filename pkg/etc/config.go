package etc

import (
	"os"
)

type Config struct {
	Addr            string
	RegistryAddress string
	ScannerAddress  string
	ScannerUsername string
	ScannerPassword string
}

func GetConfig() (*Config, error) {
	cfg := &Config{
		Addr: ":8080",
	}
	if registryAddr, ok := os.LookupEnv("REGISTRY_ADDR"); ok {
		cfg.RegistryAddress = registryAddr
	}
	if scannerAddr, ok := os.LookupEnv("SCANNER_ADDR"); ok {
		cfg.ScannerAddress = scannerAddr
	}
	if username, ok := os.LookupEnv("SCANNER_USERNAME"); ok {
		cfg.ScannerUsername = username
	}
	if pwd, ok := os.LookupEnv("SCANNER_PASSWORD"); ok {
		cfg.ScannerPassword = pwd
	}
	return cfg, nil
}
