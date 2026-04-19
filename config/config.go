package config

import (
	"os"
	"path/filepath"

	"github.com/joho/godotenv"
)

type Config struct {
	VirusTotalKey string
	GoogleTIKey   string
	AbuseIPDBKey  string
	GreyNoiseKey  string
	OTXKey        string
	ShodanKey     string
	IPInfoKey     string
	GeminiKey     string
}

// Load reads .env from the same directory as the running binary.
// A missing .env file is not an error — env vars already set in the environment are used.
func Load() (*Config, error) {
	exe, err := os.Executable()
	if err != nil {
		return LoadFrom("")
	}
	return LoadFrom(filepath.Join(filepath.Dir(exe), ".env"))
}

// LoadFrom loads from a specific .env path (used in tests).
// A missing file is not an error.
func LoadFrom(envPath string) (*Config, error) {
	// godotenv.Load silently ignores missing files only if we check ourselves
	if envPath != "" {
		if _, err := os.Stat(envPath); err == nil {
			_ = godotenv.Load(envPath)
		}
	}

	return &Config{
		VirusTotalKey: os.Getenv("VIRUSTOTAL_KEY"),
		GoogleTIKey:   os.Getenv("GOOGLE_TI_KEY"),
		AbuseIPDBKey:  os.Getenv("ABUSEIPDB_KEY"),
		GreyNoiseKey:  os.Getenv("GREYNOISE_KEY"),
		OTXKey:        os.Getenv("OTX_KEY"),
		ShodanKey:     os.Getenv("SHODAN_KEY"),
		IPInfoKey:     os.Getenv("IPINFO_KEY"),
		GeminiKey:     os.Getenv("GEMINI_KEY"),
	}, nil
}
