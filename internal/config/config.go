package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Server    ServerConfig    `yaml:"server"`
	Scanner   ScannerConfig   `yaml:"scanner"`
	Telemetry TelemetryConfig `yaml:"telemetry"`
	Mesh      MeshConfig      `yaml:"mesh"`
	AI        AIConfig        `yaml:"ai"`
	Database  DatabaseConfig  `yaml:"database"`
	Log       LogConfig       `yaml:"log"`
}

type AIConfig struct {
	Enabled bool   `yaml:"enabled"`
	APIKey  string `yaml:"api_key"`
	Model   string `yaml:"model"`
}

type MeshConfig struct {
	Enabled     bool     `yaml:"enabled"`
	NodeType    string   `yaml:"node_type"`
	BindAddr    string   `yaml:"bind"`
	ReplicaAddr string   `yaml:"replica_addr"`
	Join        []string `yaml:"join"`
	Secret      string   `yaml:"secret"`
	DataDir     string   `yaml:"data_dir"`
}

type TelemetryConfig struct {
	SNMP   SNMPConfig   `yaml:"snmp"`
	Syslog SyslogConfig `yaml:"syslog"`
	Poller PollerConfig `yaml:"poller"`
}

type SNMPConfig struct {
	Enabled   bool   `yaml:"enabled"`
	Listen    string `yaml:"listen"`
	Community string `yaml:"community"`
}

type SyslogConfig struct {
	Enabled bool   `yaml:"enabled"`
	Listen  string `yaml:"listen"`
}

type PollerConfig struct {
	Enabled  bool   `yaml:"enabled"`
	Interval string `yaml:"interval"`

	IntervalDuration time.Duration `yaml:"-"`
}

type ServerConfig struct {
	Host     string `yaml:"host"`
	Port     int    `yaml:"port"`
	Password string `yaml:"password"`
	TLS      TLSConfig `yaml:"tls"`
}

type TLSConfig struct {
	Enabled  bool   `yaml:"enabled"`
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`
}

type ScannerConfig struct {
	Subnets            []string `yaml:"subnets"`
	Interval           string   `yaml:"interval"`
	Timeout            string   `yaml:"timeout"`
	MaxConcurrentHosts int      `yaml:"max_concurrent_hosts"`
	MaxConcurrentPorts int      `yaml:"max_concurrent_ports"`
	Ports              []int    `yaml:"ports"`

	IntervalDuration time.Duration `yaml:"-"`
	TimeoutDuration  time.Duration `yaml:"-"`
}

type DatabaseConfig struct {
	Path string `yaml:"path"`
}

type LogConfig struct {
	Level string `yaml:"level"`
}

func Load(path string) (*Config, error) {
	cfg := Default()

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, nil
		}
		return nil, fmt.Errorf("read config: %w", err)
	}

	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	if err := cfg.parseDurations(); err != nil {
		return nil, err
	}

	return cfg, nil
}

func (c *Config) parseDurations() error {
	if c.Scanner.Interval != "" {
		d, err := time.ParseDuration(c.Scanner.Interval)
		if err != nil {
			return fmt.Errorf("parse scanner.interval: %w", err)
		}
		c.Scanner.IntervalDuration = d
	}
	if c.Scanner.Timeout != "" {
		d, err := time.ParseDuration(c.Scanner.Timeout)
		if err != nil {
			return fmt.Errorf("parse scanner.timeout: %w", err)
		}
		c.Scanner.TimeoutDuration = d
	}
	if c.Telemetry.Poller.Interval != "" {
		d, err := time.ParseDuration(c.Telemetry.Poller.Interval)
		if err != nil {
			return fmt.Errorf("parse telemetry.poller.interval: %w", err)
		}
		c.Telemetry.Poller.IntervalDuration = d
	}
	return nil
}

func Default() *Config {
	return &Config{
		Server: ServerConfig{
			Host: "0.0.0.0",
			Port: 8080,
		},
		Scanner: ScannerConfig{
			Subnets:            []string{},
			Interval:           "5m",
			Timeout:            "2s",
			MaxConcurrentHosts: 100,
			MaxConcurrentPorts: 20,
			Ports:              DefaultPorts(),
			IntervalDuration:   5 * time.Minute,
			TimeoutDuration:    2 * time.Second,
		},
		Telemetry: TelemetryConfig{
			SNMP: SNMPConfig{
				Enabled:   true,
				Listen:    "0.0.0.0:1162",
				Community: "public",
			},
			Syslog: SyslogConfig{
				Enabled: true,
				Listen:  "0.0.0.0:1514",
			},
			Poller: PollerConfig{
				Enabled:          true,
				Interval:         "60s",
				IntervalDuration: 60 * time.Second,
			},
		},
		Mesh: MeshConfig{
			Enabled:     false,
			NodeType:    "full",
			BindAddr:    "0.0.0.0:7946",
			ReplicaAddr: "0.0.0.0:7947",
			Secret:      "",
			DataDir:     "./mythnet-data",
		},
		AI: AIConfig{
			Enabled: true,
			Model:   "claude-sonnet-4-20250514",
		},
		Database: DatabaseConfig{
			Path: "mythnet.db",
		},
		Log: LogConfig{
			Level: "info",
		},
	}
}

func DefaultPorts() []int {
	return []int{
		21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143,
		443, 445, 993, 995, 1433, 1521, 3306, 3389,
		5432, 5900, 6379, 8080, 8443, 9090, 27017,
	}
}
