package msocks

import (
	"time"
)

// ServerConfig contains configurations for proxy server.
type ServerConfig struct {
	Common struct {
		PassHash string `toml:"pwd_hash"`
		LogPath  string `toml:"log_path"`
	} `toml:"common"`

	Server struct {
		Network  string   `toml:"network"`
		Address  string   `toml:"address"`
		MaxConns int      `toml:"max_conns"`
		Timeout  duration `toml:"timeout"`
	} `toml:"server"`

	TLS struct {
		ServerCert string `toml:"server_cert"`
		ServerKey  string `toml:"server_key"`
	} `toml:"tls"`
}

// ClientConfig contains configurations for proxy client.
type ClientConfig struct {
	Common struct {
		Password string `toml:"password"`
		LogPath  string `toml:"log_path"`
	} `toml:"common"`

	Client struct {
		PreConns int      `toml:"pre_conns"`
		Timeout  duration `toml:"timeout"`
	} `toml:"client"`

	Server struct {
		Network string `toml:"network"`
		Address string `toml:"address"`
		RootCA  string `toml:"root_ca"`
	} `toml:"server"`

	Front struct {
		Mode     string `toml:"mode"`
		Network  string `toml:"network"`
		Address  string `toml:"address"`
		Username string `toml:"username"`
		Password string `toml:"password"`
	} `toml:"front"`
}

// duration is patch for toml v2.
type duration time.Duration

// MarshalText implement encoding.TextMarshaler.
func (d duration) MarshalText() ([]byte, error) {
	return []byte(time.Duration(d).String()), nil
}

// UnmarshalText implement encoding.TextUnmarshaler.
func (d *duration) UnmarshalText(b []byte) error {
	x, err := time.ParseDuration(string(b))
	if err != nil {
		return err
	}
	*d = duration(x)
	return nil
}
