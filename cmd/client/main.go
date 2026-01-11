package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"os/signal"

	"github.com/pelletier/go-toml/v2"

	"github.com/For-ACGN/MIX-Socks"
)

var (
	cfgPath  string
	password string
)

func init() {
	flag.StringVar(&cfgPath, "cfg", "config.toml", "set configuration file path")
	flag.StringVar(&password, "ph", "", "calculate password hash for config")
	flag.Parse()
}

func main() {
	if password != "" {
		h := sha256.Sum256([]byte(password))
		fmt.Println(hex.EncodeToString(h[:]))
		return
	}

	// read ClientConfig from config file
	cfgData, err := os.ReadFile(cfgPath) // #nosec
	checkError(err)
	decoder := toml.NewDecoder(bytes.NewReader(cfgData))
	decoder.DisallowUnknownFields()

	var config msocks.ClientConfig
	err = decoder.Decode(&config)
	checkError(err)

	client, err := msocks.NewClient(&config)
	checkError(err)

	err = client.Login()
	checkError(err)
	go func() {
		err := client.Serve()
		checkError(err)
	}()

	signalCh := make(chan os.Signal, 1)
	signal.Notify(signalCh, os.Interrupt)
	<-signalCh

	err = client.Logout()
	checkError(err)
	err = client.Close()
	checkError(err)
}

func checkError(err error) {
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
