package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"time"

	"github.com/pelletier/go-toml/v2"

	"github.com/For-ACGN/MIX-Socks"
)

var (
	cfgPath  string
	password string
	setCap   bool
)

func init() {
	flag.StringVar(&cfgPath, "cfg", "config.toml", "set configuration file path")
	flag.StringVar(&password, "ph", "", "calculate password hash for config")
	flag.BoolVar(&setCap, "sc", false, "setcap cap_net_bind_service, acme mode need this")
	flag.Parse()
}

func main() {
	if setCap {
		path, err := os.Executable()
		checkError(err)
		cmd := exec.Command("sudo", "setcap 'cap_net_bind_service=+ep' "+path)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		err = cmd.Run()
		checkError(err)
		return
	}
	if password != "" {
		h := sha256.Sum256([]byte(password))
		fmt.Println(hex.EncodeToString(h[:]))
		return
	}

	// read ServerConfig from config file
	cfgData, err := os.ReadFile(cfgPath) // #nosec
	checkError(err)
	decoder := toml.NewDecoder(bytes.NewReader(cfgData))
	decoder.DisallowUnknownFields()

	var config msocks.ServerConfig
	err = decoder.Decode(&config)
	checkError(err)

	signalCh := make(chan os.Signal, 1)
	signal.Notify(signalCh, os.Interrupt)

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	go func() {
		<-signalCh
		cancel()
	}()

	server, err := msocks.NewServer(ctx, &config)
	checkError(err)
	go func() {
		err := server.Serve()
		checkError(err)
	}()

	<-signalCh

	err = server.Close()
	checkError(err)
}

func checkError(err error) {
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
