package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"github.com/BurntSushi/toml"
	"golang.org/x/net/http2"
	"io"
	"net/http"
	"os"
	"time"
)

type Config struct {
	LogLevel string `toml:"log_level"`
	Server   struct {
		ServiceAddress string `toml:"service_address"`
		CertPath       string `toml:"cert_path"`
		KeyPath        string `toml:"key_path"`
	} `toml:"server"`
	Redis struct {
		Addresses []string `toml:"addresses"`
		Passwords []string `toml:"passwords"`
	} `toml:"redis"`
	Rpc struct {
		Address   string `toml:"address"`
		KeyPath   string `toml:"key_path"`
		CertPath  string `toml:"cert_path"`
		Scheduler struct {
			Address  string `toml:"address"`
			Domain   string `toml:"domain"`
			CertPath string `toml:"cert_path"`
		} `toml:"scheduler"`
	} `toml:"rpc"`
	Sql struct {
		Address        string `toml:"address"`
		Database       string `toml:"database"`
		Username       string `toml:"username"`
		Password       string `toml:"password"`
		MaxConnections int    `toml:"max_connections"`
	} `toml:"sql"`
}

type SimpleServer struct {
}

func (s *SimpleServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {}

func (s *SimpleServer) Get(resp http.ResponseWriter, req *http.Request) error {
	return nil
}

func main() {
	configPath := os.Getenv("CONFIG_PATH")

	var config Config
	configPath = "/Users/joker/GolandProjects/prim-k8s/api/src/config.toml"
	_, err := toml.DecodeFile(configPath, &config)
	if err != nil {
		fmt.Println("decode toml failed:", err)
		return
	}

	cert, err := tls.LoadX509KeyPair(config.Server.CertPath, config.Server.KeyPath)
	if err != nil {
		fmt.Println("Error loading certificate:", err)
		return
	}

	certPool := x509.NewCertPool()
	certData, err := os.ReadFile(config.Server.CertPath)
	if err != nil {
		fmt.Println("Error reading certificate file:", err)
		return
	}
	// Parse the certificate data
	block, _ := pem.Decode(certData)
	if block == nil {
		fmt.Println("Failed to parse PEM block containing certificate")
		return
	}
	clientCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		fmt.Println("Error parsing X.509 certificate:", err)
		return
	}
	certPool.AddCert(clientCert)

	tlsConfig := tls.Config{
		Certificates:       []tls.Certificate{cert},
		InsecureSkipVerify: true,
		NextProtos:         []string{"PRIM"},
		ClientCAs:          certPool,
		ServerName:         config.Rpc.Scheduler.Domain,
	}

	// rpc client
	go func() {
		time.Sleep(10 * time.Second)
		rpcClient, err := tls.Dial("tcp", config.Rpc.Scheduler.Address, &tlsConfig)
		if err != nil {
			fmt.Println("Error dialing rpc:", err)
			return
		}
		go func() {
			rpcClient.Write([]byte(fmt.Sprintf("%s", config.Server.ServiceAddress)))
			buf := make([]byte, 1024)
			for {
				n, err := rpcClient.Read(buf)
				if err != nil {
					fmt.Println("Error reading from rpc:", err)
					return
				}
				fmt.Println("rpc says: ", string(buf[:n]))
			}
		}()
	}()

	// rpc server
	listener1, err := tls.Listen("tcp", config.Rpc.Address, &tlsConfig)
	if err != nil {
		fmt.Println("Error creating listener1:", err)
		return
	}
	defer listener1.Close()
	go func() {
		for {
			conn, err := listener1.Accept()
			if err != nil {
				fmt.Println("Error accepting connection:", err)
				continue
			}
			defer conn.Close()
			go echoHandler(conn)
		}
	}()
	http2.ConfigureServer(&http.Server{}, nil)
}

func echoHandler(rw io.ReadWriter) {
	buf := make([]byte, 1024)
	for {
		n, err := rw.Read(buf)
		if err != nil {
			fmt.Println("Error reading from stream:", err)
			return
		}
		fmt.Println("Received:", string(buf[:n]))
		_, err = rw.Write(buf[:n])
		if err != nil {
			fmt.Println("Error writing to stream:", err)
			return
		}
	}
}
