package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"github.com/BurntSushi/toml"
	"github.com/go-pg/pg/v10"
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

func (s *SimpleServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		err := s.Get(w, r)
		if err != nil {
			fmt.Println("Error handling get:", err)
		}
	case http.MethodPost:
		err := s.Post(w, r)
		if err != nil {
			fmt.Println("Error handling post:", err)
		}
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (s *SimpleServer) Get(resp http.ResponseWriter, req *http.Request) error {
	path := req.URL.Path
	query := req.URL.Query()
	resp.Header().Set("Content-Type", "text/plain")
	_, err := resp.Write([]byte(fmt.Sprintf("hello for get, path: %s, query: %s", path, query.Encode())))
	return err
}

func (s *SimpleServer) Post(resp http.ResponseWriter, req *http.Request) error {
	path := req.URL.Path
	query := req.URL.Query()
	body := make([]byte, 2048)
	n, err := req.Body.Read(body)
	if err != nil && err != io.EOF {
		return err
	}
	resp.Header().Set("Content-Type", "text/plain")
	_, err = resp.Write([]byte(fmt.Sprintf("hello for post, path: %s, query: %s, body: %s", path, query.Encode(), string(body[:n]))))
	return err
}

func main() {
	configPath := os.Getenv("CONFIG_PATH")

	var config Config
	configPath = os.Getenv("HOME") + "/GolandProjects/prim-k8s/api/src/config.toml"
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

	db := pg.Connect(&pg.Options{
		Addr:     config.Sql.Address,
		User:     config.Sql.Username,
		Password: config.Sql.Password,
		Database: config.Sql.Database,
		PoolSize: config.Sql.MaxConnections,
	})

	err = db.Ping(context.Background())
	if err != nil {
		fmt.Println("Error connecting to database:", err)
		return
	}
	fmt.Println("Connected to database")

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

	// http server
	httpServer := &http.Server{
		Addr:    config.Server.ServiceAddress,
		Handler: &SimpleServer{},
	}
	http2.ConfigureServer(httpServer, nil)
	err = httpServer.ListenAndServeTLS(config.Server.CertPath, config.Server.KeyPath)
	if err != nil {
		fmt.Println("Error creating https server:", err)
		return
	}
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
