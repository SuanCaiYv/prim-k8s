package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"github.com/BurntSushi/toml"
	"github.com/quic-go/quic-go"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	LogLevel string `toml:"log_level"`
	Server   struct {
		IpVersion      string `toml:"ip_version"`
		PublicService  bool   `toml:"public_service"`
		ClusterAddress string `toml:"cluster_address"`
		ServiceAddress string `toml:"service_address"`
		Domain         string `toml:"domain"`
		CertPath       string `toml:"cert_path"`
		KeyPath        string `toml:"key_path"`
		MaxConnections int    `toml:"max_connections"`
	} `toml:"server"`
	Transport struct {
		KeepAliveInterval     int64 `toml:"keep_alive_interval"`
		ConnectionIdleTimeout int64 `toml:"connection_idle_timeout"`
		MaxBiStreams          int64 `toml:"max_bi_streams"`
	} `toml:"transport"`
	Redis struct {
		Addresses []string `toml:"addresses"`
		Passwords []string `toml:"passwords"`
	} `toml:"redis"`
	Scheduler struct {
		Address  string `toml:"address"`
		Domain   string `toml:"domain"`
		CertPath string `toml:"cert_path"`
	} `toml:"scheduler"`
	Rpc struct {
		Scheduler struct {
			Address  string `toml:"address"`
			Domain   string `toml:"domain"`
			CertPath string `toml:"cert_path"`
		} `toml:"scheduler"`
		Api struct {
			Address  string `toml:"address"`
			Domain   string `toml:"domain"`
			CertPath string `toml:"cert_path"`
		} `toml:"api"`
	} `toml:"rpc"`
	Seqnum struct {
		CertPath string `toml:"cert_path"`
	} `toml:"seqnum"`
	MessageQueue struct {
		Address string `toml:"address"`
	} `toml:"message_queue"`
}

func (c *Config) String() string {
	return fmt.Sprintf(
		"LogLevel: %s\nServer: %v\nTransport: %v\nRedis: %v\nScheduler: %v\nRpc: %v\nSeqnum: %v\nMessageQueue: %v\n",
		c.LogLevel,
		c.Server,
		c.Transport,
		c.Redis,
		c.Scheduler,
		c.Rpc,
		c.Seqnum,
		c.MessageQueue,
	)
}

func main() {
	configPath := os.Getenv("CONFIG_PATH")
	myId := os.Getenv("MY_ID")
	clusterIp := os.Getenv("CLUSTER_IP")
	serviceIp := os.Getenv("SERVICE_IP")
	clusterAddress := os.Getenv("CLUSTER_ADDRESS")
	serviceAddress := os.Getenv("SERVICE_ADDRESS")

	var config Config
	configPath = "/Users/slma/RustProjects/prim/server/message/config.toml"
	_, err := toml.DecodeFile(configPath, &config)
	if err != nil {
		fmt.Println("decode toml failed:", err)
		return
	}
	if clusterIp != "" {
		list := strings.Split(config.Server.ClusterAddress, ":")
		config.Server.ClusterAddress = clusterIp + ":" + list[len(list)-1]
	}
	if serviceIp != "" {
		list := strings.Split(config.Server.ServiceAddress, ":")
		config.Server.ServiceAddress = serviceIp + ":" + list[len(list)-1]
	}
	if clusterAddress != "" {
		config.Server.ClusterAddress = clusterAddress
	}
	if serviceAddress != "" {
		config.Server.ServiceAddress = serviceAddress
	}

	cert, err := tls.LoadX509KeyPair(config.Server.CertPath, config.Server.KeyPath)
	if err != nil {
		fmt.Println("Error loading certificate:", err)
		return
	}

	tlsConfig := tls.Config{
		Certificates: []tls.Certificate{cert},
	}

	clusterParseList := strings.Split(config.Server.ClusterAddress, ":")
	clusterBindPort := clusterParseList[len(clusterParseList)-1]
	clusterBindAddress := ""
	if config.Server.PublicService {
		if config.Server.IpVersion == "v4" {
			config.Server.ClusterAddress = "0.0.0.0:" + clusterBindPort
		} else {
			config.Server.ClusterAddress = "[::]:" + clusterBindPort
		}
	} else {
		if config.Server.IpVersion == "v4" {
			config.Server.ClusterAddress = "127.0.0.1:" + clusterBindPort
		} else {
			config.Server.ClusterAddress = "[::1]:" + clusterBindPort
		}
	}

	serviceParseList := strings.Split(config.Server.ServiceAddress, ":")
	serviceBindPort := serviceParseList[len(serviceParseList)-1]
	serviceBindAddress := ""
	if config.Server.PublicService {
		if config.Server.IpVersion == "v4" {
			config.Server.ServiceAddress = "0.0.0.0:" + serviceBindPort
		} else {
			config.Server.ServiceAddress = "[::]:" + serviceBindPort
		}
	} else {
		if config.Server.IpVersion == "v4" {
			config.Server.ServiceAddress = "127.0.0.1:" + serviceBindPort
		} else {
			config.Server.ServiceAddress = "[::1]:" + serviceBindPort
		}
	}

	network := "tcp6"
	if config.Server.IpVersion == "v4" {
		network = "tcp4"
	}
	listener, err := tls.Listen(network, config.Server.ServiceAddress, &tlsConfig)
	if err != nil {
		fmt.Println("Error creating listener:", err)
		return
	}
	defer listener.Close()

	fmt.Println("TLS server is listening on :443")

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				fmt.Println("Error accepting connection:", err)
				continue
			}
			defer conn.Close()
			go echoHandler(conn)
		}
	}()

	network = "udp6"
	if config.Server.IpVersion == "v4" {
		network = "udp4"
	}
	list := strings.Split(serviceBindAddress, ":")
	port, err := strconv.Atoi(list[len(list)-1])
	udpConn, err := net.ListenUDP(network, &net.UDPAddr{IP: net.ParseIP(serviceBindAddress[0 : len(serviceBindAddress)-len(list[len(list)-1])-1]), Port: port})
	// ... error handling
	tr := quic.Transport{
		Conn: udpConn,
	}
	quicConf := quic.Config{
		MaxIdleTimeout:        time.Millisecond * time.Duration(config.Transport.ConnectionIdleTimeout),
		MaxIncomingStreams:    config.Transport.MaxBiStreams,
		MaxIncomingUniStreams: config.Transport.MaxBiStreams,
		KeepAlivePeriod:       time.Millisecond * time.Duration(config.Transport.KeepAliveInterval),
		Allow0RTT:             true,
	}
	ln, err := tr.Listen(&tlsConfig, &quicConf)
	// ... error handling
	go func() {
		for {
			conn, err := ln.Accept(context.Background())
			if err != nil {
				fmt.Println("Error accepting connection:", err)
				continue
			}
			rw, err := conn.AcceptStream(context.Background())
			if err != nil {
				fmt.Println("Error accepting stream:", err)
				continue
			}
			go echoHandler(rw)
		}
	}()
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
