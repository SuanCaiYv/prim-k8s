package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"github.com/BurntSushi/toml"
	"github.com/quic-go/quic-go"
	"github.com/redis/go-redis/v9"
	"io"
	"io/ioutil"
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
	Cluster struct {
		Addresses []string `toml:"addresses"`
		CertPath  string   `toml:"cert_path"`
	} `toml:"scheduler"`
	Rpc struct {
		Address  string `toml:"address"`
		KeyPath  string `toml:"key_path"`
		CertPath string `toml:"cert_path"`
		Api      struct {
			Address  string `toml:"address"`
			Domain   string `toml:"domain"`
			CertPath string `toml:"cert_path"`
		} `toml:"api"`
	} `toml:"rpc"`
}

func main() {
	configPath := os.Getenv("CONFIG_PATH")
	myId := os.Getenv("MY_ID")
	clusterIp := os.Getenv("CLUSTER_IP")
	serviceIp := os.Getenv("SERVICE_IP")
	clusterAddress := os.Getenv("CLUSTER_ADDRESS")
	serviceAddress := os.Getenv("SERVICE_ADDRESS")

	var config Config
	configPath = "/Users/joker/GolandProjects/prim-k8s/scheduler/src/config.toml"
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

	certPool := x509.NewCertPool()
	certData, err := ioutil.ReadFile(config.Server.CertPath)
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
	}

	quicConf := quic.Config{
		MaxIdleTimeout:        time.Millisecond * time.Duration(config.Transport.ConnectionIdleTimeout),
		MaxIncomingStreams:    config.Transport.MaxBiStreams,
		MaxIncomingUniStreams: config.Transport.MaxBiStreams,
		KeepAlivePeriod:       time.Millisecond * time.Duration(config.Transport.KeepAliveInterval),
		Allow0RTT:             true,
	}

	clusterParseList := strings.Split(config.Server.ClusterAddress, ":")
	clusterBindPort := clusterParseList[len(clusterParseList)-1]
	clusterBindAddress := ""
	if config.Server.PublicService {
		if config.Server.IpVersion == "v4" {
			clusterBindAddress = "0.0.0.0:" + clusterBindPort
		} else {
			clusterBindAddress = "[::]:" + clusterBindPort
		}
	} else {
		if config.Server.IpVersion == "v4" {
			clusterBindAddress = "127.0.0.1:" + clusterBindPort
		} else {
			clusterBindAddress = "[::1]:" + clusterBindPort
		}
	}

	serviceParseList := strings.Split(config.Server.ServiceAddress, ":")
	serviceBindPort := serviceParseList[len(serviceParseList)-1]
	serviceBindAddress := ""
	if config.Server.PublicService {
		if config.Server.IpVersion == "v4" {
			serviceBindAddress = "0.0.0.0:" + serviceBindPort
		} else {
			serviceBindAddress = "[::]:" + serviceBindPort
		}
	} else {
		if config.Server.IpVersion == "v4" {
			serviceBindAddress = "127.0.0.1:" + serviceBindPort
		} else {
			serviceBindAddress = "[::1]:" + serviceBindPort
		}
	}

	var password string
	if len(config.Redis.Passwords) != 0 {
		password = config.Redis.Passwords[0]
	}
	rdb := redis.NewClusterClient(&redis.ClusterOptions{
		Addrs:    config.Redis.Addresses,
		Password: password,
	})
	err = rdb.ForEachShard(context.Background(), func(ctx context.Context, shard *redis.Client) error {
		return shard.Ping(ctx).Err()
	})
	if err != nil {
		fmt.Println("Error connecting to redis:", err)
		return
	}
	fmt.Println("redis cluster ping ok.")

	// rpc client
	rpcClient, err := tls.Dial("tcp", config.Rpc.Api.Address, &tlsConfig)
	if err != nil {
		fmt.Println("Error dialing rpc:", err)
		return
	}
	go func() {
		rpcClient.Write([]byte(fmt.Sprintf("%s %s", config.Server.ClusterAddress, myId)))
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

	// rpc server
	network1 := "tcp6"
	if config.Server.IpVersion == "v4" {
		network1 = "tcp4"
	}
	listener1, err := tls.Listen(network1, config.Rpc.Address, &tlsConfig)
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

	// cluster server
	network2 := "udp6"
	if config.Server.IpVersion == "v4" {
		network2 = "udp4"
	}
	list2 := strings.Split(clusterBindAddress, ":")
	port2, err := strconv.Atoi(list2[len(list2)-1])
	udpConn2, err := net.ListenUDP(network2, &net.UDPAddr{IP: net.ParseIP(clusterBindAddress[0 : len(clusterBindAddress)-len(list2[len(list2)-1])-1]), Port: port2})
	if err != nil {
		fmt.Println("Error creating listener2:", err)
		return
	}
	// ... error handling
	tr2 := quic.Transport{
		Conn: udpConn2,
	}
	listener2, err := tr2.Listen(&tlsConfig, &quicConf)
	go func() {
		for {
			conn, err := listener2.Accept(context.Background())
			if err != nil {
				fmt.Println("Error accepting connection:", err)
				continue
			}
			go func() {
				for {
					rw, err := conn.AcceptStream(context.Background())
					if err != nil {
						fmt.Println("Error accepting stream:", err)
						continue
					}
					go echoHandler(rw)
				}
			}()
		}
	}()

	// tls server
	network3 := "tcp6"
	if config.Server.IpVersion == "v4" {
		network3 = "tcp4"
	}
	listener3, err := tls.Listen(network3, config.Server.ServiceAddress, &tlsConfig)
	if err != nil {
		fmt.Println("Error creating listener3:", err)
		return
	}
	defer listener3.Close()
	go func() {
		for {
			conn, err := listener3.Accept()
			if err != nil {
				fmt.Println("Error accepting connection:", err)
				continue
			}
			defer conn.Close()
			go echoHandler(conn)
		}
	}()

	// cluster connection
	go func() {
		for i := range config.Cluster.Addresses {
			address := config.Cluster.Addresses[i]
			if address == config.Server.ClusterAddress {
				continue
			}
			schedulerConn, err := quic.DialAddr(context.Background(), address, &tlsConfig, &quicConf)
			for {
				if err != nil {
					fmt.Println("Error dialing scheduler:", err)
					time.Sleep(time.Millisecond * 2000)
				} else {
					break
				}
				schedulerConn, err = quic.DialAddr(context.Background(), address, &tlsConfig, &quicConf)
			}
			go func() {
				conn, err := schedulerConn.OpenStream()
				if err != nil {
					fmt.Println("Error opening stream:", err)
					return
				}
				conn.Write([]byte(fmt.Sprintf("%s %s", config.Server.ClusterAddress, myId)))
				buf := make([]byte, 1024)
				for {
					n, err := conn.Read(buf)
					if err != nil {
						fmt.Println("Error reading from stream:", err)
						return
					}
					fmt.Println("scheduler says: ", string(buf[:n]))
				}
			}()
		}
	}()

	// quic server
	network5 := "udp6"
	if config.Server.IpVersion == "v4" {
		network5 = "udp4"
	}
	list5 := strings.Split(serviceBindAddress, ":")
	port5, err := strconv.Atoi(list5[len(list5)-1])
	udpConn5, err := net.ListenUDP(network5, &net.UDPAddr{IP: net.ParseIP(serviceBindAddress[0 : len(serviceBindAddress)-len(list5[len(list5)-1])-1]), Port: port5})
	// ... error handling
	tr5 := quic.Transport{
		Conn: udpConn5,
	}
	listener5, err := tr5.Listen(&tlsConfig, &quicConf)
	if err != nil {
		fmt.Println("Error creating listener4:", err)
		return
	}
	for {
		conn, err := listener5.Accept(context.Background())
		if err != nil {
			fmt.Println("Error accepting connection:", err)
			continue
		}
		go func() {
			for {
				rw, err := conn.AcceptStream(context.Background())
				if err != nil {
					fmt.Println("Error accepting stream:", err)
					continue
				}
				go echoHandler(rw)
			}
		}()
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
