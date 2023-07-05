package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"net"
	"net/http"
	"net/mail"
	"net/smtp"
	"time"

	"github.com/BurntSushi/toml"
)

type Config struct {
	Hosts    []HostConfig `toml:"host"`
	SMTP     SMTPConfig   `toml:"smtp"`
	Interval int          `toml:"interval"`
}

type HostConfig struct {
	Hostname string `toml:"hostname"`
	Port     string `toml:"port"`
}

type SMTPConfig struct {
	Server   string `toml:"server"`
	Port     int    `toml:"port"`
	Username string `toml:"username"`
	Password string `toml:"password"`
	To       string `toml:"to"`
	From     string `toml:"from"`
}

var configFile string
var intervalFlag time.Duration

func init() {
	flag.StringVar(&configFile, "c", "/etc/cert-mon/config.toml", "Path to the configuration file")
	intervalFlagTemp := flag.Duration("i", 0, "Check interval in minutes e.g 5m")
	flag.Parse()
	intervalFlag = *intervalFlagTemp
}

func main() {
	// Read configuration from the TOML file
	config, err := loadConfig(configFile)
	if err != nil {
		fmt.Println("Error loading configuration:", err)
		return
	}

	interval := time.Duration(config.Interval) * time.Minute
	fmt.Println("interval:", interval)
	if intervalFlag != 0 {
		interval = intervalFlag
	}
	fmt.Println("interval:", interval)
	fmt.Println("args:", flag.Args())

	// Iterate over the hosts and check certificate validity
	for _, host := range config.Hosts {
		// set default port
		if host.Port == "" {
			host.Port = "443"
		}
		go checkCertificate(host, interval, config.SMTP)
	}

	// Keep the program running
	select {}
}

func loadConfig(path string) (Config, error) {
	//var config Config
	config := Config{
		Interval: 60 * 24,
	}
	if _, err := toml.DecodeFile(path, &config); err != nil {
		return config, err
	}

	return config, nil
}

func checkCertificate(host HostConfig, checkInterval time.Duration, smtpConfig SMTPConfig) {
	// Define the duration between certificate checks
	// checkInterval := interval
	// checkInterval := time.Hour * 24

	// Custom TLS configuration
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true, // Skip certificate verification (only for testing)
		// MinVersion:         tls.VersionTLS12, // Specify the minimum TLS version
		// CipherSuites: []uint16{
		// 	tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, // Add supported cipher suites
		// 	tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		// },
	}

	// Custom HTTP client with modified User-Agent header
	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
			DialContext: (&net.Dialer{
				Timeout:   5 * time.Second, // Set dial timeout
				KeepAlive: 30 * time.Second,
			}).DialContext,
		},
	}

	// Infinite loop to periodically check the certificate
	for {
		// // Connect to the specified hostname and port
		// conn, err := net.Dial("tcp", net.JoinHostPort(host.Hostname, host.Port))
		// if err != nil {
		// 	fmt.Printf("Error connecting to %s:%s - %s\n", host.Hostname, host.Port, err)
		// 	time.Sleep(checkInterval)
		// 	continue
		// }

		// // Create a TLS connection with custom configuration
		// tlsConn := tls.Client(conn, tlsConfig)

		// // Handshake with the server to establish a TLS connection
		// err = tlsConn.Handshake()
		// if err != nil {
		// 	if err, ok := err.(net.Error); ok && err.Timeout() {
		// 		fmt.Printf("TLS handshake timeout for %s:%s - %s\n", host.Hostname, host.Port, err)
		// 	} else if err != nil {
		// 		fmt.Printf("TLS handshake error for %s:%s - %s\n", host.Hostname, host.Port, err)
		// 	}
		// 	time.Sleep(checkInterval)
		// 	continue
		// }
		// // Retrieve the certificate chain from the server
		// certs := tlsConn.ConnectionState().PeerCertificates

		// Make an HTTP request to the specified hostname and port

		url := fmt.Sprintf("https://%s:%s", host.Hostname, host.Port)
		req, err := http.NewRequest(http.MethodGet, url, nil)
		if err != nil {
			fmt.Printf("Error creating HTTP request for %s:%s - %s\n", host.Hostname, host.Port, err)
			time.Sleep(checkInterval)
			continue
		}

		// Set the custom User-Agent header
		req.Header.Set("User-Agent", "cert-mon/1.0")

		// Send the HTTP request and get the response
		resp, err := httpClient.Do(req)
		if err != nil {
			fmt.Printf("HTTP request error for %s:%s - %s\n", host.Hostname, host.Port, err)
			time.Sleep(checkInterval)
			continue
		}
		resp.Body.Close()

		// Check the TLS handshake status
		if resp.TLS == nil {
			fmt.Printf("TLS handshake error for %s:%s - TLS handshake did not occur\n", host.Hostname, host.Port)
			time.Sleep(checkInterval)
			continue
		}
		// Retrieve the certificate chain from the server
		certs := resp.TLS.PeerCertificates

		// Check the expiration date of the leaf certificate
		expirationDate := certs[0].NotAfter
		daysRemaining := int(time.Until(expirationDate).Hours() / 24)
		fmt.Printf("Days remaining until certificate expiration for %s:%s | %d days\n", host.Hostname, host.Port, daysRemaining)

		// Send an email if the certificate is expiring within 10 days
		if daysRemaining <= 10 {
			sendEmailNotification(host, daysRemaining, smtpConfig)
		} else {
			// fmt.Printf("Certificate for %s:%s is not expiring within 10 days.\n", host.Hostname, host.Port)
		}

		// conn.Close()
		time.Sleep(checkInterval)
	}
}

func sendEmailNotification(host HostConfig, daysRemaining int, smtpConfig SMTPConfig) {
	from := mail.Address{Name: "", Address: smtpConfig.From}
	to := mail.Address{Name: "", Address: smtpConfig.To}
	fmt.Printf("from.Address: %s\n", from.Address)

	// Create the email message
	subject := "Subject: Certificate Expiration Notification\r\n\r\n"
	// message := fmt.Sprintf("Subject: Certificate Expiration Notification\r\n\r\n")
	message := fmt.Sprintf("%s The certificate for %s:%s is expiring in %d days.", subject, host.Hostname, host.Port, daysRemaining)
	// Set up the SMTP client
	auth := smtp.PlainAuth("", smtpConfig.Username, smtpConfig.Password, smtpConfig.Server)
	tlsconfig := &tls.Config{
		ServerName: smtpConfig.Server,
	}
	// Connect to the SMTP server
	conn, err := tls.Dial("tcp", fmt.Sprintf("%s:%d", smtpConfig.Server, smtpConfig.Port), tlsconfig)
	if err != nil {
		fmt.Printf("TLS Error connecting to the SMTP server: %s\n", err)
		return
	}
	defer conn.Close()

	client, err := smtp.NewClient(conn, smtpConfig.Server)
	if err != nil {
		fmt.Printf("Error connecting to the SMTP server: %s\n", err)
		return
	}
	defer client.Close()

	// Authenticate with the SMTP server
	err = client.Auth(auth)
	if err != nil {
		fmt.Printf("SMTP authentication error: %s\n", err)
		return
	}

	// Set the sender and recipient
	err = client.Mail(from.Address)
	if err != nil {
		fmt.Printf("Error setting sender: %s\n", err)
		return
	}
	err = client.Rcpt(to.Address)
	if err != nil {
		fmt.Printf("Error setting recipient: %s\n", err)
		return
	}

	// Send the email message
	w, err := client.Data()
	if err != nil {
		fmt.Printf("Error starting email data: %s\n", err)
		return
	}
	_, err = w.Write([]byte(message))
	if err != nil {
		fmt.Printf("Error writing email data: %s\n", err)
		return
	}
	err = w.Close()
	if err != nil {
		fmt.Printf("Error closing email data: %s\n", err)
		return
	}

	fmt.Printf("Email notification sent for %s:%s\n", host.Hostname, host.Port)
}
