package main

import (
	"os"
	"fmt"
	"flag"
	"strings"
	"ssh-checker/internal/config"
	"ssh-checker/internal/utils"
)

func ParseFlags() {

	format := map[string]bool{
		"text": true,
		"json": true,
		"all":  true,
	}

	help := flag.Bool("help", false, "Display help information")
	flag.BoolVar(&config.LogDebug, "debug", config.LogDebug, "Enable debug logging")
	host := flag.String("host", "", "Host/IP address of the SSH server. Use comma to separate multiple addresses.")
	port := flag.String("port", "22", "Port number of the SSH server. Use comma to separate multiple ports.")
	username := flag.String("user", "", "Username for SSH login. Use comma to separate multiple usernames.")
	password := flag.String("pass", "", "Password for SSH login. Use comma to separate multiple passwords.")

	hostFile := flag.String("host-file", "", "Path to a file containing a list of host/IP addresses (one per line).")
	portFile := flag.String("port-file", "", "Path to a file containing a list of ports (one per line).")
	usernameFile := flag.String("user-file", "", "Path to a file containing a list of usernames (one per line).")
	passwordFile := flag.String("pass-file", "", "Path to a file containing a list of passwords (one per line).")

	chunkSize := flag.Int("chunk-size", 10, "Number of concurrent SSH login attempts.")
	flag.IntVar(&config.AppConfig.SSHDelayMs, "delay", 0, "Delay in milliseconds between each SSH login attempt.")
	flag.IntVar(&config.AppConfig.WorkersCount, "workers", 0, "Number of workers for concurrent SSH login attempts.")
	flag.IntVar(&config.AppConfig.WorkersLiveCheck, "workers-live", 0, "Number of workers for live host checking.")
	flag.IntVar(&config.AppConfig.WorkersLoginCheck, "workers-login", 0, "Number of workers for SSH login checking.")
	flag.StringVar(&config.FormattedOutput, "format", "text", "Output format: text or json or all (both).")

	flag.Parse()

	if *help {
		ShowUsage()
	}

	if *host != "" {
		hosts := strings.Split(*host, ",")
		normalizedHosts, err := utils.NormalizeHosts(hosts)
		if err != nil {
			fmt.Println("Error normalizing hosts:", err)
			os.Exit(1)
		}
		config.AppConfig.Hosts = normalizedHosts
	} else if *hostFile != "" {
		hosts, err := getHostsFromFile(*hostFile)
		if err != nil {
			fmt.Println("Error reading hosts from file:", err)
			os.Exit(1)
		}
		config.AppConfig.Hosts = hosts
	}

	if *port != "" {
		ports := strings.Split(*port, ",")
		normalizedPorts, err := utils.NormalizePorts(ports)
		if err != nil {
			fmt.Println("Error normalizing ports:", err)
			os.Exit(1)
		}
		config.AppConfig.Port = normalizedPorts
	} else if *portFile != "" {
		ports, err := getPortsFromFile(*portFile)
		if err != nil {
			fmt.Println("Error reading ports from file:", err)
		} else {
			config.AppConfig.Port = ports
		}
	}

	if len(config.AppConfig.Port) == 0 {
		config.AppConfig.Port = []string{"22"}
	}

	if *username != "" {
		usernames := strings.Split(*username, ",")
		config.AppConfig.User = usernames
	} else if *usernameFile != "" {
		users, err := utils.GetItemsFromFile(*usernameFile)
		if err != nil {
			fmt.Println("Error reading usernames from file:", err)
			os.Exit(1)
		}
		config.AppConfig.User = users
	}

	if *password != "" {
		passwords := strings.Split(*password, ",")
		config.AppConfig.Password = passwords
	} else if *passwordFile != "" {
		passwords, err := utils.GetItemsFromFile(*passwordFile)
		if err != nil {
			fmt.Println("Error reading passwords from file:", err)
			os.Exit(1)
		}
		config.AppConfig.Password = passwords
	}

	if !format[config.FormattedOutput] {
		fmt.Println("Invalid format specified. Use 'text', 'json', or 'all'.")
		os.Exit(1)
	}

	config.AppConfig.ChunkSize = *chunkSize
}

func ShowUsage() {
	flag.Usage()
	os.Exit(0)
}

func getHostsFromFile(filePath string) ([]string, error) {
	hosts, err := utils.GetItemsFromFile(filePath)
	if err != nil {
		return nil, err
	}

	return utils.NormalizeHosts(hosts)
}

func getPortsFromFile(filePath string) ([]string, error) {
	ports, err := utils.GetItemsFromFile(filePath)
	if err != nil {
		return nil, err
	}

	return utils.NormalizePorts(ports)
}
