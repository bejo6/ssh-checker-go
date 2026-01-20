package utils

import (
	"net"
	"time"
	"regexp"
	"strconv"
	"strings"
)

func PortIsOpen(host, port string) bool {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, port), time.Second*2)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

func GetIPsFromCIDR(cidr string) ([]string, error) {
	var ips []string
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}

	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); incIP(ip) {
		ips = append(ips, ip.String())
	}

	// Remove network and broadcast addresses
	if len(ips) > 2 {
		return ips[1 : len(ips)-1], nil
	}
	return ips, nil
}

func incIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func NormalizeHosts(hosts []string) ([]string, error) {
	var mapHosts = make(map[string]bool)
	var validHosts []string

	for _, host := range hosts {
		if strings.Contains(host, "/") {
			ips, err := GetIPsFromCIDR(host)
			if err != nil {
				continue
			}
			for _, ip := range ips {
				if !mapHosts[ip] {
					validHosts = append(validHosts, ip)
					mapHosts[ip] = true
				}
			}
			continue
		}

		host = strings.TrimSpace(strings.ToLower(host))
		if host == "" {
			continue
		}
		validHost := false
		if !mapHosts[host] {
			if net.ParseIP(host) != nil {
				validHost = true
			} else {
				if _, err := net.LookupHost(host); err == nil {
					validHost = true
				}
			}

			if validHost {
				validHosts = append(validHosts, host)
				mapHosts[host] = true
			}
		}
	}

	return validHosts, nil
}

func NormalizePorts(ports []string) ([]string, error) {
	var mapPorts = make(map[string]bool)
	var validPorts []string

	pattern := regexp.MustCompile(`^\d{1,5}$`)

	for _, port := range ports {
		portNum := pattern.ReplaceAllString(port, "")
		if portNum == "" {
			continue
		}

		if p, err := strconv.Atoi(portNum); err == nil && p > 0 && p <= 65535 {
			if !mapPorts[port] {
				validPorts = append(validPorts, port)
				mapPorts[port] = true
			}
		}
	}

	return validPorts, nil
}