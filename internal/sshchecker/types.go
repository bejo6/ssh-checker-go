package sshchecker

import (
	"time"
)

type Host struct {
	Address string `json:"address"`
	Port    string `json:"port"`
}

type DataLogin struct {
	Host
	User     string `json:"user"`
	Password string `json:"password"`
}

type TimeStats struct {
	Start        time.Time
	LiveCheck    time.Duration
	LoginCheck   time.Duration
	Total        time.Duration
}

type SSHResult struct {
	LiveHosts []Host
	ValidLogins []DataLogin
	TimeStats TimeStats
}

var OutputName = "sshchecker_results"
var MaxLiveHosts = 500
var MaxLoginAttempts = 100
