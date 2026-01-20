package sshchecker

import (
	"os"
	"fmt"
	"sync"
	"time"
	"strings"
	"crypto/md5"
	"encoding/json"
	"ssh-checker/internal/config"
	"ssh-checker/internal/utils"
	"golang.org/x/crypto/ssh"
)

func NewSSHChecker() *SSHResult {
	return &SSHResult{
		LiveHosts:   []Host{},
		ValidLogins: make(map[string]DataLogin),
	}
}

func (s *SSHResult) Run() {
	s.TimeStats.Start = time.Now()

	// --- Live host phase ---
	liveStart := time.Now()
	s.runCheckLive()
	s.TimeStats.LiveCheck = time.Since(liveStart)

	if len(s.LiveHosts) == 0 {
		fmt.Println("[!] No live hosts found. Exiting.")
		os.Exit(0)
	}

	// --- SSH login phase ---
	loginStart := time.Now()
	s.runCheckLogin()
	s.TimeStats.LoginCheck = time.Since(loginStart)

	s.TimeStats.Total = time.Since(s.TimeStats.Start)
	s.printTimeStats()

	if len(s.ValidLogins) == 0 {
		fmt.Println("[!] No valid logins found.")
		os.Exit(0)
	}

	s.SaveToFile()
}

func (s *SSHResult) runCheckLive() {
	usePool := false
	if config.AppConfig.WorkersCount > 0 || config.AppConfig.WorkersLiveCheck > 0 {
		usePool = true
	}
	if config.AppConfig.WorkersCount > 0 && config.AppConfig.WorkersLiveCheck <= 0 {
		config.AppConfig.WorkersLiveCheck = config.AppConfig.WorkersCount
	}
	if len(s.LiveHosts) >= MaxLiveHosts {
		usePool = true
	}

	if usePool {
		fmt.Println("[*] Live host checking mode: with worker pool")
		s.CheckLiveHostsWithWorkerPool()
	} else {
		fmt.Println("[*] Live host checking mode: standard")
		s.CheckLiveHosts()
	}
}

func (s *SSHResult) runCheckLogin() {
	usePool := false
	if config.AppConfig.WorkersCount > 0 || config.AppConfig.WorkersLoginCheck > 0 {
		usePool = true
	}
	if config.AppConfig.WorkersCount > 0 && config.AppConfig.WorkersLoginCheck <= 0 {
		config.AppConfig.WorkersLoginCheck = config.AppConfig.WorkersCount
	}

	totalLogins := len(s.LiveHosts) *
		len(config.AppConfig.User) *
		len(config.AppConfig.Password)

	if totalLogins >= MaxLoginAttempts {
		usePool = true
	}

	if config.AppConfig.SSHDelayMs > 0 {
		if usePool {
			fmt.Printf("[*] SSH login mode: delayed with worker pool (%d ms)\n", config.AppConfig.SSHDelayMs)
			s.CheckValidLoginsWithWorkerPoolAndDelay()
		} else {
			fmt.Printf("[*] SSH login mode: delayed (%d ms)\n", config.AppConfig.SSHDelayMs)
			s.CheckValidLoginsWithDelay()
		}
	} else {
		if usePool {
			fmt.Println("[*] SSH login mode: fast with worker pool")
			s.CheckValidLoginsWithWorkerPool()
		} else {
			fmt.Println("[*] SSH login mode: fast (no delay)")
			s.CheckValidLogins()
		}
	}
}

func (s *SSHResult) CheckLiveHosts() {
	mapHosts := mappingHosts()

	fmt.Println("[*] Checking live hosts...")

	chunkSize := config.AppConfig.ChunkSize
	if chunkSize <= 0 {
		chunkSize = 10
	}

	sem := make(chan struct{}, chunkSize)
	var wg sync.WaitGroup
	var mu sync.Mutex

	for address, data := range mapHosts {
		wg.Add(1)

		go func(address string, data Host) {
			defer wg.Done()

			// acquire slot
			sem <- struct{}{}
			defer func() { <-sem }()

			if utils.PortIsOpen(data.Address, data.Port) {
				fmt.Println("[+] Host is live:", address)

				// protect shared slice
				mu.Lock()
				s.AddLiveHost(data)
				mu.Unlock()
			} else {
				if config.LogDebug {
					fmt.Println("[-] Host is not reachable:", address)
				}
			}
		}(address, data)
	}

	wg.Wait()

	fmt.Println("[*] Live host checking completed.")

	if len(s.LiveHosts) > 0 {
		fmt.Println("[*] Found", len(s.LiveHosts),
			"live hosts from", len(mapHosts), "combinations host:port.")
	}
}

func (s *SSHResult) CheckLiveHostsWithWorkerPool(){
	mapHosts := mappingHosts()

	fmt.Println("[*] Checking live hosts (worker pool)...")

	workerCount := config.AppConfig.WorkersLiveCheck
	if workerCount < 50 {
		workerCount = 50
	}

	jobs := make(chan Host)
	var wg sync.WaitGroup
	var mu sync.Mutex

	// start workers
	for i := 0; i < workerCount; i++ {
		go func(id int) {
			for data := range jobs {
				address := fmt.Sprintf("%s:%s", data.Address, data.Port)
				if utils.PortIsOpen(data.Address, data.Port) {
					fmt.Println("[+] Host is live:", address)

					mu.Lock()
					s.AddLiveHost(data)
					mu.Unlock()
				} else {
					if config.LogDebug {
						fmt.Println("[-] Host is not reachable:", address)
					}
				}

				wg.Done()
			}
		}(i)
	}

	// send jobs
	for _, data := range mapHosts {
		wg.Add(1)
		jobs <- data
	}

	close(jobs)
	wg.Wait()

	fmt.Println("[*] Live host checking completed.")

	if len(s.LiveHosts) > 0 {
		fmt.Println("[*] Found", len(s.LiveHosts),
			"live hosts from", len(mapHosts), "combinations host:port.")
	}
}

func (s *SSHResult) CheckValidLogins() {
	dataLogins := s.mappingDataLogin()

	fmt.Println("[*] Checking SSH logins...")

	chunkSize := config.AppConfig.ChunkSize
	if chunkSize <= 0 {
		chunkSize = 10
	}

	sem := make(chan struct{}, chunkSize)
	var wg sync.WaitGroup
	var mu sync.Mutex

	for _, dataLogin := range dataLogins {
		wg.Add(1)

		go func(dl DataLogin) {
			defer wg.Done()

			// acquire slot
			sem <- struct{}{}
			defer func() { <-sem }()

			lKey := loginKey(dl)
			if _, exists := s.ValidLogins[lKey]; exists {
				return
			}
			success, err := CheckSshLogin(dl)
			if success {
				fmt.Printf("[+] Valid login found: %s@%s:%s with password: %s\n",
					dl.User, dl.Address, dl.Port, dl.Password)

				mu.Lock()
				s.ValidLogins[lKey] = dl
				// save temporary data to file
				saveLogin(dl)
				mu.Unlock()
			} else {
				if config.LogDebug {
					fmt.Printf("[-] Invalid login: %s@%s:%s with password: %s (%v)\n",
						dl.User, dl.Address, dl.Port, dl.Password, err)
				}
			}
		}(dataLogin)
	}

	wg.Wait()

	fmt.Println("[*] SSH login checking completed.")

	if len(s.ValidLogins) > 0 {
		fmt.Println("[*] Found", len(s.ValidLogins), "valid login combinations.")
	}
}

func (s *SSHResult) CheckValidLoginsWithDelay() {
	dataLogins := s.mappingDataLogin()

	fmt.Println("[*] Checking SSH logins with per-host rate limit...")

	chunkSize := config.AppConfig.ChunkSize
	if chunkSize <= 0 {
		chunkSize = 10
	}

	delay := time.Duration(config.AppConfig.SSHDelayMs) * time.Millisecond
	if delay < 200*time.Millisecond {
		delay = 400 * time.Millisecond
	}

	sem := make(chan struct{}, chunkSize)
	var wg sync.WaitGroup
	var mu sync.Mutex

	// per-host lock
	hostLocks := make(map[string]chan struct{})
	var hostMu sync.Mutex

	getHostLock := func(key string) chan struct{} {
		hostMu.Lock()
		defer hostMu.Unlock()

		if _, exists := hostLocks[key]; !exists {
			hostLocks[key] = make(chan struct{}, 1)
		}
		return hostLocks[key]
	}

	for _, dataLogin := range dataLogins {
		wg.Add(1)

		go func(dl DataLogin) {
			defer wg.Done()

			// global concurrency limit
			sem <- struct{}{}
			defer func() { <-sem }()

			// per-host serialization
			hKey := hostKey(dl)
			lock := getHostLock(hKey)

			lock <- struct{}{} // acquire host
			defer func() { <-lock }() // release

			lKey := loginKey(dl)
			if _, exists := s.ValidLogins[lKey]; exists {
				return
			}
			success, err := CheckSshLogin(dl)

			time.Sleep(delay) // delay before next attempt to same host

			if success {
				fmt.Printf("[+] Valid login found: %s@%s:%s with password: %s\n",
					dl.User, dl.Address, dl.Port, dl.Password)

				mu.Lock()
				s.ValidLogins[lKey] = dl
				// save temporary data to file
				saveLogin(dl)
				mu.Unlock()
			} else {
				if config.LogDebug {
					fmt.Printf("[-] Invalid login: %s@%s:%s with password: %s (%v)\n",
						dl.User, dl.Address, dl.Port, dl.Password, err)
				}
			}
		}(dataLogin)
	}

	wg.Wait()

	fmt.Println("[*] SSH login checking completed.")

	if len(s.ValidLogins) > 0 {
		fmt.Println("[*] Found", len(s.ValidLogins), "valid login combinations.")
	}
}

func (s *SSHResult) CheckValidLoginsWithWorkerPool() {
	dataLogins := s.mappingDataLogin()

	fmt.Println("[*] Checking SSH logins (worker pool)...")

	workerCount := config.AppConfig.WorkersLoginCheck
	if workerCount < 5 {
		workerCount = 10
	}

	jobs := make(chan DataLogin)
	var wg sync.WaitGroup
	var mu sync.Mutex

	// start workers
	for i := 0; i < workerCount; i++ {
		go func(id int) {
			for dl := range jobs {
				lKey := loginKey(dl)
				if _, exists := s.ValidLogins[lKey]; exists {
					// already found
					wg.Done()
					continue
				}

				success, err := CheckSshLogin(dl)

				if success {
					fmt.Printf("[+] Valid login found: %s@%s:%s with password: %s\n",
						dl.User, dl.Address, dl.Port, dl.Password)

					mu.Lock()
					s.ValidLogins[lKey] = dl
					// save temporary data to file
					saveLogin(dl)
					mu.Unlock()
				} else {
					if config.LogDebug {
						fmt.Printf("[-] Invalid login: %s@%s:%s with password: %s (%v)\n",
							dl.User, dl.Address, dl.Port, dl.Password, err)
					}
				}

				wg.Done()
			}
		}(i)
	}

	// send jobs
	for _, dl := range dataLogins {
		wg.Add(1)
		jobs <- dl
	}

	close(jobs)
	wg.Wait()

	fmt.Println("[*] SSH login checking completed.")
}

func (s *SSHResult) CheckValidLoginsWithWorkerPoolAndDelay() {
	dataLogins := s.mappingDataLogin()

	fmt.Println("[*] Checking SSH logins (worker pool + per-host rate limit)...")

	workerCount := config.AppConfig.WorkersLoginCheck
	if workerCount < 5 {
		workerCount = 10
	}

	delay := time.Duration(config.AppConfig.SSHDelayMs) * time.Millisecond
	if delay <= 0 {
		delay = 400 * time.Millisecond
	}

	jobs := make(chan DataLogin)
	var wg sync.WaitGroup
	var mu sync.Mutex

	// per-host lock
	hostLocks := make(map[string]chan struct{})
	var hostMu sync.Mutex

	getHostLock := func(key string) chan struct{} {
		hostMu.Lock()
		defer hostMu.Unlock()

		if _, exists := hostLocks[key]; !exists {
			hostLocks[key] = make(chan struct{}, 1)
		}
		return hostLocks[key]
	}

	// start workers
	for i := 0; i < workerCount; i++ {
		go func(id int) {
			for dl := range jobs {
				lKey := loginKey(dl)
				if _, exists := s.ValidLogins[lKey]; exists {
					// already found
					wg.Done()
					continue
				}

				// per-host serialization
				hKey := hostKey(dl)
				lock := getHostLock(hKey)

				lock <- struct{}{} // serialize per host
				success, err := CheckSshLogin(dl)
				time.Sleep(delay)
				<-lock

				if success {
					fmt.Printf("[+] Valid login found: %s@%s:%s with password: %s\n",
						dl.User, dl.Address, dl.Port, dl.Password)

					mu.Lock()
					s.ValidLogins[lKey] = dl
					// save temporary data to file
					saveLogin(dl)
					mu.Unlock()
				} else {
					if config.LogDebug {
						fmt.Printf("[-] Invalid login: %s@%s:%s with password: %s (%v)\n",
							dl.User, dl.Address, dl.Port, dl.Password, err)
					}
				}

				wg.Done()
			}
		}(i)
	}

	// send jobs
	for _, dl := range dataLogins {
		wg.Add(1)
		jobs <- dl
	}

	close(jobs)
	wg.Wait()

	fmt.Println("[*] SSH login checking completed.")
}

func (s *SSHResult) SaveToJSON() error {
	filePath := OutputName + ".json"
	var existingData = make(map[string]DataLogin)

	// if file exists, read existing data
	if _, err := os.Stat(filePath); err == nil {
		fileContent, err := os.ReadFile(filePath)
		if err != nil {
			return err
		}
		if err := json.Unmarshal(fileContent, &existingData); err != nil {
			return err
		}
	}

	// prepare new data
	for _, login := range s.ValidLogins {
		hostKey := loginKey(login)
		if _, exists := existingData[hostKey]; !exists {
			existingData[hostKey] = login
		}
	}

	// write to file
	dataToWrite, err := json.MarshalIndent(existingData, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filePath, dataToWrite, 0644); err != nil {
		return err
	}

	fmt.Println("[*] Results saved to", filePath)
	return nil
}

func (s *SSHResult) SaveToFile() error {
	if config.FormattedOutput == "json" || config.FormattedOutput == "all" {
		if err := s.SaveToJSON(); err != nil {
			fmt.Println("Error saving results to JSON:", err)
		}
		if config.FormattedOutput == "all" {
			if err := s.SaveToText(); err != nil {
				fmt.Println("Error saving results to text file:", err)
			}
		}
	} else if config.FormattedOutput == "text" {
		if err := s.SaveToText(); err != nil {
			fmt.Println("Error saving results to text file:", err)
		}
	}

	return nil
}

func (s *SSHResult) SaveToText() error {
	filePath := OutputName + ".txt"
	var lines []string

	// prepare data
	for _, login := range s.ValidLogins {
		line := fmt.Sprintf("%s:%s | %s | %s", login.Address, login.Port, login.User, login.Password)
		lines = append(lines, line)
	}

	dataToWrite := strings.Join(lines, "\n")
	// save append mode
	f, err := os.OpenFile(filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	if _, err := f.WriteString(dataToWrite + "\n"); err != nil {
		return err
	}

	fmt.Println("[*] Results saved to", filePath)
	return nil
}

func (s *SSHResult) AddLiveHost(host Host) {
	s.LiveHosts = append(s.LiveHosts, host)
}

func (s *SSHResult) mappingDataLogin() map[string]DataLogin {
	if config.LogDebug {
		fmt.Println("[*] Mapping login combinations...")
	}

	var mapDataLogin = make(map[string]DataLogin)

	for _, password := range config.AppConfig.Password {
		for _, user := range config.AppConfig.User {
			for _, host := range s.LiveHosts {
				dataLogin := DataLogin{
					Host:     host,
					User:     user,
					Password: password,
				}
				key := loginKeyWithPassword(dataLogin)
				if _, exists := mapDataLogin[key]; !exists {
					mapDataLogin[key] = dataLogin
				}
			}
		}
	}

	if config.LogDebug {
		fmt.Println("[*] Total combinations of login to check:", len(mapDataLogin))
	}

	return mapDataLogin
}

func (s *SSHResult) printTimeStats() {
	fmt.Println("[*] Time statistics:")
	fmt.Printf("    Live host check : %v\n", s.TimeStats.LiveCheck)
	fmt.Printf("    SSH login check : %v\n", s.TimeStats.LoginCheck)
	fmt.Printf("    Total runtime   : %v\n", s.TimeStats.Total)
	if len(s.ValidLogins) > 0 {
		avg := s.TimeStats.LoginCheck / time.Duration(len(s.ValidLogins))
		fmt.Printf("    Avg time/login  : %v\n", avg)
	}
}

func CheckSshLogin(dataLogin DataLogin) (bool, error) {
	// SSH client configuration
	config := &ssh.ClientConfig{
		User: dataLogin.User,
		Auth: []ssh.AuthMethod{
			ssh.Password(dataLogin.Password),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}

	// Connect to the SSH server
	address := fmt.Sprintf("%s:%s", dataLogin.Address, dataLogin.Port)
	client, err := ssh.Dial("tcp", address, config)
	if err != nil {
		return false, err
	}
	defer client.Close()

	// If we reach here, the login was successful
	return true, nil
}

func mappingHosts() map[string]Host {
	if config.LogDebug {
		fmt.Println("[*] Mapping host:port combinations...")
	}

	mapHosts := make(map[string]Host)
	for _, host := range config.AppConfig.Hosts {
		for _, port := range config.AppConfig.Port {
			key := strings.Join([]string{host, port}, ":")
			if _, exists := mapHosts[key]; !exists {
				mapHosts[key] = Host{Address: host, Port: port}
			}
		}
	}

	if config.LogDebug {
		fmt.Println("[*] Total combinations of host:port to check:", len(mapHosts))
	}

	return mapHosts
}

func hostKey(dl DataLogin) string {
	return dl.Address + ":" + dl.Port
}

func loginKey(dl DataLogin) string {
	hostKey := fmt.Sprintf("%s:%s:%s", dl.Address, dl.Port, dl.User)
	return fmt.Sprintf("%x", md5.Sum([]byte(hostKey)))
}

func loginKeyWithPassword(dl DataLogin) string {
	hostKey := fmt.Sprintf("%s:%s:%s:%s", dl.Address, dl.Port, dl.User, dl.Password)
	return fmt.Sprintf("%x", md5.Sum([]byte(hostKey)))
}

func saveLogin(dataLogin DataLogin) error {
	if config.FormattedOutput == "json" || config.FormattedOutput == "all" {
		if err := saveLoginToJSON(dataLogin); err != nil {
			return err
		}

		if config.FormattedOutput == "all" {
			if err := saveLoginToText(dataLogin); err != nil {
				return err
			}
		}
	} else if config.FormattedOutput == "text" {
		if err := saveLoginToText(dataLogin); err != nil {
			return err
		}
	}

	return nil
}

func saveLoginToJSON(dataLogin DataLogin) error {
	filePath := OutputName + ".json"
	var existingData = make(map[string]DataLogin)

	// if file exists, read existing data
	if _, err := os.Stat(filePath); err == nil {
		fileContent, err := os.ReadFile(filePath)
		if err != nil {
			return err
		}
		if err := json.Unmarshal(fileContent, &existingData); err != nil {
			return err
		}
	}

	hashKey := loginKey(dataLogin)
	if _, exists := existingData[hashKey]; !exists {
		existingData[hashKey] = dataLogin
	}

	dataToWrite, err := json.MarshalIndent(existingData, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filePath, dataToWrite, 0644); err != nil {
		return err
	}

	return nil
}

func saveLoginToText(dataLogin DataLogin) error {
	filePath := OutputName + ".txt"
	
	// save append mode
	f, err := os.OpenFile(filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	line := fmt.Sprintf(
		"%s:%s | %s | %s\n",
		dataLogin.Address,
		dataLogin.Port,
		dataLogin.User,
		dataLogin.Password,
	)
	if _, err := f.WriteString(line); err != nil {
		return err
	}

	return nil
}
