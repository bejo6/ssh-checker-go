package main

import (
	"os"
	"fmt"
	"ssh-checker/internal/config"
	"ssh-checker/internal/sshchecker"
)

func main() {
	ParseFlags()

	if len(config.AppConfig.Hosts) == 0 {
		fmt.Println("[!] No valid hosts provided. Use -help for usage information.")
		os.Exit(1)
	}
	if len(config.AppConfig.Port) == 0 {
		fmt.Println("[!] No valid ports provided. Use -help for usage information.")
		os.Exit(1)
	}
	if len(config.AppConfig.User) == 0 {
		fmt.Println("[!] No valid usernames provided. Use -help for usage information.")
		os.Exit(1)
	}
	if len(config.AppConfig.Password) == 0 {
		fmt.Println("[!] No valid passwords provided. Use -help for usage information.")
		os.Exit(1)
	}

	sc := sshchecker.NewSSHChecker()
	sc.Run()
}
