package main

import (
	"fmt"
	"os"
)

const version = "0.0.0-scaffold"

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "version", "--version", "-v":
			fmt.Println(version)
			return
		}
	}
	printHelp()
}

func printHelp() {
	fmt.Println("sshca — SSH certificate authority and management CLI")
	fmt.Println()
	fmt.Printf("Status: pre-release (%s). Commands coming.\n", version)
	fmt.Println("See https://github.com/roselabs-io/sshca")
	fmt.Println()
	fmt.Println("Planned commands:")
	fmt.Println("  sshca ca init        Generate a CA keypair with correct permissions")
	fmt.Println("  sshca ca show        Print CA pubkeys + fingerprints")
	fmt.Println("  sshca cert sign      Sign a public key as a user or host cert")
	fmt.Println("  sshca cert list      Show the JSONL audit log")
	fmt.Println("  sshca cert inspect   Human-readable view of a cert")
	fmt.Println("  sshca cert renew     Re-sign with principals inferred from existing cert")
	fmt.Println("  sshca cert revoke    Revoke a cert via KRL")
	fmt.Println("  sshca cert krl       Print KRL metadata")
}
