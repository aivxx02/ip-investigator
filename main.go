package main

import (
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "Usage: ip-investigator <ip>")
		os.Exit(1)
	}
	fmt.Println("IP Investigator — scaffold OK, target:", os.Args[1])
}
