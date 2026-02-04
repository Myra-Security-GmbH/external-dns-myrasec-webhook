package main

import (
	"github.com/Myra-Security-GmbH/external-dns-myrasec-webhook/cmd/webhook/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		panic(err)
	}
}
