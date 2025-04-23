package main

import (
	"github.com/netguru/myra-external-dns-webhook/cmd/webhook/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		panic(err)
	}
}
