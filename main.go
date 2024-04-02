package main

import (
	"DNS/server"
	"fmt"
)

func main() {
	dns := server.NewDNS()
	if err := dns.Serve(53); err != nil {
		fmt.Println(err)
	}
}