package main

import (
	"DNS/server"
	"fmt"
	"os"
)

func main() {
	var dns *server.DNSServer
	argLength := len(os.Args[1:])
	if argLength > 0 {
		dns = server.NewDNSWithDataFile(os.Args[1])
	} else {
		dns = server.NewDNS()
	}
	
	if err := dns.Serve(53); err != nil {
		fmt.Println(err)
	}
}
