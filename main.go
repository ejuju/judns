package main

import (
	"log"
	"net"
	"time"

	"github.com/ejuju/my-dns/pkg/dns"
)

func main() {
	query := dns.NewQuery(0, &dns.Question{
		Name:  dns.Name{"com"},
		Type:  1,
		Class: 1,
	})

	conn, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: net.IPv4(8, 8, 8, 8), Port: 53})
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	// Send query
	_, err = conn.Write(query.AppendEncoded([]byte{}))
	if err != nil {
		panic(err)
	}

	// Read response
	buffer := make([]byte, 512)
	conn.SetReadDeadline(time.Now().Add(time.Second))
	n, err := conn.Read(buffer)
	if err != nil {
		panic(err)
	}
	if n < 512 {
		buffer = buffer[:n]
	}
	_, response, err := dns.DecodeMessage(buffer)
	if err != nil {
		panic(err)
	}
	for _, answer := range response.Answer {
		log.Println(answer)
	}
}
