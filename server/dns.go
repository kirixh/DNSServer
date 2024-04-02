package server

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
)

const (
	connType   = "udp"
	defaultPathToDataFile   = "DNS_data.txt"
	maxMsgSize = 512
	defaultTTL = 86400
)

type dnsType uint16

const (
	_ dnsType = iota
	A
	CNAME
	Unknown
)

type dnsClass uint16

const (
	_ dnsClass = iota
	IN
	CS
	CH
	HS
)

var stringToDNSTypeMap = map[string]dnsType{
	"A":     A,
	"CNAME": CNAME,
}

var stringToDNSClassMap = map[string]dnsClass{
	"IN": IN,
	"CS": CS,
	"CH": CH,
	"HS": HS,
}

type dnsRecord struct {
	Name  string
	Type  dnsType
	Class dnsClass
	TTL   uint32
}

type DNSHeader struct {
	PacketID uint16
	Flags    uint16
	QDCount  uint16
	ANCount  uint16
	NSCount  uint16
	ARCount  uint16
}

type DNSServer struct {
	UDPConn    *net.UDPConn
	recordsMap map[dnsRecord]string
	pathToDataFile string
}

func NewDNS() *DNSServer {
	dns := DNSServer{nil, map[dnsRecord]string{}, defaultPathToDataFile}
	dns.init()
	return &dns
}

func NewDNSWithDataFile(pathToDataFile string) *DNSServer {
	dns := DNSServer{nil, map[dnsRecord]string{}, pathToDataFile}
	dns.init()
	return &dns
}

func (dns *DNSServer) init() {
	if err := dns.loadDNSRecords(dns.pathToDataFile); err != nil {
		fmt.Println(err)
	}
}

func (dns *DNSServer) SetPathToDataFile(pathToDataFile string) {
	if pathToDataFile != dns.pathToDataFile {
		dns.pathToDataFile = pathToDataFile
		dns.init()
	}
}

func (dns *DNSServer) Serve(port uint) error {
	udpAddr, err := net.ResolveUDPAddr(connType, ":"+strconv.Itoa(int(port)))
	if err != nil {
		return fmt.Errorf("ошибка разрешения адреса: %w", err)
	}

	dns.UDPConn, err = net.ListenUDP(connType, udpAddr)
	if err != nil {
		return fmt.Errorf("ошибка начала слушания: %w", err)
	}
	defer dns.UDPConn.Close()

	fmt.Println("DNS сервер слушает порт ", strconv.Itoa(int(port)))

	for {
		buffer := make([]byte, maxMsgSize)
		_, remoteAddr, err := dns.UDPConn.ReadFromUDP(buffer)
		if err != nil {
			fmt.Println("ошибка чтения:", err)
			continue
		}

		go dns.handleDNSRequest(remoteAddr, buffer)
	}
}

func (dns *DNSServer) handleDNSRequest(remoteAddr *net.UDPAddr, request []byte) {
	requestBuffer := bytes.NewBuffer(request)
	header, err := processHeader(requestBuffer)
	if err != nil {
		fmt.Println(err)
	}

	qRecords := make([]dnsRecord, 0, header.QDCount)
	for range header.QDCount {
		domain, err := extractDomain(requestBuffer)
		if err != nil {
			fmt.Println(err)
			continue
		}
		qtype := dnsType(binary.BigEndian.Uint16(requestBuffer.Next(2)))
		qclass := dnsClass(binary.BigEndian.Uint16(requestBuffer.Next(2)))
		qRecords = append(qRecords, dnsRecord{domain, qtype, qclass, defaultTTL})
	}

	qAnswers := make([]string, 0)
	for _, qRecord := range qRecords {
		recordData, ok := dns.recordsMap[qRecord]
		if ok {
			qAnswers = append(qAnswers, recordData)
		} else {
			//handleRemoteDNSRequest(remoteAddr, request)
		}
	}

	dns.sendLocalResponse(remoteAddr, header, qRecords, qAnswers)
}

func (dns *DNSServer) sendLocalResponse(remoteAddr *net.UDPAddr, requestHeader *DNSHeader, qRecords []dnsRecord, qAnswers []string) {
	response := buildResponse(requestHeader, qRecords, qAnswers)

	if _, err := dns.UDPConn.WriteToUDP(response, remoteAddr); err != nil {
		fmt.Println("Ошибка отправки локального ответа:", err)
	}
}

func processHeader(requestBuf *bytes.Buffer) (*DNSHeader, error) {
	var queryHeader DNSHeader

	if err := binary.Read(requestBuf, binary.BigEndian, &queryHeader); err != nil {
		return nil, fmt.Errorf("ошибка чтения заголовка: %w", err)
	}
	return &queryHeader, nil
}

func extractDomain(requestBuf *bytes.Buffer) (string, error) {
	var (
		domain string
		err    error
	)

	for b, err := requestBuf.ReadByte(); b != 0x00 && err == nil; b, err = requestBuf.ReadByte() {
		labelLen := int(b)
		domain += string(requestBuf.Next(labelLen)) + "."
	}

	if err != nil {
		err = fmt.Errorf("ошибка извлечения домена: %w", err)
	}

	return domain[:len(domain)-1], err
}

func encodeDomain(domain string, responseBuf *bytes.Buffer) error {
	parts := strings.Split(domain, ".")

	for _, label := range parts {
		if len(label) > 0 {
			if err := responseBuf.WriteByte(byte(len(label))); err != nil {
				return fmt.Errorf("ошибка записи домена в буффер: %w", err)
			}
			if _, err := responseBuf.Write([]byte(label)); err != nil {
				return fmt.Errorf("ошибка записи домена в буффер: %w", err)
			}
		}
	}
	if err := responseBuf.WriteByte(0x00); err != nil {
		return fmt.Errorf("ошибка записи домена в буффер: %w", err)
	}

	return nil
}

func encodeRData(rdata string, responseBuf *bytes.Buffer) error {
	parts := strings.Split(rdata, ".")
	if err := binary.Write(responseBuf, binary.BigEndian, uint16(len(parts))); err != nil {
		return fmt.Errorf("ошибка записи RDATA в буффер: %w", err)
	}

	for _, label := range parts {
		if len(label) > 0 {
			data, err := strconv.Atoi(label)
			if err != nil {
				return fmt.Errorf("ошибка записи домена в буффер: %w", err)
			}

			if err := responseBuf.WriteByte(byte(data)); err != nil {
				return fmt.Errorf("ошибка записи домена в буффер: %w", err)
			}
		}
	}

	return nil
}

// Построить ответ на основе локальной записи
func buildResponse(requestHeader *DNSHeader, qRecords []dnsRecord, qAnswers []string) []byte {
	responseBuffer := new(bytes.Buffer)
	responseHeader := *requestHeader
	responseHeader.Flags = requestHeader.Flags | 1 << 15 // Ставим QR = 1
	responseHeader.ANCount = uint16(len(qAnswers))
	if err := binary.Write(responseBuffer, binary.BigEndian, &responseHeader); err != nil {
		fmt.Println("Ошибка записи заголовка в буффер: %w", err)
		return []byte{}
	}

	for _, qRecord := range qRecords {
		if err := encodeDomain(qRecord.Name, responseBuffer); err != nil {
			fmt.Println("Ошибка построения ответа: %w", err)
			return []byte{}
		}
		binary.Write(responseBuffer, binary.BigEndian, &qRecord.Type)
		binary.Write(responseBuffer, binary.BigEndian, &qRecord.Class)
	}

	for idx, qAnswer := range qAnswers {
		if err := encodeDomain(qRecords[idx].Name, responseBuffer); err != nil {
			fmt.Println("Ошибка построения ответа: %w", err)
			return []byte{}
		}
		binary.Write(responseBuffer, binary.BigEndian, &qRecords[idx].Type)
		binary.Write(responseBuffer, binary.BigEndian, &qRecords[idx].Class)
		binary.Write(responseBuffer, binary.BigEndian, &qRecords[idx].TTL)
		if err := encodeRData(qAnswer, responseBuffer); err != nil {
			fmt.Println("Ошибка построения ответа: %w", err)
			return []byte{}
		}
	}

	return responseBuffer.Bytes()
}

func (dns *DNSServer) loadDNSRecords(filename string) error {

	file, err := os.Open(filename)
	if err != nil {
		return fmt.Errorf("ошибка открытия файла: %w", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()

		if strings.HasPrefix(line, ";") || len(strings.TrimSpace(line)) == 0 {
			continue
		}

		fields := strings.Fields(line)

		if len(fields) < 4 {
			continue
		}

		recordClass, ok := stringToDNSClassMap[fields[1]]
		if !ok {
			fmt.Printf("Ошибка чтения класса записи %s", fields[0])
			continue
		}

		recordType, ok := stringToDNSTypeMap[fields[2]]
		if !ok {
			fmt.Printf("Ошибка чтения типа записи %s", fields[0])
			continue
		}

		dns.recordsMap[dnsRecord{
			Name:  fields[0],
			Class: recordClass,
			Type:  recordType,
			TTL:   defaultTTL,
		}] = fields[3]
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("ошибка чтения файла: %w", err)
	}

	return nil
}
