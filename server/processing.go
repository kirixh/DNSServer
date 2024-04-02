package server

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"
)

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
	responseHeader.Flags = requestHeader.Flags | 1<<15 // Ставим QR = 1
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
