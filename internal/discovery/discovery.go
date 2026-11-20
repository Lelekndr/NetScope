package discovery

import (
	"fmt"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"net"
	"os"
	"time"
)

func CheckHost(ip string) (bool, error) {
	parsedIP := net.ParseIP(ip)

	if parsedIP == nil || parsedIP.To4() == nil {
		return false, fmt.Errorf("invalid IP address: %s", ip)
	}

	conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		return false, fmt.Errorf("erro ao abrir socket ICMP: %w", err)
	}
	defer conn.Close()

	message := icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Code: 0,
		Body: &icmp.Echo{
			ID:   os.Getpid() & 0xffff,
			Seq:  1,
			Data: []byte("NetScope Discovery"),
		},
	}

	messageBytes, err := message.Marshal(nil)
	if err != nil {
		return false, fmt.Errorf("erro ao serializar mensagem ICMP: %w", err)
	}
	destination := &net.IPAddr{
		IP: parsedIP,
	}

	_, err = conn.WriteTo(messageBytes, destination)
	if err != nil {
		return false, fmt.Errorf("erro ao enviar mensagem ICMP: %w", err)
	}
	err = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if err != nil {
		return false, fmt.Errorf("erro ao configurar timeout: %w", err)
	}

	buffer := make([]byte, 1500)

	for {
		n, peer, err := conn.ReadFrom(buffer)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				return false, nil
			}
			return false, fmt.Errorf("erro ao receber resposta ICMP: %w", err)
		}

		receivedMessage, err := icmp.ParseMessage(1, buffer[:n])
		if err != nil {
			continue
		}

		if receivedMessage.Type != ipv4.ICMPTypeEchoReply {
			continue
		}

		source, ok := peer.(*net.IPAddr)
		if !ok || !source.IP.Equal(parsedIP) {
			continue
		}

		echo, ok := receivedMessage.Body.(*icmp.Echo)
		if !ok {
			continue
		}

		if echo.ID != (os.Getpid()&0xffff) || echo.Seq != 1 {
			continue
		}

		return true, nil
	}
}
