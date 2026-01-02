package pcaf

import (
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcap"
)

type Segment struct {
	Data []byte
}

type Exchanges struct {
	Request  Segment
	Response Segment
}

type Endpoint struct {
	IP   string
	Port uint16
}

type Stream struct {
	Exchanges []Exchanges
	Src       Endpoint
	Dst       Endpoint
}

type Options struct {
	DestinationIP   string
	DestinationPort uint16
}

type flowKey struct {
	AIP   string
	APort uint16
	BIP   string
	BPort uint16
}

type tcpPacket struct {
	srcIP   string
	dstIP   string
	srcPort uint16
	dstPort uint16
	payload []byte
}

func normalizeFlow(aIP string, aPort uint16, bIP string, bPort uint16) flowKey {
	if aIP < bIP || (aIP == bIP && aPort <= bPort) {
		return flowKey{aIP, aPort, bIP, bPort}
	}
	return flowKey{bIP, bPort, aIP, aPort}
}

func squashOptions(opts []Options) Options {
	var out Options
	for _, o := range opts {
		if o.DestinationIP != "" {
			out.DestinationIP = o.DestinationIP
		}
		if o.DestinationPort != 0 {
			out.DestinationPort = o.DestinationPort
		}
	}
	return out
}

func Parse(filename string, opts ...Options) ([]Stream, error) {
	options := squashOptions(opts)

	handle, err := pcap.OpenOffline(filename)
	if err != nil {
		return nil, err
	}
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	flows := make(map[flowKey][]tcpPacket)

	for packet := range packetSource.Packets() {
		netLayer := packet.NetworkLayer()
		transLayer := packet.TransportLayer()
		if netLayer == nil || transLayer == nil {
			continue
		}

		tcp, ok := transLayer.(*layers.TCP)
		if !ok || len(tcp.Payload) == 0 {
			continue
		}

		var srcIP, dstIP string
		switch ip := netLayer.(type) {
		case *layers.IPv4:
			srcIP = ip.SrcIP.String()
			dstIP = ip.DstIP.String()
		case *layers.IPv6:
			srcIP = ip.SrcIP.String()
			dstIP = ip.DstIP.String()
		default:
			continue
		}

		srcPort := uint16(tcp.SrcPort)
		dstPort := uint16(tcp.DstPort)

		if options.DestinationIP != "" {
			if srcIP != options.DestinationIP && dstIP != options.DestinationIP {
				continue
			}
		}

		if options.DestinationPort != 0 {
			if srcPort != options.DestinationPort && dstPort != options.DestinationPort {
				continue
			}
		}

		key := normalizeFlow(srcIP, srcPort, dstIP, dstPort)
		flows[key] = append(flows[key], tcpPacket{
			srcIP:   srcIP,
			dstIP:   dstIP,
			srcPort: srcPort,
			dstPort: dstPort,
			payload: append([]byte(nil), tcp.Payload...),
		})
	}

	var streams []Stream

	for _, packets := range flows {
		if len(packets) == 0 {
			continue
		}

		server := Endpoint{
			IP:   packets[0].dstIP,
			Port: packets[0].dstPort,
		}
		client := Endpoint{
			IP:   packets[0].srcIP,
			Port: packets[0].srcPort,
		}

		if options.DestinationIP != "" && options.DestinationIP == server.IP {
			client, server = server, client
		} else if options.DestinationPort != 0 && options.DestinationPort == server.Port {
			client, server = server, client
		}

		stream := Stream{
			Src: client,
			Dst: server,
		}

		var current *Exchanges
		lastDirection := ""

		for _, pkt := range packets {
			isRequest := pkt.dstIP == server.IP && pkt.dstPort == server.Port

			if isRequest {
				if current == nil {
					current = &Exchanges{}
					current.Request.Data = append(current.Request.Data, pkt.payload...)
					lastDirection = "request"
					continue
				}

				if lastDirection == "request" {
					current.Request.Data = append(current.Request.Data, pkt.payload...)
				} else {
					stream.Exchanges = append(stream.Exchanges, *current)
					current = &Exchanges{}
					current.Request.Data = append(current.Request.Data, pkt.payload...)
					lastDirection = "request"
				}
			} else {
				if current == nil {
					continue
				}

				if lastDirection == "response" {
					current.Response.Data = append(current.Response.Data, pkt.payload...)
				} else {
					current.Response.Data = append(current.Response.Data, pkt.payload...)
					lastDirection = "response"
				}
			}
		}

		if current != nil {
			stream.Exchanges = append(stream.Exchanges, *current)
		}

		if len(stream.Exchanges) > 0 {
			streams = append(streams, stream)
		}
	}

	return streams, nil
}
