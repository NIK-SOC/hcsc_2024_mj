package main

import (
	"fmt"
	"log"
	"net"
	"sync"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

const flag string = "HCSC24{JACK_KNOWS_JACKSHID_ABOUT_NETWORKING}"
const disclaimer string = "hint: we cannot leak the whole message at once, remember ascii? try char by char. id stands for index. you can use any IPv6 thats in the range and not the hint as src, dst can be anything."
const hintDst string = "2001:470:6d:d6::1337"

type PacketWithAddr struct {
	PacketData []byte
	Addr       net.Addr
}

var flagSlice []int
var conn *net.IPConn
var connMutex sync.Mutex

func init() {
	flagSlice = make([]int, len(flag))
	for i, c := range flag {
		flagSlice[i] = int(c)
	}
}

func main() {
	var err error
	conn, err = net.ListenIP("ip4:41", &net.IPAddr{IP: net.IPv4(0, 0, 0, 0)})
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	fmt.Println("The challenge is up!")

	packetChan := make(chan PacketWithAddr, 100) // Adjust the buffer size as needed, I believe 100 is fair for our competition
	var wg sync.WaitGroup

	for i := 0; i < 10; i++ { // Adjust the number of goroutines as needed
		wg.Add(1)
		go func() {
			defer wg.Done()
			handlePacket(packetChan)
		}()
	}

	buf := make([]byte, 1500)
	for {
		n, addr, err := conn.ReadFrom(buf)
		if err != nil {
			panic(err)
		}
		packetChan <- PacketWithAddr{PacketData: buf[:n], Addr: addr}
	}
	// since this runs forever, we don't need to close the packetChan
}

func handlePacket(packetChan <-chan PacketWithAddr) {
	for packet := range packetChan {
		processPacket(packet)
	}
}

func processPacket(packetWithAddr PacketWithAddr) {

	packet := gopacket.NewPacket(packetWithAddr.PacketData, layers.LayerTypeIPv6, gopacket.Default)
	if packet == nil {
		log.Println("Failed to decode packet")
		return
	}

	icmpv6Layer := packet.Layer(layers.LayerTypeICMPv6)
	if icmpv6Layer != nil {
		icmpv6, _ := icmpv6Layer.(*layers.ICMPv6)
		if icmpv6.TypeCode.Type() != layers.ICMPv6TypeEchoRequest {
			return
		}
	}

	icmpv6EchoLayer := packet.Layer(layers.LayerTypeICMPv6Echo)
	if icmpv6EchoLayer != nil {
		icmpv6, _ := icmpv6EchoLayer.(*layers.ICMPv6Echo)
		log.Printf("ICMPv6Echo: id=%d, seq=%d from=%s (%s)\n", icmpv6.Identifier, icmpv6.SeqNumber, packetWithAddr.Addr, packet.NetworkLayer().NetworkFlow().Src().String())

		if icmpv6.Identifier >= uint16(len(flag)) {
			log.Printf("Received id=%d, expected less than %d from=%s (%s)\n", icmpv6.Identifier, len(flag), packetWithAddr.Addr, packet.NetworkLayer().NetworkFlow().Src().String())
			return
		}
		if packet.NetworkLayer().NetworkFlow().Dst().String() != hintDst && icmpv6.SeqNumber != uint16(flagSlice[icmpv6.Identifier]) {
			log.Printf("Received seq=%d, expected=%d from=%s (%s)\n", icmpv6.SeqNumber, flagSlice[icmpv6.Identifier], packetWithAddr.Addr, packet.NetworkLayer().NetworkFlow().Src().String())
			return
		}

		ip6Layer := &layers.IPv6{
			Version:    6,
			SrcIP:      packet.NetworkLayer().NetworkFlow().Dst().Raw(),
			DstIP:      packet.NetworkLayer().NetworkFlow().Src().Raw(),
			NextHeader: layers.IPProtocolICMPv6,
			HopLimit:   64,
		}

		icmpv6Layer := &layers.ICMPv6{
			TypeCode: layers.CreateICMPv6TypeCode(layers.ICMPv6TypeEchoReply, 0),
		}

		icmpv6Layer.SetNetworkLayerForChecksum(ip6Layer)

		icmp6EchoLayer := &layers.ICMPv6Echo{
			Identifier: icmpv6.Identifier,
			SeqNumber:  icmpv6.SeqNumber,
		}

		buffer := gopacket.NewSerializeBuffer()
		opts := gopacket.SerializeOptions{
			FixLengths:       true,
			ComputeChecksums: true,
		}

		var err error
		if hintDst == packet.NetworkLayer().NetworkFlow().Dst().String() {
			err = gopacket.SerializeLayers(buffer, opts, ip6Layer, icmpv6Layer, icmp6EchoLayer, gopacket.Payload([]byte(disclaimer)))
		} else {
			err = gopacket.SerializeLayers(buffer, opts, ip6Layer, icmpv6Layer, icmp6EchoLayer)
		}
		if err != nil {
			log.Println("Failed to serialize packet")
			return
		}

		connMutex.Lock()
		defer connMutex.Unlock()
		_, err = conn.WriteTo(buffer.Bytes(), &net.IPAddr{IP: packetWithAddr.Addr.(*net.IPAddr).IP})
		if err != nil {
			log.Println("Failed to send packet")
			return
		}
	}
}
