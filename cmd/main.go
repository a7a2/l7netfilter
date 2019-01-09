// Copyright 2018 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

// afpacket provides a simple example of using afpacket with zero-copy to read
// packet data.
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	_ "github.com/coreos/go-iptables/iptables"

	"github.com/google/gopacket"
	"github.com/google/gopacket/afpacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"golang.org/x/net/bpf"

	_ "github.com/google/gopacket/layers"
)

var (
	iface      = flag.String("i", "lo", "Interface to read from")
	snaplen    = flag.Int("s", 0, "Snaplen, if <= 0, use 65535")
	bufferSize = flag.Int("b", 8, "Interface buffersize (MB)")
	filter     = flag.String("f", "port 631", "BPF filter")
	count      = flag.Int64("c", -1, "If >= 0, # of packets to capture before returning")
	verbose    = flag.Int64("log_every", 1, "Write a log every X packets")
	addVLAN    = flag.Bool("add_vlan", false, "If true, add VLAN header")
)

type afpacketHandle struct {
	TPacket *afpacket.TPacket
}

func newAfpacketHandle(device string, snaplen int, block_size int, num_blocks int,
	useVLAN bool, timeout time.Duration) (*afpacketHandle, error) {

	h := &afpacketHandle{}
	var err error

	if device == "any" {
		h.TPacket, err = afpacket.NewTPacket(
			afpacket.OptFrameSize(snaplen),
			afpacket.OptBlockSize(block_size),
			afpacket.OptNumBlocks(num_blocks),
			afpacket.OptAddVLANHeader(useVLAN),
			afpacket.OptPollTimeout(timeout),
			afpacket.SocketRaw,
			afpacket.TPacketVersion3)
	} else {
		h.TPacket, err = afpacket.NewTPacket(
			afpacket.OptInterface(device),
			afpacket.OptFrameSize(snaplen),
			afpacket.OptBlockSize(block_size),
			afpacket.OptNumBlocks(num_blocks),
			afpacket.OptAddVLANHeader(useVLAN),
			afpacket.OptPollTimeout(timeout),
			afpacket.SocketRaw,
			afpacket.TPacketVersion3)
	}
	return h, err
}

// ZeroCopyReadPacketData satisfies ZeroCopyPacketDataSource interface
func (h *afpacketHandle) ZeroCopyReadPacketData() (data []byte, ci gopacket.CaptureInfo, err error) {
	return h.TPacket.ZeroCopyReadPacketData()
}

// SetBPFFilter translates a BPF filter string into BPF RawInstruction and applies them.
func (h *afpacketHandle) SetBPFFilter(filter string, snaplen int) (err error) {
	pcapBPF, err := pcap.CompileBPFFilter(layers.LinkTypeEthernet, snaplen, filter)
	if err != nil {
		return err
	}
	bpfIns := []bpf.RawInstruction{}
	for _, ins := range pcapBPF {
		bpfIns2 := bpf.RawInstruction{
			Op: ins.Code,
			Jt: ins.Jt,
			Jf: ins.Jf,
			K:  ins.K,
		}
		bpfIns = append(bpfIns, bpfIns2)
	}
	if h.TPacket.SetBPF(bpfIns); err != nil {
		return err
	}
	return h.TPacket.SetBPF(bpfIns)
}

// LinkType returns ethernet link type.
func (h *afpacketHandle) LinkType() layers.LinkType {
	return layers.LinkTypeEthernet
}

// Close will close afpacket source.
func (h *afpacketHandle) Close() {
	h.TPacket.Close()
}

// afpacketComputeSize computes the block_size and the num_blocks in such a way that the
// allocated mmap buffer is close to but smaller than target_size_mb.
// The restriction is that the block_size must be divisible by both the
// frame size and page size.
func afpacketComputeSize(targetSizeMb int, snaplen int, pageSize int) (
	frameSize int, blockSize int, numBlocks int, err error) {

	if snaplen < pageSize {
		frameSize = pageSize / (pageSize / snaplen)
	} else {
		frameSize = (snaplen/pageSize + 1) * pageSize
	}

	// 128 is the default from the gopacket library so just use that
	blockSize = frameSize * 128
	numBlocks = (targetSizeMb * 1024 * 1024) / blockSize

	if numBlocks == 0 {
		return 0, 0, 0, fmt.Errorf("Interface buffersize is too small")
	}

	return frameSize, blockSize, numBlocks, nil
}

func main() {
	flag.Parse()
	log.Printf("Starting on interface %q", *iface)
	if *snaplen <= 0 {
		*snaplen = 65535
	}
	szFrame, szBlock, numBlocks, err := afpacketComputeSize(*bufferSize, *snaplen, os.Getpagesize())
	if err != nil {
		log.Fatal(err)
	}
	afpacketHandle, err := newAfpacketHandle(*iface, szFrame, szBlock, numBlocks, *addVLAN, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	err = afpacketHandle.SetBPFFilter(*filter, *snaplen)
	if err != nil {
		log.Fatal(err)
	}
	source := gopacket.ZeroCopyPacketDataSource(afpacketHandle)
	defer afpacketHandle.Close()

	bytes := uint64(0)
	packets := uint64(0)
	for ; *count != 0; *count-- {
		data, _, err := source.ZeroCopyReadPacketData()
		if err != nil {
			log.Fatal(err)
		}
		bytes += uint64(len(data))
		packets++
		if *count%*verbose == 0 {
			packet := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.NoCopy)
			if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
				tcp, _ := tcpLayer.(*layers.TCP)
				if app := packet.ApplicationLayer(); app != nil && tcp.DstPort == 631 {
					payload := string(app.Payload())
					lines := strings.Split(payload, "\n")
					for _, line := range lines {
						hasProto := strings.Contains(line, "HTTP/1.1") || strings.Contains(line, "HTTP/2.0")
						hasHost := strings.HasPrefix(strings.ToUpper(line), "HOST")
						if hasProto || hasHost {
							if hasProto {
								lineArray := strings.Fields(line)
								method := lineArray[0]
								path := lineArray[1]
								proto := lineArray[2]
								log.Printf("Method: %s, Path: %s, Proto: %s\n", method, path, proto)
							}
							if hasHost {
								hostNotTrimmed := strings.Join(strings.Split(line, ":")[1:], ":")
								host := strings.TrimSpace(hostNotTrimmed)
								log.Printf("Host: %s\n", host)
							}
							log.Printf("From src port %d to dst port %d\n", tcp.SrcPort, tcp.DstPort)
							log.Printf("Read in %d bytes in %d packets", bytes, packets)
						}
					}
				}
			}
		}
	}
}
