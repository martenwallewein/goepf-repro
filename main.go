// Copyright (c) 2019 Dropbox, Inc.
// Full license can be found in the LICENSE file.

package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"time"

	"github.com/dropbox/goebpf"
)

type ipAddressList []string

var iface = flag.String("iface", "", "Interface to bind XDP program to")

// var elf = flag.String("elf", "ebpf_prog/xdp_fw.elf", "clang/llvm compiled binary file")
// var ipList ipAddressList

func main() {
	// flag.Var(&ipList, "drop", "IPv4 CIDR to DROP traffic from, repeatable")
	flag.Parse()
	if *iface == "" {
		fatalError("-iface is required.")
	}
	elf := "bpf/xdp_sock.elf"

	// Create eBPF system
	bpf := goebpf.NewDefaultEbpfSystem()
	// Load .ELF files compiled by clang/llvm
	err := bpf.LoadElf(elf)
	if err != nil {
		fatalError("LoadElf() failed: %v", err)
	}
	printBpfInfo(bpf)

	rxcnt := bpf.GetMapByName("rxcnt")
	if rxcnt == nil {
		fatalError("eBPF map 'rxcnt' not found")
	}
	xdp := bpf.GetProgramByName("xdp_sock")
	if xdp == nil {
		fatalError("Program 'xdp' not found.")
	}

	// Load XDP program into kernel
	err = xdp.Load()
	if err != nil {
		fatalError("xdp.Load(): %v", err)
	}

	// Attach to interface
	err = xdp.Attach(*iface)
	if err != nil {
		fatalError("xdp.Attach(): %v", err)
	}
	defer xdp.Detach()

	// Add CTRL+C handler + Kill handler
	ctrlC := make(chan os.Signal, 1)
	signal.Notify(ctrlC, os.Interrupt)
	signal.Notify(ctrlC, os.Kill)

	fmt.Println("XDP program successfully loaded and attached. Counters refreshed every second.")
	fmt.Println("Press CTRL+C to stop.")
	fmt.Println()

	// Print stat every second / exit on CTRL+C
	ticker := time.NewTicker(1 * time.Second)
	for {
		select {
		case <-ticker.C:
			fmt.Println("TYPE                 COUNT")
			for i := 0; i < 13; i++ {
				value, err := rxcnt.LookupInt(i)
				if err != nil {
					fatalError("LookupInt failed: %v", err)
				}
				fmt.Printf("%d    %d\n", i, value)
			}
		case <-ctrlC:
			fmt.Println("\nDetaching program and exit")
			return
		}
	}
}

func fatalError(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}

func printBpfInfo(bpf goebpf.System) {
	fmt.Println("Maps:")
	for _, item := range bpf.GetMaps() {
		fmt.Printf("\t%s: %v, Fd %v\n", item.GetName(), item.GetType(), item.GetFd())
	}
	fmt.Println("\nPrograms:")
	for _, prog := range bpf.GetPrograms() {
		fmt.Printf("\t%s: %v, size %d, license \"%s\"\n",
			prog.GetName(), prog.GetType(), prog.GetSize(), prog.GetLicense(),
		)

	}
	fmt.Println()
}
