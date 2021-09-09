//go:build linux
// +build linux

// This program demonstrates how to attach an eBPF program to a tracepoint and receive events
// via a ringbuffer.
package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"golang.org/x/sys/unix"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang-11 RingbufferExample ./bpf/ringbuffer_example.c -- -I../headers -O2

// An Event represents a event sent to userspace from the eBPF program
// running in the kernel. Note that this must match the C event_t structure,
// and that both C and Go structs must be aligned the same way.
type Event struct {
	PID      uint32
	Comm     [16]byte
	Filename [256]byte
}

func main() {
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	// Allow the current process to lock memory for eBPF resources.
	rrl, err := ebpf.RemoveMemlockRlimit()
	if err != nil {
		log.Fatal(err)
	}

	// Load pre-compiled programs and maps into the kernel.
	objs := RingbufferExampleObjects{}
	if err := LoadRingbufferExampleObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %s", err)
	}
	defer objs.Close()

	// Revert the process' rlimit after eBPF resources have been loaded.
	if err := rrl(); err != nil {
		log.Fatal(err)
	}

	tp, err := link.Tracepoint("syscalls", "sys_enter_openat", objs.TpSyscallSysEnterOpenat)
	if err != nil {
		log.Fatalf("opening tracepoint: %s", err)
	}
	defer tp.Close()

	// Open a ringbuf event reader from userspace on the BPF_MAP_TYPE_RINGBUF map
	// described in the eBPF C program.
	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		log.Fatalf("creating ringbuf event reader: %s", err)
	}
	defer rd.Close()

	go func() {
		// Wait for a signal and close the ringbuf reader,
		// which will interrupt rd.Read() and make the program exit.
		<-stopper
		log.Println("Received signal, exiting program..")

		if err := rd.Close(); err != nil {
			log.Fatalf("closing ringbuf event reader: %s", err)
		}
	}()

	log.Printf("Listening for events..")

	var event Event
	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			log.Printf("reading from ringbuf event reader: %s", err)
		}

		// Parse the event entry into an Event structure.
		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
			log.Printf("parsing ringbuf event: %s", err)
			continue
		}

		log.Printf("PID: %d(%s), filename: %s", event.PID, unix.ByteSliceToString(event.Comm[:]), unix.ByteSliceToString(event.Filename[:]))
	}
}
