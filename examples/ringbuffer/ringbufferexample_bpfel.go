// Code generated by bpf2go; DO NOT EDIT.
// +build 386 amd64 amd64p32 arm arm64 mips64le mips64p32le mipsle ppc64le riscv64

package main

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"

	"github.com/cilium/ebpf"
)

// LoadRingbufferExample returns the embedded CollectionSpec for RingbufferExample.
func LoadRingbufferExample() (*ebpf.CollectionSpec, error) {
	reader := bytes.NewReader(_RingbufferExampleBytes)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("can't load RingbufferExample: %w", err)
	}

	return spec, err
}

// LoadRingbufferExampleObjects loads RingbufferExample and converts it into a struct.
//
// The following types are suitable as obj argument:
//
//     *RingbufferExampleObjects
//     *RingbufferExamplePrograms
//     *RingbufferExampleMaps
//
// See ebpf.CollectionSpec.LoadAndAssign documentation for details.
func LoadRingbufferExampleObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := LoadRingbufferExample()
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}

// RingbufferExampleSpecs contains maps and programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type RingbufferExampleSpecs struct {
	RingbufferExampleProgramSpecs
	RingbufferExampleMapSpecs
}

// RingbufferExampleSpecs contains programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type RingbufferExampleProgramSpecs struct {
	TpSyscallSysEnterOpenat *ebpf.ProgramSpec `ebpf:"tp_syscall_sys_enter_openat"`
}

// RingbufferExampleMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type RingbufferExampleMapSpecs struct {
	Events *ebpf.MapSpec `ebpf:"events"`
}

// RingbufferExampleObjects contains all objects after they have been loaded into the kernel.
//
// It can be passed to LoadRingbufferExampleObjects or ebpf.CollectionSpec.LoadAndAssign.
type RingbufferExampleObjects struct {
	RingbufferExamplePrograms
	RingbufferExampleMaps
}

func (o *RingbufferExampleObjects) Close() error {
	return _RingbufferExampleClose(
		&o.RingbufferExamplePrograms,
		&o.RingbufferExampleMaps,
	)
}

// RingbufferExampleMaps contains all maps after they have been loaded into the kernel.
//
// It can be passed to LoadRingbufferExampleObjects or ebpf.CollectionSpec.LoadAndAssign.
type RingbufferExampleMaps struct {
	Events *ebpf.Map `ebpf:"events"`
}

func (m *RingbufferExampleMaps) Close() error {
	return _RingbufferExampleClose(
		m.Events,
	)
}

// RingbufferExamplePrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to LoadRingbufferExampleObjects or ebpf.CollectionSpec.LoadAndAssign.
type RingbufferExamplePrograms struct {
	TpSyscallSysEnterOpenat *ebpf.Program `ebpf:"tp_syscall_sys_enter_openat"`
}

func (p *RingbufferExamplePrograms) Close() error {
	return _RingbufferExampleClose(
		p.TpSyscallSysEnterOpenat,
	)
}

func _RingbufferExampleClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Do not access this directly.
//go:embed ringbufferexample_bpfel.o
var _RingbufferExampleBytes []byte
