package main

import (
	"reflect"
	"testing"
	"unsafe"

	// Raise RLIMIT_MEMLOCK
	_ "github.com/cilium/ebpf/internal/testutils"
)

func TestLoadingSpec(t *testing.T) {
	spec, err := loadExample()
	if err != nil {
		t.Fatal("Can't load spec:", err)
	}

	if spec == nil {
		t.Fatal("Got a nil spec")
	}
}

func TestLoadingObjects(t *testing.T) {
	var objs exampleObjects
	if err := loadExampleObjects(&objs, nil); err != nil {
		t.Fatal("Can't load objects:", err)
	}
	defer objs.Close()

	if objs.Filter == nil {
		t.Error("Loading returns an object with nil programs")
	}

	if objs.Map1 == nil {
		t.Error("Loading returns an object with nil maps")
	}
}

func TestTypes(t *testing.T) {
	if exampleEHOOPY != 0 {
		t.Error("Expected exampleEHOOPY to be 0, got", exampleEHOOPY)
	}
	if exampleEFROOD != 1 {
		t.Error("Expected exampleEFROOD to be 0, got", exampleEFROOD)
	}

	e := exampleE(0)
	if size := unsafe.Sizeof(e); size != 4 {
		t.Error("Expected size of exampleE to be 4, got", size)
	}

	bf := exampleBarfoo{}
	if size := unsafe.Sizeof(bf); size != 16 {
		t.Error("Expected size of exampleE to be 16, got", size)
	}
	if reflect.TypeOf(bf.Bar).Kind() != reflect.Int64 {
		t.Error("Expected exampleBarfoo.Bar to be int64")
	}
	if reflect.TypeOf(bf.Baz).Kind() != reflect.Bool {
		t.Error("Expected exampleBarfoo.Baz to be bool")
	}
	if reflect.TypeOf(bf.Boo) != reflect.TypeOf(e) {
		t.Error("Expected examplebarfoo.Boo to be exampleE")
	}
}
