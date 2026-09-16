package ocirelease

import (
	"encoding/binary"
	"testing"
)

func fixtureELF(machine uint16, interpreter bool) []byte {
	data := make([]byte, 256)
	copy(data, []byte{0x7f, 'E', 'L', 'F', 2, 1, 1})
	binary.LittleEndian.PutUint16(data[16:18], 2)
	binary.LittleEndian.PutUint16(data[18:20], machine)
	binary.LittleEndian.PutUint32(data[20:24], 1)
	binary.LittleEndian.PutUint64(data[32:40], 64)
	binary.LittleEndian.PutUint16(data[52:54], 64)
	binary.LittleEndian.PutUint16(data[54:56], 56)
	if interpreter {
		binary.LittleEndian.PutUint16(data[56:58], 1)
		binary.LittleEndian.PutUint32(data[64:68], 3)
	}
	return data
}

func TestParseStrictRejectsDuplicateAndTrailingJSON(t *testing.T) {
	for _, input := range []string{
		`{"a":1,"a":2}`,
		`{"a":1} {"b":2}`,
		`{"a":NaN}`,
	} {
		if _, err := parseStrict([]byte(input)); err == nil {
			t.Fatalf("parseStrict accepted %q", input)
		}
	}
	value, err := parseStrict([]byte(`{"a":[1,true,null]}`))
	if err != nil || string(compactJSON(value)) != `{"a":[1,true,null]}` {
		t.Fatalf("canonical JSON failed: value=%v err=%v", value, err)
	}
}

func TestStaticELFPolicy(t *testing.T) {
	if !staticELF(fixtureELF(62, false), "amd64") {
		t.Fatal("static amd64 ELF was rejected")
	}
	if !staticELF(fixtureELF(183, false), "arm64") {
		t.Fatal("static arm64 ELF was rejected")
	}
	if staticELF(fixtureELF(62, true), "amd64") {
		t.Fatal("ELF with PT_INTERP was accepted")
	}
	if staticELF(fixtureELF(183, false), "amd64") {
		t.Fatal("wrong ELF machine was accepted")
	}
	malformed := fixtureELF(62, false)
	binary.LittleEndian.PutUint64(malformed[32:40], ^uint64(0)-16)
	binary.LittleEndian.PutUint16(malformed[56:58], 2)
	if staticELF(malformed, "amd64") {
		t.Fatal("overflowing program-header table was accepted")
	}
}

func TestV3PolicyRequiresExactSevenServiceOrderAndDomain(t *testing.T) {
	expected := []string{
		"gateway", "controlplane", "agentproxy", "firmwareorigin",
		"generationcoordinator", "accountauthorization", "factorytimeauthority",
	}
	if len(supportedServices) != len(expected) ||
		len(supportedServiceOrder) != len(expected) {
		t.Fatal("OCI v3 service set is incomplete")
	}
	for index, service := range expected {
		if supportedServiceOrder[index] != service || !supportedServices[service] {
			t.Fatalf("OCI v3 service %d=%q is not canonical", index, service)
		}
	}
	if string(signatureDomain) != "XIAOZHI-AGENT-OCI-RELEASE-V3\x00" {
		t.Fatal("OCI v3 signature domain changed")
	}
}
