package scanner

import (
	"reflect"
	"testing"
)

func TestParsePorts(t *testing.T) {
	tests := []struct {
		name    string
		spec    string
		want    []int
		wantErr bool
	}{
		{"single", "80", []int{80}, false},
		{"list", "443,22,80", []int{22, 80, 443}, false},
		{"range", "20-23", []int{20, 21, 22, 23}, false},
		{"mixed with dupes", "22,20-23,22", []int{20, 21, 22, 23}, false},
		{"spaces", " 80 , 443 ", []int{80, 443}, false},
		{"zero", "0", nil, true},
		{"too high", "70000", nil, true},
		{"reversed range", "100-50", nil, true},
		{"garbage", "abc", nil, true},
		{"bad range", "1-x", nil, true},
		{"empty", "", nil, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParsePorts(tc.spec)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr = %v", err, tc.wantErr)
			}
			if !tc.wantErr && !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
		})
	}
}

func TestParsePortsKeywords(t *testing.T) {
	top, err := ParsePorts("top")
	if err != nil || len(top) != len(TopPorts) {
		t.Fatalf("top: got %d ports, err %v", len(top), err)
	}
	all, err := ParsePorts("all")
	if err != nil || len(all) != 65535 {
		t.Fatalf("all: got %d ports, err %v", len(all), err)
	}
}
