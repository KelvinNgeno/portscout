package scanner

import "testing"

func TestExpandTargets(t *testing.T) {
	t.Run("plain host and ip", func(t *testing.T) {
		got, err := ExpandTargets([]string{"example.com", "10.0.0.1"})
		if err != nil || len(got) != 2 {
			t.Fatalf("got %v, err %v", got, err)
		}
	})

	t.Run("/30 drops network and broadcast", func(t *testing.T) {
		got, err := ExpandTargets([]string{"192.168.1.0/30"})
		if err != nil {
			t.Fatal(err)
		}
		want := []string{"192.168.1.1", "192.168.1.2"}
		if len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
			t.Fatalf("got %v, want %v", got, want)
		}
	})

	t.Run("/32 is a single host", func(t *testing.T) {
		got, err := ExpandTargets([]string{"10.1.2.3/32"})
		if err != nil || len(got) != 1 || got[0] != "10.1.2.3" {
			t.Fatalf("got %v, err %v", got, err)
		}
	})

	t.Run("too large", func(t *testing.T) {
		if _, err := ExpandTargets([]string{"10.0.0.0/8"}); err == nil {
			t.Fatal("expected error for /8")
		}
	})

	t.Run("invalid CIDR", func(t *testing.T) {
		if _, err := ExpandTargets([]string{"10.0.0.0/99"}); err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("empty", func(t *testing.T) {
		if _, err := ExpandTargets(nil); err == nil {
			t.Fatal("expected error")
		}
	})
}
