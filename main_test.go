package main

import (
	"strings"
	"testing"
)

func TestWriteCNBlockAppend(t *testing.T) {
	base := "# Group: vip\n# display-name = VIP\nrx-data-per-sec = 100\nno-route = 192.168.1.0/24\n"
	out := writeCNBlock(base, []string{"1.0.1.0/24", "1.0.2.0/23"})
	if !strings.HasPrefix(out, base) {
		t.Fatalf("head not preserved:\n%q", out)
	}
	if !strings.Contains(out, "no-route = 1.0.1.0/24\n") || !strings.Contains(out, "no-route = 1.0.2.0/23\n") {
		t.Fatalf("cidrs missing:\n%q", out)
	}
	if !strings.Contains(out, "no-route = 192.168.1.0/24\n") {
		t.Fatalf("manual no-route lost:\n%q", out)
	}
	if strings.Count(out, cnBlockBegin) != 1 {
		t.Fatalf("block markers duplicated:\n%q", out)
	}
}

func TestWriteCNBlockReplace(t *testing.T) {
	base := "# Group: vip\n" + cnBlockBegin + "\nno-route = 9.9.9.0/24\n" + cnBlockEnd + "\nroute = 10.0.0.0/8\n"
	out := writeCNBlock(base, []string{"1.0.1.0/24"})
	if strings.Contains(out, "9.9.9.0/24") {
		t.Fatalf("old block not removed:\n%q", out)
	}
	if !strings.Contains(out, "no-route = 1.0.1.0/24\n") {
		t.Fatalf("new cidr missing:\n%q", out)
	}
	if !strings.HasSuffix(out, "route = 10.0.0.0/8\n") {
		t.Fatalf("tail not preserved:\n%q", out)
	}
	if strings.Count(out, cnBlockBegin) != 1 || strings.Count(out, cnBlockEnd) != 1 {
		t.Fatalf("marker count wrong:\n%q", out)
	}
}

func TestParseGroupConfigWithCNBlock(t *testing.T) {
	content := "# display-name = VIP\nrx-data-per-sec = 100\n" +
		cnBlockBegin + "\nno-route = 1.0.1.0/24\nno-route = 1.0.2.0/23\n" + cnBlockEnd + "\n" +
		"no-route = 192.168.1.0/24\n"
	g := parseGroupConfig("vip", content)
	if !g.CNDirect || g.CNDirectCount != 2 {
		t.Fatalf("CNDirect=%v count=%d", g.CNDirect, g.CNDirectCount)
	}
	if g.NoRoutes != "192.168.1.0/24" {
		t.Fatalf("NoRoutes should only hold manual entries, got %q", g.NoRoutes)
	}
	if g.RxDataPerSec != 100 {
		t.Fatalf("RxDataPerSec=%d", g.RxDataPerSec)
	}
}

func TestWriteCNBlockIdempotent(t *testing.T) {
	cidrs := []string{"1.0.1.0/24", "1.0.2.0/23"}
	first := writeCNBlock("# Group: v\n", cidrs)
	second := writeCNBlock(first, cidrs)
	if first != second {
		t.Fatalf("not idempotent:\n--- first ---\n%q\n--- second ---\n%q", first, second)
	}
}
