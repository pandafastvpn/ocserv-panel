package main

import (
	"net"
	"net/http"
	"strings"
	"testing"
)

func TestWriteCNBlockExcludeAppend(t *testing.T) {
	base := "# Group: vip\n# display-name = VIP\nrx-data-per-sec = 100\nno-route = 192.168.1.0/24\n"
	out := writeCNBlock(base, CNModeExclude, []string{"1.0.1.0/24", "1.0.2.0/23"})
	if !strings.HasPrefix(out, base) {
		t.Fatalf("head not preserved:\n%q", out)
	}
	if !strings.Contains(out, "no-route = 1.0.1.0/24\n") || !strings.Contains(out, "no-route = 1.0.2.0/23\n") {
		t.Fatalf("cidrs missing:\n%q", out)
	}
	if !strings.Contains(out, "no-route = 192.168.1.0/24\n") {
		t.Fatalf("manual no-route lost:\n%q", out)
	}
	if !strings.Contains(out, "# cn-mode = exclude\n") {
		t.Fatalf("mode marker missing:\n%q", out)
	}
	if strings.Count(out, cnBlockBegin) != 1 {
		t.Fatalf("block markers duplicated:\n%q", out)
	}
}

func TestWriteCNBlockWhitelistReplace(t *testing.T) {
	base := "# Group: vip\n" + cnBlockBegin + "\n# cn-mode = exclude\nno-route = 9.9.9.0/24\n" + cnBlockEnd + "\nroute = 10.0.0.0/8\n"
	out := writeCNBlock(base, CNModeWhitelist, []string{"1.2.3.0/24"})
	if strings.Contains(out, "9.9.9.0/24") {
		t.Fatalf("old block not removed:\n%q", out)
	}
	if !strings.Contains(out, "route = 1.2.3.0/24\n") {
		t.Fatalf("whitelist route missing:\n%q", out)
	}
	if !strings.HasSuffix(out, "route = 10.0.0.0/8\n") {
		t.Fatalf("tail not preserved:\n%q", out)
	}
	if strings.Count(out, cnBlockBegin) != 1 || strings.Count(out, cnBlockEnd) != 1 {
		t.Fatalf("marker count wrong:\n%q", out)
	}
}

func TestParseGroupConfigModes(t *testing.T) {
	exclude := "# display-name = VIP\nrx-data-per-sec = 100\n" +
		cnBlockBegin + "\n# cn-mode = exclude\nno-route = 1.0.1.0/24\nno-route = 1.0.2.0/23\n" + cnBlockEnd + "\n" +
		"no-route = 192.168.1.0/24\n"
	g := parseGroupConfig("vip", exclude)
	if !g.CNDirect || g.CNMode != CNModeExclude || g.CNDirectCount != 2 {
		t.Fatalf("exclude: CNDirect=%v mode=%q count=%d", g.CNDirect, g.CNMode, g.CNDirectCount)
	}
	if g.NoRoutes != "192.168.1.0/24" {
		t.Fatalf("NoRoutes should only hold manual entries, got %q", g.NoRoutes)
	}
	if g.RxDataPerSec != 100 {
		t.Fatalf("RxDataPerSec=%d", g.RxDataPerSec)
	}

	whitelist := cnBlockBegin + "\n# cn-mode = whitelist\nroute = 1.2.3.0/24\nroute = 4.5.6.0/24\n" + cnBlockEnd + "\nroute = 11.0.0.0/8\n"
	g2 := parseGroupConfig("vip2", whitelist)
	if !g2.CNDirect || g2.CNMode != CNModeWhitelist || g2.CNDirectCount != 2 {
		t.Fatalf("whitelist: CNDirect=%v mode=%q count=%d", g2.CNDirect, g2.CNMode, g2.CNDirectCount)
	}
	// The managed block must be stripped from the visible manual routes.
	if g2.Routes != "11.0.0.0/8" {
		t.Fatalf("Routes should only hold manual entries, got %q", g2.Routes)
	}
}

func TestWriteCNBlockIdempotent(t *testing.T) {
	cidrs := []string{"1.0.1.0/24", "1.0.2.0/23"}
	first := writeCNBlock("# Group: v\n", CNModeExclude, cidrs)
	second := writeCNBlock(first, CNModeExclude, cidrs)
	if first != second {
		t.Fatalf("not idempotent:\n--- first ---\n%q\n--- second ---\n%q", first, second)
	}
}

func TestCidrToRange(t *testing.T) {
	r, ok := cidrToRange("10.0.0.0/8")
	if !ok || r.start != 0x0A000000 || r.end != 0x0AFFFFFF {
		t.Fatalf("10.0.0.0/8 => %+v ok=%v", r, ok)
	}
	r, ok = cidrToRange("1.2.3.4/32")
	if !ok || r.start != 0x01020304 || r.end != 0x01020304 {
		t.Fatalf("1.2.3.4/32 => %+v ok=%v", r, ok)
	}
	if _, ok = cidrToRange("bogus"); ok {
		t.Fatal("bogus cidr accepted")
	}
}

func TestWhitelistComplementMath(t *testing.T) {
	// Complement of 1.0.0.0/8 in 1.x space, merged with reserved cuts.
	cuts := []ipRange{
		{start: 0x01000000, end: 0x01FFFFFF},
		{start: 0x0A000000, end: 0x0AFFFFFF}, // 10/8 reserved
	}
	cidrs := rangesToCIDRs(complementRanges(mergeIPRanges(sortedRanges(cuts))))
	got := strings.Join(cidrs, ",")
	want := "0.0.0.0/8,2.0.0.0/7,4.0.0.0/6,8.0.0.0/7,11.0.0.0/8,12.0.0.0/6,16.0.0.0/4,32.0.0.0/3,64.0.0.0/2,128.0.0.0/1"
	if got != want {
		t.Fatalf("complement mismatch:\n got %s\nwant %s", got, want)
	}
	for _, c := range cidrs {
		if _, _, err := parseCIDRForTest(c); err != nil {
			t.Fatalf("invalid cidr %q: %v", c, err)
		}
	}
}

func TestBuildGroupFileContentModes(t *testing.T) {
	form := func(mode string) *http.Request {
		r, _ := http.NewRequest("POST", "/", strings.NewReader(
			"name=g&rx_data_per_sec=0&tx_data_per_sec=0&session_timeout=0&idle_timeout=0&dns=&routes=&no_routes=&max_same_clients=0&cn_mode="+mode))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		return r
	}
	out, err := buildGroupFileContent("g", form(""))
	if err != nil || strings.Contains(out, cnBlockBegin) {
		t.Fatalf("mode empty should not add block: err=%v out=%q", err, out)
	}
	if cnZoneCIDRs() == nil {
		// Without a zone cache both managed modes must fail cleanly.
		if _, err := buildGroupFileContent("g", form("exclude")); err == nil {
			t.Fatal("exclude without cache should error")
		}
		if _, err := buildGroupFileContent("g", form("whitelist")); err == nil {
			t.Fatal("whitelist without cache should error")
		}
	}
}

func sortedRanges(rs []ipRange) []ipRange {
	out := append([]ipRange(nil), rs...)
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j].start < out[j-1].start; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}

func parseCIDRForTest(s string) (interface{}, interface{}, error) {
	_, ipnet, err := net.ParseCIDR(s)
	return nil, ipnet, err
}
