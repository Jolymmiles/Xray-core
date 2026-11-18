package reality

import (
	"net"
	"os"
	"strings"
	"sync"
	"testing"
)

// TestTicketSurvey probes real sites as REALITY targets, each in the list
// REALITY_SURVEY (space separated), and prints how they issue and resume
// tickets. Skipped without the list: it goes to the Internet.
func TestTicketSurvey(t *testing.T) {
	sites := strings.Fields(os.Getenv("REALITY_SURVEY"))
	if len(sites) == 0 {
		t.Skip("REALITY_SURVEY is empty")
	}
	var wg sync.WaitGroup
	sem := make(chan struct{}, 4)
	results := make([]string, len(sites))
	for i, site := range sites {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			config := &Config{Type: "tcp", Dest: net.JoinHostPort(site, "443")}
			shape, err := probeTicketShape(config, site, 2)
			if err != nil {
				results[i] = site + "\tno\t" + err.Error()
				return
			}
			results[i] = site + "\tyes\t" + strings.Join([]string{
				"tickets " + itoa(shape.Tickets) + "/" + itoa(shape.ResTickets),
				"len " + itoa(shape.TicketLen) + "/" + itoa(shape.ResTicketLen),
				"prefix " + itoa(len(shape.Prefix)),
				"nonce " + itoa(shape.NonceLen),
				"lifetime " + itoa(int(shape.Lifetime)),
				"flight " + itoa(shape.FlightRecords),
				"full " + ints(shape.FullRecords),
				"resumed " + ints(shape.ResRecords),
			}, ", ")
		}()
	}
	wg.Wait()
	for _, r := range results {
		t.Log(r)
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b []byte
	for ; n > 0; n /= 10 {
		b = append([]byte{byte('0' + n%10)}, b...)
	}
	if neg {
		b = append([]byte{'-'}, b...)
	}
	return string(b)
}

func ints(xs []int) string {
	parts := make([]string, len(xs))
	for i, x := range xs {
		parts[i] = itoa(x)
	}
	return "[" + strings.Join(parts, " ") + "]"
}
