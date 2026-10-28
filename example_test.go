// SPDX-License-Identifier: Apache-2.0

package masterfile_test

import (
	"fmt"
	"os"

	"github.com/miekg/dns"

	"github.com/vooon/go-masterfile"
)

// A zone is parsed, edited with a list of operations and rendered again;
// comments and layout survive, and only the SOA serial would change on
// Commit.
func ExampleZone_Apply() {
	z, err := masterfile.Parse([]byte(`$ORIGIN example.org.
$TTL 1h
@    IN SOA ns1 hostmaster 2024010100 2h 30m 2w 1h
     IN NS  ns1
; hosts
www  IN A   192.0.2.1 ; web
old  IN A   192.0.2.9
`), "example.org.")
	if err != nil {
		panic(err)
	}
	results, err := z.Apply(
		masterfile.Insert{Owner: "www", Records: []masterfile.RR{{Type: dns.TypeAAAA, Content: "2001:db8::1"}}},
		masterfile.Replace{
			Selector: masterfile.Selector{Owner: "www", Types: []uint16{dns.TypeA}},
			Records:  []masterfile.RR{{Type: dns.TypeA, Content: "192.0.2.2"}},
		},
		masterfile.DeleteOwner{Owner: "old.example.org."},
	)
	if err != nil {
		panic(err)
	}
	for i, r := range results {
		fmt.Printf("op %d: matched %d removed %d inserted %d\n", i, r.Matched, r.Removed, r.Inserted)
	}
	fmt.Println("changed:", z.Changed)
	if err := z.Format(os.Stdout, false); err != nil {
		panic(err)
	}
	// Output:
	// op 0: matched 0 removed 0 inserted 1
	// op 1: matched 1 removed 1 inserted 1
	// op 2: matched 1 removed 1 inserted 0
	// changed: true
	// $ORIGIN example.org.
	// $TTL 1h
	// @   IN SOA  ns1 hostmaster (
	//     2024010100 ; serial  Mon, 01 Jan 2024 #00
	//     2h         ; refresh
	//     30m        ; retry
	//     2w         ; expire
	//     1h         ; minimum
	// )
	//     IN NS   ns1
	// ; hosts
	// www IN A    192.0.2.2 ; web
	//     IN AAAA 2001:db8::1
}
