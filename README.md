# Sanitized IXFR capture for TechnitiumSoftware/DnsServer PR #2187

Excerpt from a production packet capture (2026-09-26), Windows Server AD-integrated
DNS master -> Technitium DNS secondary, showing the exact IXFR response that
triggers the condensation bug fixed by PR #2187.

## Contents

`ixfr-condense-sanitized.pcap` — one TCP connection (port 53) with two real IXFR
exchanges, SLL2/IPv4/TCP, checksums valid:

| Exchange | DNS id | Answers | Serials | What it shows |
|---|---|---|---|---|
| control round | 47128 | 78 | 862613 -> 862615 | normal hourly delta: delete block 37 RRs (30 distinct records, no duplicates), add block 37 RRs — condenses correctly even with the buggy code |
| **fatal round** | 47156 | **258** | 862708 -> 862710 | delete block carries **217 RRs covering only 2 distinct names**: the apex RRset (30 RRs = 19 A + 8 AAAA + 3 NS) is deleted **7 times**; the add block carries 37 RRs with the same apex set exactly **once** |

Fatal message anatomy (answer section, 258 RRs):

```
idx   0        SOA  serial 862710            <- envelope first SOA (new version)
idx   1        SOA  serial 862708            <- start of delete block (old version)
idx   2..218   217 RRs: 210x apex example.com (7 copies of the 30-RR apex set)
                        + 7x one other name
idx 219        SOA  serial 862710            <- start of add block (new version)
idx 220..256   37 RRs: 30x apex example.com (the apex set, exactly once) + 7x other
idx 257        SOA  serial 862710            <- envelope closing SOA
```

With `List<T>.Remove()` one-cancel-per-add semantics, 30 of the 210 apex
deletions cancel against the 30 additions; **180 surplus deletions survive and
every addition is dropped**. The secondary applies that net sequence, deletes
its entire apex RRset, advances the SOA serial, and logs the transfer as
successful — silent data loss.

`fatal-round-rrs.txt` — all 258 RRs of the fatal message in wire order, for
reading without Wireshark. (Note: `tcpdump` flags mid-stream TCP segments as
"invalid" because a DNS/TCP message spans several segments; Wireshark with TCP
reassembly shows the full messages.)

## Sanitization

Mechanical, structure-preserving rewrite of the original capture:

* zone name -> `example.com`; hostname labels -> stable pseudonyms
  (structural labels kept verbatim)
* IPv4 -> `192.0.2.0/24` (TEST-NET-1), IPv6 -> `2001:db8::/32`
* **unchanged:** SOA serials, TTLs, DNS message IDs, flags, RR counts, RR order,
  delete/add block structure — everything the bug depends on

Verified RR-by-RR against the original messages: identical type/class/TTL
sequence and block structure; only names and addresses differ, per the mapping
above. The original transfer was ACL-based (no TSIG, `ARCOUNT=0`), so no
credentials or key material exist in either version.

Original message digests (for provenance; the raw capture contains internal
names/addresses and is therefore not published):

* fatal round, 5202 bytes:   `sha256 17ab0ae0dff4339a55f9de93a136fe860cd6220fc08caa157bcfbb6de1c875f6`
* control round, 1650 bytes: `sha256 339d71c3ca7607773cb47d6dc499cf8df220d8d400d546db88bbc6f73fd60e33`
