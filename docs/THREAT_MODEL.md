
SDL Threat Model — Network Traffic Analyzer & IDS
Assets
Packet data (PCAP)

Detection rules

Alert logs & stats

Entry Points
PCAP (offline) and live interfaces

Threats & Mitigations
Parser Exploits / Buffer Overflows

Bounds-checked parsing; prefer fixed-size buffers; CI with AddressSanitizer/Valgrind.

Evasion via Fragmentation

Demo build does not reassemble; document limitation; recommend upstream reassembly or Suricata/Snort integration.

Privilege Concerns

Live capture requires privileged capability; recommend running as non-root with CAP_* capabilities only.

Rules Bypass / Incomplete DPI

Minimal DSL; encourage layered detection + richer protocol decoders.

Residual Risks
Minimal HTTP parser; limited protocol coverage by design for a compact demo.
