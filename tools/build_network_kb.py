"""Author the network-layer attack knowledge bank -> nmapvuln/data/network_kb.json.

These are the network-wide techniques from the standard "Pentesting Network"
methodology (the topics in the HackTricks network section): layer-2/3 spoofing,
IPv6 takeover, first-hop-redundancy and routing-protocol attacks, VLAN hopping,
IDS/IPS evasion and so on. They are not tied to a single open port, so they are
kept separate from the per-service bank and shown in their own tab.

The content here is original and deliberately methodology-level: what the
technique is, when it applies, the standard tool, a representative command, what
a successful result looks like, and the defensive fix. It is reconnaissance and
assessment guidance for authorised engagements; the tool never runs any of it.

Run:  python tools/build_network_kb.py
"""

from __future__ import annotations

import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "..", "nmapvuln", "data", "network_kb.json")


def row(technique, tools, command, expect, mitigation):
    return {
        "technique": technique,
        "tools": tools,
        "command": command,
        "expect": expect,
        "mitigation": mitigation,
    }


TOPICS = [
    {
        "key": "sniffing-arp-spoofing",
        "name": "Sniffing & ARP spoofing (MITM)",
        "summary": "On a switched LAN, poison the ARP caches of a victim and the "
        "gateway so traffic routes through you, then read or alter it. The base "
        "layer-2 man-in-the-middle that most other LAN attacks build on.",
        "applies_when": "You have a foothold on the same broadcast domain (a LAN "
        "port, a wireless client, a compromised host) and no dynamic ARP "
        "inspection is enforced.",
        "rows": [
            row("Passive sniffing", "tcpdump, Wireshark",
                "tcpdump -i eth0 -w capture.pcap",
                "Cleartext credentials and tokens for any unencrypted protocol "
                "sharing the segment (FTP, HTTP, SNMP, LDAP simple bind).",
                "Encrypt everything in transit; segment the network; use switch "
                "port security."),
            row("ARP cache poisoning", "bettercap, ettercap, arpspoof",
                "bettercap -iface eth0 -eval \"set arp.spoof.targets <victim>; arp.spoof on; net.sniff on\"",
                "Victim and gateway send their traffic to you; you relay it and "
                "capture or modify it in flight.",
                "Enable Dynamic ARP Inspection (DAI) with DHCP snooping; use static "
                "ARP for critical hosts."),
            row("SSL/TLS downgrade in path", "bettercap (hstshijack), sslstrip",
                "bettercap -iface eth0 -caplet hstshijack/hstshijack",
                "Strips or downgrades TLS on victims that allow it, exposing "
                "session content.",
                "Enforce HSTS with preload; pin certificates; HTTPS-only."),
        ],
    },
    {
        "key": "llmnr-nbtns-mdns-relay",
        "name": "LLMNR / NBT-NS / mDNS / WPAD poisoning & NTLM relay",
        "summary": "Windows falls back to broadcast name resolution (LLMNR, "
        "NBT-NS, mDNS) and to WPAD proxy auto-discovery when DNS fails. Answer "
        "those broadcasts to capture NetNTLM hashes, or relay the authentication "
        "to another host for code execution without ever cracking it.",
        "applies_when": "A Windows network where LLMNR/NBT-NS are still enabled "
        "and SMB signing is not required on at least some hosts.",
        "rows": [
            row("Capture NetNTLM hashes", "Responder",
                "responder -I eth0 -wv",
                "NetNTLMv1/v2 hashes from hosts that mistype a share or hostname; "
                "crack offline with hashcat mode 5600.",
                "Disable LLMNR (GPO) and NBT-NS; disable WPAD; require SMB signing."),
            row("Relay instead of crack", "impacket ntlmrelayx",
                "ntlmrelayx.py -tf targets.txt -smb2support",
                "Authentication relayed to targets without SMB signing: command "
                "execution, SAM dump, or a session as the captured user.",
                "Enforce SMB signing everywhere; enable EPA/channel binding on "
                "LDAP and HTTP."),
            row("WPAD credential capture", "Responder (-w), mitm6",
                "responder -I eth0 -wFv",
                "Browsers requesting wpad.dat prompt for and leak domain "
                "credentials to a rogue proxy.",
                "Create a real wpad DNS record (or disable auto-proxy); disable "
                "Web Proxy Auto-Discovery."),
        ],
    },
    {
        "key": "dhcpv6-ipv6-takeover",
        "name": "DHCPv6 spoofing & IPv6 DNS takeover (mitm6)",
        "summary": "Even IPv4-only networks usually leave IPv6 on. Answer the "
        "clients' DHCPv6 solicitations to assign yourself as their IPv6 DNS "
        "server, then route name resolution (and WPAD) through you — a reliable "
        "primary vector into Active Directory.",
        "applies_when": "Windows clients with IPv6 enabled (the default) on a "
        "segment where no DHCPv6 guard is configured.",
        "rows": [
            row("Become the IPv6 DNS server", "mitm6",
                "mitm6 -d <domain.local> -i eth0",
                "Clients accept you as their DNS server over IPv6 and send you "
                "their queries, including WPAD.",
                "Enable RA Guard and DHCPv6 Guard on switches; disable IPv6 if "
                "genuinely unused; block rogue RAs."),
            row("Chain to relay", "mitm6 + ntlmrelayx",
                "ntlmrelayx.py -6 -t ldaps://<dc> -wh fakewpad.<domain> --delegate-access",
                "Relayed LDAP authentication can create a computer account or grant "
                "delegation, leading to privilege escalation in AD.",
                "Require LDAP channel binding and signing; restrict who can add "
                "computer accounts (ms-DS-MachineAccountQuota = 0)."),
        ],
    },
    {
        "key": "pentesting-ipv6",
        "name": "Pentesting IPv6",
        "summary": "IPv6 is frequently unmonitored. Discover live IPv6 hosts via "
        "multicast and neighbour discovery, then scan them directly — they often "
        "expose the same services as IPv4 with none of the firewalling.",
        "applies_when": "Any segment where IPv6 is active; especially dual-stack "
        "hosts whose IPv6 interface is less protected than IPv4.",
        "rows": [
            row("Discover link-local hosts", "THC-IPv6 (alive6), ping6",
                "alive6 eth0",
                "A list of responding IPv6 hosts on the link, including ones with "
                "no IPv4 service exposed.",
                "Apply equivalent firewall policy to IPv6; monitor ICMPv6; RA Guard."),
            row("Enumerate neighbours", "ip, ndisc6",
                "ip -6 neigh show dev eth0",
                "Neighbour cache entries mapping IPv6 addresses to MACs for "
                "follow-up scanning.",
                "Segment IPv6; restrict neighbour discovery; monitor NDP."),
            row("Scan over IPv6", "nmap",
                "nmap -6 -sV -p- <ipv6-address>",
                "Open services on the IPv6 interface, often unfiltered compared to "
                "the IPv4 side of the same host.",
                "Firewall IPv6 to parity with IPv4; disable unused IPv6."),
        ],
    },
    {
        "key": "vlan-hopping",
        "name": "VLAN hopping / lateral segmentation bypass",
        "summary": "Reach VLANs you were not placed in, either by negotiating a "
        "trunk with a switch that leaves DTP on (switch spoofing) or by "
        "double-tagging frames so the first tag is stripped and the second "
        "delivers you into another VLAN.",
        "applies_when": "An access port with DTP enabled, or a native-VLAN "
        "misconfiguration that allows double-tagged frames to leak.",
        "rows": [
            row("Switch spoofing (DTP)", "yersinia, frogger",
                "yersinia -I   # enable trunking via DTP, then read 802.1Q tags",
                "The port becomes a trunk and you receive traffic for every VLAN; "
                "create sub-interfaces per tag to reach them.",
                "Disable DTP (switchport nonegotiate); set access ports to "
                "'switchport mode access'."),
            row("Double tagging", "Scapy",
                "sendp(Ether()/Dot1Q(vlan=1)/Dot1Q(vlan=<target>)/IP(dst=...)/..., iface='eth0')",
                "A one-way frame is delivered into the target VLAN when the native "
                "VLAN matches the outer tag.",
                "Never use VLAN 1 as native; set a dedicated unused native VLAN; "
                "prune trunks."),
        ],
    },
    {
        "key": "hsrp-glbp-attacks",
        "name": "GLBP & HSRP (first-hop redundancy) attacks",
        "summary": "HSRP, VRRP and GLBP elect a virtual default gateway by "
        "priority. If the election packets are unauthenticated (or use the "
        "well-known cleartext key), claim the highest priority to become the "
        "active gateway and route the segment's traffic through you.",
        "applies_when": "You can see HSRP/VRRP/GLBP hellos on the segment and "
        "they carry no authentication or a default/cleartext key.",
        "rows": [
            row("Observe the election", "Wireshark, Loki",
                "wireshark -i eth0 -f 'proto 112 or udp port 1985 or udp port 3222'",
                "Group, virtual IP, current priority and any authentication in the "
                "HSRP/VRRP/GLBP hellos.",
                "Authenticate FHRP with a strong key; restrict which ports may "
                "source the protocol."),
            row("Seize the active role", "Loki, scapy",
                "loki_gtk.py   # send HSRP coup with priority 255",
                "You become the active gateway; victims route through you, giving "
                "a full man-in-the-middle for the subnet.",
                "Use the maximum priority on real routers plus MD5 auth; enable "
                "port security."),
        ],
    },
    {
        "key": "eigrp-attacks",
        "name": "EIGRP attacks",
        "summary": "EIGRP forms neighbour adjacencies and exchanges routes. Where "
        "it is unauthenticated, inject yourself as a neighbour to advertise bogus "
        "routes (blackhole or redirect traffic) or flood the process.",
        "applies_when": "You observe EIGRP hellos (IP protocol 88, multicast "
        "224.0.0.10) with no MD5/SHA authentication.",
        "rows": [
            row("Discover EIGRP", "Wireshark, tcpdump",
                "tcpdump -i eth0 -n proto 88",
                "EIGRP hellos revealing the autonomous-system number and whether "
                "authentication is set.",
                "Enable EIGRP authentication (key-chain); use passive-interface on "
                "access segments."),
            row("Inject a route", "Scapy, FRRouting",
                "# craft an EIGRP neighbour with Scapy and advertise a /0 route",
                "Traffic for the advertised prefixes is pulled toward you — a "
                "redirect or blackhole.",
                "Authenticate the routing protocol; filter routes; restrict "
                "adjacencies to known interfaces."),
        ],
    },
    {
        "key": "ids-ips-evasion",
        "name": "IDS / IPS evasion",
        "summary": "Signature and reassembly engines can be slipped with "
        "fragmentation, decoys, timing and source manipulation. Useful to "
        "confirm whether a negative scan result reflects a hardened host or a "
        "sensor dropping your probes.",
        "applies_when": "A scan returns suspiciously little, or you need to test "
        "whether network sensors detect the assessment traffic.",
        "rows": [
            row("Fragment probes", "nmap",
                "nmap -f -p- <ip>",
                "Fragmented packets that may pass sensors doing no reassembly.",
                "Enforce full stream reassembly on the IPS; drop tiny fragments."),
            row("Decoys and spoofed source", "nmap",
                "nmap -D RND:10 -p- <ip>",
                "Your real source address is hidden among decoys in the logs.",
                "Correlate on behaviour, not single source IPs; rate-limit."),
            row("Slow and randomise", "nmap",
                "nmap -T1 --scan-delay 5s --randomize-hosts <range>",
                "Probe rate below threshold-based detection windows.",
                "Use long-baseline anomaly detection, not just short-window "
                "thresholds."),
            row("Source-port trust", "nmap",
                "nmap -sS -g 53 -p- <ip>",
                "Probes sourced from a trusted port (53, 88) may bypass weak ACLs.",
                "Do not trust source ports in firewall rules; use stateful policy."),
        ],
    },
    {
        "key": "ssdp-upnp-evilssdp",
        "name": "SSDP & UPnP spoofing (EvilSSDP)",
        "summary": "Hosts discover services by multicasting SSDP searches. Answer "
        "them with a rogue device whose description points at an attacker page to "
        "phish credentials or deliver content, or abuse writable UPnP IGD rules.",
        "applies_when": "SSDP (UDP 1900) is open on the segment and clients browse "
        "network devices.",
        "rows": [
            row("Rogue SSDP device", "evil-ssdp",
                "evil-ssdp eth0 -t <template>",
                "Victims browsing network devices open your fake device page; a "
                "credential template harvests logins.",
                "Disable UPnP/SSDP where not needed; filter multicast 1900; user "
                "awareness."),
            row("Enumerate UPnP IGD", "upnpc (miniupnpc)",
                "upnpc -l",
                "The internet gateway's port-mapping table; writable mappings can "
                "expose internal hosts.",
                "Disable UPnP IGD on gateways; restrict port-mapping to trusted "
                "clients."),
        ],
    },
    {
        "key": "dds-rtps-impersonation",
        "name": "DDS / RTPS service impersonation",
        "summary": "DDS (Data Distribution Service) over RTPS is used in robotics, "
        "ROS 2 and industrial systems. Unauthenticated participants can be "
        "discovered and impersonated to read or publish topic data.",
        "applies_when": "You find RTPS discovery traffic (default UDP 7400+) on an "
        "OT/robotics segment with DDS security disabled.",
        "rows": [
            row("Discover participants", "Wireshark, RustDDS/FastDDS tooling",
                "# capture RTPS discovery on UDP 7400-7500 and enumerate participants",
                "The list of DDS participants, topics and data types on the bus.",
                "Enable the DDS Security plugins (authentication, access control, "
                "encryption); segment OT networks."),
            row("Impersonate a publisher", "FastDDS / CycloneDDS APIs",
                "# join the domain and publish to a discovered topic",
                "Injected data accepted by subscribers when no authentication is "
                "enforced.",
                "Require mutual authentication and signed data; isolate the DDS "
                "domain."),
        ],
    },
    {
        "key": "telecom-exploitation",
        "name": "Telecom network exploitation",
        "summary": "Mobile core and interconnect protocols — GTP, SS7, Diameter, "
        "SIP — carry little inherent authentication. On a reachable core or "
        "roaming interface they allow subscriber tracking, interception and "
        "fraud. High-level reference; relevant only on telecom infrastructure.",
        "applies_when": "The engagement scope includes a mobile core, a lab EPC, "
        "or an SS7/Diameter interconnect you are authorised to test.",
        "rows": [
            row("Map the GTP control plane", "GTPmap, Wireshark",
                "# probe GTP-C on UDP 2123 and enumerate reachable nodes",
                "Reachable SGSN/GGSN/PGW endpoints and whether GTP is filtered at "
                "the edge.",
                "Enforce GTP firewalling at borders (GRX/IPX); validate TEIDs; "
                "rate-limit."),
            row("SS7/Diameter location & intercept", "SigPloit (lab only)",
                "# issue MAP/Diameter queries against an authorised test core",
                "Subscriber location or interception where the signalling link "
                "trusts the peer.",
                "Deploy SS7/Diameter firewalls; apply GSMA FS.11/FS.19 category "
                "filtering; monitor for cross-category messages."),
        ],
    },
    {
        "key": "webrtc-dos",
        "name": "WebRTC DoS",
        "summary": "WebRTC's STUN/TURN and media paths can be abused for "
        "amplification and resource exhaustion against clients or relays, or to "
        "reveal a target's real IP behind a proxy via ICE candidates.",
        "applies_when": "A target application uses WebRTC (video/voice, "
        "conferencing) and you are assessing its availability or privacy "
        "exposure.",
        "rows": [
            row("Leak real IP via ICE", "browser, STUN query tools",
                "# collect ICE candidates from the offer/answer exchange",
                "Host and server-reflexive candidates can reveal a client's real "
                "address behind a VPN or proxy.",
                "Force relay-only ICE (TURN) for sensitive deployments; filter "
                "host candidates."),
            row("TURN/STUN resource exhaustion", "custom STUN flooder",
                "# flood allocation/binding requests at the TURN server",
                "Degraded or exhausted relay capacity, denying service to legitimate "
                "sessions.",
                "Authenticate TURN (long-term credentials); rate-limit allocations; "
                "quota per user."),
        ],
    },
]

REFERENCE = [
    {
        "key": "nmap-summary",
        "name": "Nmap summary (scan techniques)",
        "summary": "A quick reference for the scan types the rest of this tool "
        "consumes, so a thin result can be read correctly.",
        "applies_when": "Planning or interpreting the scan that feeds this report.",
        "rows": [
            row("Host discovery", "nmap", "nmap -sn <range>",
                "Live hosts without a port scan (ping sweep).",
                "n/a (reference)"),
            row("Full TCP service scan", "nmap", "nmap -sC -sV -p- -T4 <ip>",
                "All TCP ports with version and default-script detail — the ideal "
                "input for this tool.",
                "n/a (reference)"),
            row("UDP scan", "nmap", "nmap -sU --top-ports 100 <ip>",
                "Common UDP services (SNMP, DNS, NTP, IKE) that a TCP-only scan "
                "misses.",
                "n/a (reference)"),
            row("Stealth / evasion", "nmap", "nmap -sS -f -D RND:5 -T2 <ip>",
                "SYN scan with fragmentation, decoys and slower timing.",
                "n/a (reference)"),
        ],
    },
    {
        "key": "network-protocols",
        "name": "Network protocols explained",
        "summary": "Short reference for the layer-2/3 protocols the attacks above "
        "target, so the technique and its fix make sense in context.",
        "applies_when": "Background for the network-attack techniques.",
        "rows": [
            row("ARP", "n/a", "n/a",
                "Maps IPv4 to MAC with no authentication — the basis of LAN MITM.",
                "Dynamic ARP Inspection with DHCP snooping."),
            row("NDP / ICMPv6", "n/a", "n/a",
                "IPv6's neighbour and router discovery; rogue RAs redirect traffic.",
                "RA Guard, DHCPv6 Guard."),
            row("LLMNR / NBT-NS / mDNS", "n/a", "n/a",
                "Broadcast name resolution fallbacks that leak NetNTLM hashes.",
                "Disable via GPO; rely on DNS only."),
            row("FHRP (HSRP/VRRP/GLBP)", "n/a", "n/a",
                "Elects a virtual gateway by priority; unauthenticated election "
                "enables gateway takeover.",
                "Authenticate with a strong key; max priority on real routers."),
            row("802.1Q", "n/a", "n/a",
                "VLAN tagging; DTP and native-VLAN misconfig enable VLAN hopping.",
                "Disable DTP; dedicated unused native VLAN."),
        ],
    },
]


# Primary-tool / authoritative reference per topic (official sources, not a wiki).
REFS = {
    "sniffing-arp-spoofing": "https://www.bettercap.org/",
    "llmnr-nbtns-mdns-relay": "https://github.com/lgandx/Responder",
    "dhcpv6-ipv6-takeover": "https://github.com/dirkjanm/mitm6",
    "pentesting-ipv6": "https://github.com/vanhauser-thc/thc-ipv6",
    "vlan-hopping": "https://github.com/nccgroup/vlan-hopping---frogger",
    "hsrp-glbp-attacks": "https://github.com/raizo62/loki_on_kali",
    "eigrp-attacks": "https://github.com/raizo62/loki_on_kali",
    "ids-ips-evasion": "https://nmap.org/book/man-bypass-firewalls-ids.html",
    "ssdp-upnp-evilssdp": "https://github.com/initstring/evil-ssdp",
    "dds-rtps-impersonation": "https://www.omg.org/spec/DDS-SECURITY/",
    "telecom-exploitation": "https://github.com/SigPloiter/SigPloit",
    "webrtc-dos": "https://datatracker.ietf.org/doc/html/rfc8826",
    "nmap-summary": "https://nmap.org/book/man.html",
    "network-protocols": "https://nmap.org/book/man.html",
}

# A little more depth on the topics that shipped thin.
EXTRA_ROWS = {
    "dds-rtps-impersonation": [
        row("Exhaust discovery", "custom RTPS flooder",
            "# flood PARTICIPANT/ENDPOINT discovery (SPDP/SEDP) on UDP 7400+",
            "Subscribers spend resources on fake participants, degrading the bus.",
            "Rate-limit discovery; isolate the DDS domain; enable the DDS Security "
            "access-control plugin."),
    ],
    "telecom-exploitation": [
        row("SIP enumeration", "sipvicious (svwar/svmap)",
            "svmap <range>   # then svwar to enumerate extensions",
            "Reachable SIP devices and valid extensions for follow-up.",
            "Authenticate SIP; restrict signalling to trusted peers; rate-limit "
            "REGISTER/INVITE."),
    ],
    "webrtc-dos": [
        row("Signalling/SDP tampering", "intercepting proxy",
            "# modify the SDP offer/answer in the signalling channel",
            "Forced codec or candidate changes that break or redirect the media "
            "session.",
            "Authenticate and integrity-protect signalling (DTLS-SRTP, secure "
            "WebSocket)."),
    ],
}


def main() -> int:
    for topic in TOPICS + REFERENCE:
        key = topic["key"]
        if key in REFS:
            topic["ref"] = REFS[key]
        if key in EXTRA_ROWS:
            topic["rows"].extend(EXTRA_ROWS[key])

    bundle = {
        "note": "Network-wide attack methodology. Original content, methodology "
        "level. The tool prints this reference; it never executes any of it. Run "
        "only against systems you are authorised to test.",
        "topics": TOPICS,
        "reference": REFERENCE,
    }
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(os.path.normpath(OUT), "w", encoding="utf-8") as fh:
        json.dump(bundle, fh, ensure_ascii=False, indent=1)
    total = sum(len(t["rows"]) for t in TOPICS) + sum(len(t["rows"]) for t in REFERENCE)
    print(f"{len(TOPICS)} attack topics + {len(REFERENCE)} reference pages, "
          f"{total} rows -> {os.path.normpath(OUT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
