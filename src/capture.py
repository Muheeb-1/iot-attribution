"""
CAPTURE - turning a real Wireshark recording into the same table the simulator writes.

WHAT THIS FILE DOES
-------------------
Everything downstream of step 3 - features, detection, attribution, the brief,
the dashboard - reads one thing: a flow table with these columns

    conn_id  t  src  dst  dport  bytes_out  bytes_in  pkts

src/generate.py invents that table. This file measures it, from a .pcapng
recorded off the lab network. Nothing else in the pipeline changes. That is
the whole point: if the attribution method only works on traffic I made up,
it is not a result, it is a tautology. Pointing the same untouched pipeline
at a real capture is what turns it into a claim about the world.

    real packets  ->  tshark  ->  flows  ->  the exact same table

WHAT A "FLOW" IS HERE
---------------------
A pcap is packets; the table wants connections. One row per flow, where a
flow is one conversation between two endpoints:

    TCP    one connection. A fresh SYN starts a new row even if the port
           pair repeats, because an ESP32 that reconnects to the broker
           forty times has made forty connections, and collapsing them
           would hide exactly the reconnect-storm behaviour worth seeing.
    UDP    packets sharing both endpoints and both ports.
    other  ARP, ICMP, anything without ports: grouped by the two endpoints.
           ARP is kept rather than dropped - a device suddenly ARPing its
           way across the subnet is lateral movement, and it is the one
           place that shows up first.

Any flow is closed after IDLE_SECONDS of silence, and a later packet opens a
new one. Without that, a device that broadcasts every thirty seconds for the
whole capture produces a single row spanning the entire recording, which is
useless to a per-window feature table.

WHO SENT IT: MAC, NOT IP
------------------------
Rows are keyed on the sender's hardware address. IP addresses are handed out
by the router and change between sessions; on this network 192.168.0.129 is
esp32-01 today and need not be tomorrow. The MAC is burned into the chip. An
attribution result that says "192.168.0.129 did it" is a result about a DHCP
lease, which is not a thing anyone can go and unplug.

The identity of the far end is resolved the same way when it is one of ours,
and otherwise left as the literal IP. That is deliberate: features.py decides
"outside the lab" by asking whether a destination is in the asset inventory,
so an unrecognised address must stay unrecognisable rather than being tidied
into some friendly name.

TWO HONEST DIFFERENCES FROM THE SIMULATOR
-----------------------------------------
1. bytes_out/bytes_in are WIRE bytes - full frames, headers included - because
   that is what a capture actually contains. The simulator's byte counts are
   nominal payload. So absolute volumes are not comparable between a simulated
   run and a captured one. Everything the detector does is relative to each
   device's own baseline, so this does not affect it, but it is the reason a
   captured run's raw numbers look different from a simulated one's.

2. A real capture is minutes long, not six hours, and the baseline has to be
   cut from it proportionally. The default is the first half. Say so out loud
   in the meta file rather than pretending a three-hour baseline exists.

USAGE
-----
    python -m src.capture pcap/data1.pcapng              # -> next free data/run_NNN
    python -m src.capture pcap/data1.pcapng --run run_009
    python -m src.capture pcap/data1.pcapng --rows 10    # print the first rows
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path

import pandas as pd

from src import runs, windows

ROOT = Path(__file__).resolve().parents[1]

# --------------------------------------------------------------------------
# The lab's asset inventory.
#
# This is the one piece of knowledge that cannot be measured from the packets
# and has to be written down by hand - which is exactly the situation every
# real security team is in, and why features.py is allowed to use it. It is
# not the answer sheet: it says which machines are ours, not which one is
# compromised.
#
# Every entry below was confirmed FROM THE CAPTURES, not assumed. The evidence
# is recorded next to each one so a wrong name is a checkable claim rather than
# a guess that quietly poisons every result downstream:
#
#   esp32-01  DHCP hostname "esp32-C3C010" in data1.pcapng; Espressif OUI.
#             Absent from baseline.pcapng - it was not powered on for that
#             recording. Still a real board, so it stays in the inventory.
#   esp32-02  MQTT topic "iot/esp32-02" on port 1883; Espressif OUI.
#   esp32-03  MQTT topic "iot/esp32-03" on port 1883; Espressif OUI.
#   broker    the endpoint every sensor opens 1883 to; ASUSTek OUI (it is the
#             laptop). Seen on .0.200 and on .137.1, its ICS hotspot address.
#   router    DHCP hostname "ArcherC6", TP-Link OUI, .0.254. Present in both
#             captures and the loudest talker in each.
# --------------------------------------------------------------------------
MAC_TO_NAME = {
    # ---- the lab's own devices: these are the suspects (see DEVICE_KINDS) --
    "1c:c3:ab:c3:c0:10": "esp32-01",   # 192.168.0.129
    "30:76:f5:e4:eb:60": "esp32-02",   # 192.168.0.160
    "30:76:f5:e5:e5:ac": "esp32-03",   # 192.168.0.203
    # "xx:xx:xx:xx:xx:xx": "plug",     # <- smart plug; decide which group first

    # ---- infrastructure: named, but never suspects (see INFRASTRUCTURE) ----
    "cc:28:aa:75:4e:bd": "broker",     # 192.168.0.200 / 192.168.137.1
    "c0:3a:55:43:f3:18": "router",     # 192.168.0.254, TP-Link Archer C6

    # ---- background: they show up in captures, but are never attackable ----
    "48:83:b4:19:b8:13": "phone",      # 192.168.0.177
    "2c:6d:c1:3e:7a:9c": "laptop-i3",  # 192.168.0.218
}

# A second way to recognise the fixed infrastructure. If one of these is ever
# reached through the router - or swapped for another machine on the same
# address - the MAC will not match but the address still identifies it.
#
# The router NEEDS its entry here, not just the MAC one. It appears both as a
# sender (its own MAC) and as a bare IP in flows that merely pass through it,
# and without this line one physical box shows up in the flow table as two
# separate identities: "c0:3a:55:43:f3:18" and "192.168.0.254".
IP_TO_NAME = {
    "192.168.0.200": "broker",
    "192.168.137.1": "broker",
    "192.168.0.254": "router",
    "192.168.0.177": "phone",
    "192.168.0.218": "laptop-i3",
}

# Named, but NOT suspects. The broker talks to everything by design, so
# attributing an incident to it would be attributing it to the message queue;
# the router carries every packet on the segment for the same structural
# reason. Naming them is still worth doing - it collapses each to one readable
# identity instead of a scatter of raw MACs and IPs - but they are excluded
# from the inventory, which is what makes them un-blameable.
#
# Exclusion is not a special case in the code. features.py builds rows only
# for names in device_names, and device_names is DEVICE_KINDS - so anything
# absent from DEVICE_KINDS can never be scored, ranked, or accused. This set
# exists to make that intent explicit and checkable rather than an accident of
# omission; the assertion below is what actually holds the line.
INFRASTRUCTURE = {"broker", "router"}

# Named, but not ours to blame: the household devices that share the air with
# the lab but are not part of the experiment - a phone, say. They appear in
# every capture, they are noisy, and they are never scored, ranked, attacked,
# or accused. They are the weather the experiment happens in.
#
# They are kept out of DEVICE_KINDS for exactly the reason the router is: a
# device that cannot be scored cannot be accused. Naming them is still worth
# doing, because an unnamed device fragments into a scatter of raw MACs and
# DHCP addresses, and "esp32-02 contacted 4 new outside addresses" reads very
# differently when three of them turn out to have been the same phone.
#
# NOTE - laptop-i3 used to live here. It has been promoted to a SCORED
# CANDIDATE (it is in DEVICE_KINDS below): a permanently-innocent, naturally
# loud device that the detector scores and attribution may rank or even blame,
# but that scenario.py must never actually attack. "Scored" and "attackable"
# are now two separate properties - see the note on DEVICE_KINDS.
#
# ON THE PHONE'S ADDRESS. It was first recorded here as 46:bf:ec:fd:f8:c6 on
# 192.168.0.106 - a RANDOMISED address, with the locally-administered bit set,
# which is what modern handsets use as a per-network private Wi-Fi address.
# Those rotate, so that entry was only ever good for the captures of the day.
# It has since been switched to present its real burned-in MAC, recorded above:
# 48:83:b4:19:b8:13 on 192.168.0.177, globally unique, and stable across
# networks and reboots.
#
# The episode is worth keeping in view rather than deleting, because the
# failure mode is silent: a rotated MAC does not error, it simply stops
# matching, and the phone quietly reappears as an unnamed stranger - which
# reads downstream as a lab device contacting a new outside address. If an
# unexplained device ever shows up in a capture, check this first.
BACKGROUND = {"phone"}

# Never a blamed origin, because never scored. features.py builds rows only for
# names in DEVICE_KINDS, so anything here is invisible to the detector and can
# never be ranked or accused. This is a WEAKER statement than "never attacked":
# laptop-i3 is scored and blamable yet must still never be attacked - that
# stronger, attack-side rule lives in scenario.ORIGINS, not here.
NEVER_ORIGIN = INFRASTRUCTURE | BACKGROUND

# The suspects - the devices the detector scores and attribution may rank.
# generate.py leaves infrastructure out of device_names for the same reason,
# and features.py only ever builds rows for names on this list.
#
# BEING SCORED IS NOT THE SAME AS BEING ATTACKABLE. Every ESP32 board is both:
# scored here, and triggerable through scenario.ORIGINS. laptop-i3 is scored
# but NOT in ORIGINS - a real, naturally-loud device that is permanently
# innocent. It is in the ranking on purpose: a noisy-but-benign candidate is
# the honest stress test for a method that must not just blame whoever is
# loudest. Its kind is "laptop", so nothing downstream mistakes it for a sensor.
DEVICE_KINDS = {
    "esp32-01": "sensor",
    "esp32-02": "sensor",
    "esp32-03": "sensor",
    "laptop-i3": "laptop",   # scored candidate, but NEVER an attack origin
    # "plug": "plug",                # <- ONLY if the plug can be an origin;
    #                                #    if it is background, add it to
    #                                #    BACKGROUND above instead.
}

# The two tables must not contradict each other. A name that is infrastructure
# AND a suspect would be scored and blamed despite the comment above saying it
# never could be, and the failure would be silent.
assert not (NEVER_ORIGIN & set(DEVICE_KINDS)), (
    "these names can never be an origin, yet are listed as suspects: %s"
    % sorted(NEVER_ORIGIN & set(DEVICE_KINDS))
)

# Every name that must never be blamed has to be RESOLVABLE, or the exclusion
# silently does nothing: an unmapped phone arrives as a raw MAC, which is not
# in NEVER_ORIGIN, and the protection never applies to it.
_unnamed = NEVER_ORIGIN - set(MAC_TO_NAME.values()) - set(IP_TO_NAME.values())
assert not _unnamed, (
    "these must never be an origin but no MAC or IP resolves to them: %s"
    % sorted(_unnamed)
)

# Addresses are matched lowercase-with-colons, because that is the shape tshark
# emits. A key written the way a router's admin page shows it - 46-BF-EC-FD-F8-C6
# - would simply never match, and the device would stay unnamed with no error.
for _mac in MAC_TO_NAME:
    assert _mac == _mac.lower().replace("-", ":"), (
        "MAC keys must be lowercase and colon-separated, not %r" % _mac
    )

# Every suspect needs a MAC, or it can never appear in a captured run at all -
# it would sit in the meta file as a device the detector silently never scores.
_unmapped = set(DEVICE_KINDS) - set(MAC_TO_NAME.values())
assert not _unmapped, (
    "these devices are in DEVICE_KINDS but no MAC resolves to them: %s"
    % sorted(_unmapped)
)

# Close a flow after this much silence. 60s matches the feature window, so a
# flow never silently straddles more windows than the thing measuring it.
IDLE_SECONDS = 60.0

# Frames sent to everybody. Named rather than left as raw addresses so a
# broadcast storm reads as one destination in the table instead of many.
BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"
BROADCAST_NAME = "broadcast"

# STEP 18, CHANGE C1 - multicast is "broadcast" too, also for IP packets.
#
# endpoint_name always MEANT to call multicast traffic "broadcast" (see its
# comment), but the check sat after "if ip: return ip", so it never fired for
# an IP packet. A Windows name lookup from laptop-i3 (LLMNR, UDP 5355 to
# 224.0.0.252 or ff02::1:3), an mDNS query (224.0.0.251) or an SSDP search
# (239.255.255.250) therefore arrived in the flow table as a raw address -
# and features.py counted each as a "new outside address" and as an extra
# destination. That is what flagged the innocent laptop in live_batch_05 and in
# rehearsal_01. With this switch ON, IPv4 multicast (224.0.0.0/4), IPv6
# multicast (ff00::/8) and the all-ones address 255.255.255.255 are named
# "broadcast", whatever the MAC says.
#
# A switch, not a silent edit, so the old rule can still be scored: set it to
# False (or run evaluate.py with --rules old) and conversion is exactly what it
# was before Step 18. The runs already saved in data/ were converted under the
# old rule; their meta files have no "multicast_as_broadcast" entry.
# Measured effect: docs/LIVE_PLAN.md section 7, "Step 18".
MULTICAST_AS_BROADCAST = True
ALL_ONES_IPV4 = "255.255.255.255"

# Exactly the columns generate.py writes, in exactly that order.
COLUMNS = ["conn_id", "t", "src", "dst", "dport", "bytes_out", "bytes_in", "pkts"]

# STEP 18b - one extra fact per flow: did its sender have no address yet?
#
# A device that is JOINING the network does not have an IP address yet, so its
# DHCP DISCOVER and REQUEST are sent from 0.0.0.0. That is exactly what
# esp32-02 did when it dropped off and came back in rehearsal_01 (+695 s).
# Windows also sends a DHCP broadcast now and then - an INFORM, "tell me the
# network settings" - but it sends it from the address it already has
# (laptop-i3: 192.168.0.218), because it is not joining anything. In the
# eight columns above the two look identical (dst "broadcast", dport 67), so
# Step 18's rejoin rule caught both. This column tells them apart:
#
#   src_unassigned   True if the flow's initiator sent at least one of its
#                    packets from 0.0.0.0 ("I have no address yet").
#
# It is an EXTRA column, after the eight, so nothing that reads the eight
# changes. Runs saved before Step 18b - and every simulated run - do not have
# it; detect.rejoin_minutes then finds no rejoin at all (the honest reading:
# the fact was never recorded). The message type itself (DISCOVER = 1,
# REQUEST = 3, INFORM = 8) is not needed: the source address already says
# whether the device had joined.
UNASSIGNED_IPV4 = "0.0.0.0"
SRC_UNASSIGNED = "src_unassigned"
FLOW_COLUMNS = COLUMNS + [SRC_UNASSIGNED]

# The fields pulled out of each packet. occurrence=f (first) matters: a frame
# with tunnelled or nested layers reports several ip.src values, and we want
# the outermost one rather than a tab-separated pair that parses as neither.
TSHARK_FIELDS = [
    "frame.time_epoch",
    "frame.len",
    "eth.src",
    "eth.dst",
    "ip.src",
    "ip.dst",
    "ipv6.src",
    "ipv6.dst",
    "ip.proto",
    "tcp.srcport",
    "tcp.dstport",
    "tcp.flags.syn",
    "tcp.flags.ack",
    "udp.srcport",
    "udp.dstport",
    "arp.opcode",
]


# --------------------------------------------------------------------------
# Finding and running tshark
# --------------------------------------------------------------------------

def find_tshark(explicit: str | None = None) -> str:
    """
    Locate tshark.

    Wireshark's Windows installer does not put tshark on PATH, so looking only
    there fails on the machine this was written on. Check PATH first anyway -
    if the user has arranged for a particular tshark, that is the one they
    mean - then the standard install locations.
    """
    if explicit:
        if not Path(explicit).exists():
            raise FileNotFoundError("no tshark at %s" % explicit)
        return explicit

    found = shutil.which("tshark")
    if found:
        return found

    candidates = [
        r"C:\Program Files\Wireshark\tshark.exe",
        r"C:\Program Files (x86)\Wireshark\tshark.exe",
        "/usr/bin/tshark",
        "/usr/local/bin/tshark",
        "/opt/homebrew/bin/tshark",
    ]
    for candidate in candidates:
        if Path(candidate).exists():
            return candidate

    raise FileNotFoundError(
        "tshark not found. It ships with Wireshark (https://www.wireshark.org).\n"
        "If it is installed somewhere unusual, pass --tshark PATH."
    )


def read_packets(pcap_path: Path, tshark: str) -> list[dict]:
    """
    One pass over the capture, one dict per packet.

    tshark is asked for tab-separated fields rather than JSON or XML because
    the capture can be large and this is the only output format that streams
    cheaply. Missing fields come back as empty strings, which the parsers
    below treat as "not applicable" rather than zero - a packet with no TCP
    layer has no port, and calling that port 0 would silently merge it with
    real traffic.
    """
    command = [tshark, "-r", str(pcap_path), "-T", "fields",
               "-E", "separator=/t", "-E", "occurrence=f"]
    for field in TSHARK_FIELDS:
        command += ["-e", field]

    result = subprocess.run(command, capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(
            "tshark failed reading %s:\n%s" % (pcap_path, result.stderr.strip())
        )

    packets = []
    for line in result.stdout.splitlines():
        if not line.strip():
            continue
        parts = line.split("\t")
        # Trailing empty fields can be dropped by tshark; pad rather than
        # index-error on a packet that simply had nothing in its last field.
        parts += [""] * (len(TSHARK_FIELDS) - len(parts))
        packets.append(dict(zip(TSHARK_FIELDS, parts)))
    return packets


# --------------------------------------------------------------------------
# Naming the two ends of a packet
# --------------------------------------------------------------------------

def _int_or_none(text):
    try:
        return int(text)
    except (TypeError, ValueError):
        return None


@lru_cache(maxsize=4096)
def is_group_address(ip: str) -> bool:
    """
    True for an address that means "everyone listening", not one machine:
    IPv4 multicast (224.0.0.0/4), IPv6 multicast (ff00::/8) and 255.255.255.255.
    Anything that does not parse as an IP address is not one. Cached, because
    a capture repeats the same few addresses thousands of times.
    """
    if not ip:
        return False
    if ip == ALL_ONES_IPV4:
        return True
    try:
        return ipaddress.ip_address(ip).is_multicast
    except ValueError:
        return False


def endpoint_name(mac: str, ip: str, multicast_as_broadcast: bool | None = None) -> str:
    """
    Who this address belongs to.

    MAC first, because that is the identity that survives a DHCP lease. Then
    the IP table, which covers the broker being reached some other way. Then
    the literal address, and only if there is not one, the literal MAC.

    Returning the raw address for strangers is the point, not a fallback:
    features.py counts destinations that are new AND not in the inventory, so
    an unknown address has to stay visibly unknown. A multicast address is not
    a stranger, though - it is "everyone on the segment" - so with the Step 18
    switch ON (MULTICAST_AS_BROADCAST, read at call time unless passed) it is
    named "broadcast" before the literal-address rule is reached.
    """
    if multicast_as_broadcast is None:
        multicast_as_broadcast = MULTICAST_AS_BROADCAST
    mac = (mac or "").lower()
    if mac in MAC_TO_NAME:
        return MAC_TO_NAME[mac]
    if mac == BROADCAST_MAC:
        return BROADCAST_NAME
    if ip and ip in IP_TO_NAME:
        return IP_TO_NAME[ip]
    if multicast_as_broadcast and is_group_address(ip):
        return BROADCAST_NAME
    if ip:
        return ip
    if mac.startswith(("01:00:5e", "33:33")):
        # IPv4 / IPv6 multicast, which is a broadcast for our purposes.
        return BROADCAST_NAME
    return mac or "unknown"


def packet_shape(packet: dict):
    """
    Reduce a packet to (proto, src_name, dst_name, src_port, dst_port, is_syn).

    Ports are None for anything that has none. Returns None for a packet with
    no ethernet layer at all, which should not happen on this network but is
    not worth crashing over.
    """
    eth_src = (packet["eth.src"] or "").lower()
    eth_dst = (packet["eth.dst"] or "").lower()
    if not eth_src:
        return None

    ip_src = packet["ip.src"] or packet["ipv6.src"] or ""
    ip_dst = packet["ip.dst"] or packet["ipv6.dst"] or ""

    src = endpoint_name(eth_src, ip_src)
    dst = endpoint_name(eth_dst, ip_dst)

    tcp_sport = _int_or_none(packet["tcp.srcport"])
    udp_sport = _int_or_none(packet["udp.srcport"])

    if tcp_sport is not None:
        # A connection request: SYN set, ACK clear. tshark reports these as
        # "1"/"0" or "True"/"False" depending on version, so test loosely.
        syn = str(packet["tcp.flags.syn"]).strip() in ("1", "True")
        ack = str(packet["tcp.flags.ack"]).strip() in ("1", "True")
        return ("tcp", src, dst, tcp_sport,
                _int_or_none(packet["tcp.dstport"]), syn and not ack)

    if udp_sport is not None:
        return "udp", src, dst, udp_sport, _int_or_none(packet["udp.dstport"]), False

    if packet["arp.opcode"]:
        return "arp", src, dst, None, None, False

    proto_number = _int_or_none(packet["ip.proto"])
    if proto_number is not None:
        return "ip%d" % proto_number, src, dst, None, None, False

    return "l2", src, dst, None, None, False


def addresses_from_packets(packets, known: dict | None = None) -> dict:
    """
    name -> the last IPv4 address each named device sent from, for the
    incident report's "block this device" line (Step 19). Read from the
    packets because the flow table keys devices by MAC and keeps no IP - on
    purpose (see the module docstring). 0.0.0.0 (a device that has no
    address yet) is skipped. Pass known to continue an earlier result.
    """
    found = dict(known or {})
    for packet in packets:
        name = MAC_TO_NAME.get((packet.get("eth.src") or "").lower())
        ip = packet.get("ip.src") or ""
        if name and ip and ip != UNASSIGNED_IPV4:
            found[name] = ip
    return found


# --------------------------------------------------------------------------
# Packets -> flows
# --------------------------------------------------------------------------

class _Flow:
    """One conversation being accumulated. Not exported; see build_flows."""

    __slots__ = ("t", "src", "dst", "dport", "bytes_out", "bytes_in", "pkts", "last",
                 "src_unassigned")

    def __init__(self, t, src, dst, dport):
        self.t = t
        self.src = src          # whoever spoke first: the initiator
        self.dst = dst
        self.dport = dport
        self.bytes_out = 0      # initiator -> responder
        self.bytes_in = 0       # responder -> initiator
        self.pkts = 0
        self.last = t
        self.src_unassigned = False   # Step 18b: initiator spoke from 0.0.0.0

    def add(self, t, length, from_initiator, unassigned=False):
        if from_initiator:
            self.bytes_out += length
            if unassigned:
                self.src_unassigned = True
        else:
            self.bytes_in += length
        self.pkts += 1
        self.last = t

    def row(self):
        return {
            "t": self.t,
            "src": self.src,
            "dst": self.dst,
            "dport": self.dport,
            "bytes_out": self.bytes_out,
            "bytes_in": self.bytes_in,
            "pkts": self.pkts,
            SRC_UNASSIGNED: self.src_unassigned,
        }


def build_flows(packets: list[dict], idle_seconds: float = IDLE_SECONDS) -> pd.DataFrame:
    """
    Group packets into flows and return the table, times relative to t=0.
    The eight COLUMNS, then src_unassigned (Step 18b, see FLOW_COLUMNS).

    Kept as a plain function taking plain dicts - no files, no tshark - so it
    can be tested with a handful of hand-written packets, the same way
    features.build_features can.

    The flow key is deliberately direction-free: a packet from the broker back
    to esp32-01 must land in the same row as the request it answers, or every
    conversation would be split into two half-duplex rows and bytes_in would
    be zero everywhere.
    """
    if not packets:
        return pd.DataFrame(columns=FLOW_COLUMNS)

    start = None
    open_flows = {}
    done = []

    for packet in packets:
        try:
            when = float(packet["frame.time_epoch"])
        except (TypeError, ValueError):
            continue
        if start is None:
            start = when
        t = when - start

        shape = packet_shape(packet)
        if shape is None:
            continue
        proto, src, dst, sport, dport, is_syn = shape
        length = _int_or_none(packet["frame.len"]) or 0

        # Order-independent key, so both directions hash to the same flow.
        ends = sorted([(src, sport), (dst, dport)], key=lambda e: (e[0], e[1] or -1))
        key = (proto, ends[0], ends[1])

        flow = open_flows.get(key)

        # Two reasons to start a new row rather than extend the old one: the
        # conversation went quiet long enough to count as over, or TCP said
        # so explicitly with a fresh SYN.
        if flow is not None and (t - flow.last > idle_seconds or is_syn):
            done.append(flow)
            flow = None

        if flow is None:
            # First packet seen decides who the initiator is - which is right
            # for TCP (the SYN sender) and the only available answer for UDP.
            flow = _Flow(t, src, dst, dport if dport is not None else 0)
            open_flows[key] = flow

        flow.add(t, length, from_initiator=(src == flow.src),
                 unassigned=(packet.get("ip.src") == UNASSIGNED_IPV4))

    done.extend(open_flows.values())

    frame = pd.DataFrame([f.row() for f in done])
    frame = frame.sort_values("t", kind="stable").reset_index(drop=True)

    # Identical shape and dtypes to generate.py, so anything reading a
    # captured run cannot tell it apart from a simulated one.
    frame.insert(0, "conn_id", ["C%06d" % i for i in range(len(frame))])
    frame["bytes_out"] = frame["bytes_out"].astype("int64")
    frame["bytes_in"] = frame["bytes_in"].astype("int64")
    frame["pkts"] = frame["pkts"].astype("int32")
    frame["dport"] = frame["dport"].astype("int32")
    frame[SRC_UNASSIGNED] = frame[SRC_UNASSIGNED].astype(bool)
    return frame[FLOW_COLUMNS]


# --------------------------------------------------------------------------
# Saving, in the shape src/runs.py expects
# --------------------------------------------------------------------------

def next_free_run_id(data_dir: Path = runs.DATA_DIR) -> str:
    """
    The first run_NNN not already on disk.

    Overwriting is never the default. data/ holds the simulated runs the
    reported numbers came from; quietly replacing run_003 with a capture would
    change results/table1.csv the next time evaluation ran and leave nothing
    to explain why.
    """
    used = {p.stem for p in Path(data_dir).glob("run_*.parquet")}
    n = 0
    while ("run_%03d" % n) in used:
        n += 1
    return "run_%03d" % n


def save_run(frame: pd.DataFrame, run_id: str, pcap_path: Path,
             baseline_seconds=None,
             window_seconds: int = windows.WINDOW_SECONDS,
             data_dir: Path = runs.DATA_DIR,
             force: bool = False):
    """
    Write data/<run_id>.parquet and the matching .meta.json.

    Both files, always. runs.load_run needs the pair, and a parquet without
    its inventory is a table nothing in this project can open.
    """
    data_dir = Path(data_dir)
    data_dir.mkdir(parents=True, exist_ok=True)
    parquet_file = runs.data_path(run_id, data_dir)
    meta_file = runs.meta_path(run_id, data_dir)

    if not force:
        for existing in (parquet_file, meta_file):
            if existing.exists():
                raise FileExistsError(
                    "%s already exists. Captured runs share the data/ folder with\n"
                    "  the simulated ones, so this refuses to overwrite. Pick another\n"
                    "  --run id, or pass --force if replacing it is what you meant."
                    % existing
                )

    capture_seconds = float(frame["t"].max()) if len(frame) else 0.0
    if baseline_seconds is None:
        # Half the capture, rounded down to whole windows, but never zero -
        # with no baseline there is nothing to call normal and the detector
        # has no reference to compare against.
        whole_windows = int(capture_seconds // window_seconds)
        baseline_seconds = max(1, whole_windows // 2) * window_seconds

    meta = {
        "run_id": run_id,
        "scenario": "capture",
        "source_pcap": str(pcap_path),
        "devices": [{"name": n, "kind": k} for n, k in DEVICE_KINDS.items()],
        "device_names": list(DEVICE_KINDS),
        "window_seconds": int(window_seconds),
        "capture_seconds": int(round(capture_seconds)),
        "baseline_seconds": int(baseline_seconds),
        "baseline_windows": windows.baseline_window_count(baseline_seconds, window_seconds),
        "n_connections": int(len(frame)),
        # Which naming rule built this table (Step 18, C1). Runs saved before
        # Step 18 have no such entry: they were all converted with the old rule.
        "multicast_as_broadcast": bool(MULTICAST_AS_BROADCAST),
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }

    frame.to_parquet(parquet_file, index=False)
    meta_file.write_text(json.dumps(meta, indent=2), encoding="utf-8")
    return parquet_file, meta_file, meta


def capture_to_run(pcap_path, run_id=None, tshark=None,
                   idle_seconds: float = IDLE_SECONDS,
                   baseline_seconds=None,
                   window_seconds: int = windows.WINDOW_SECONDS,
                   data_dir: Path = runs.DATA_DIR,
                   force: bool = False):
    """The whole job: pcap in, saved run out."""
    pcap_path = Path(pcap_path)
    if not pcap_path.exists():
        raise FileNotFoundError("no capture file at %s" % pcap_path)

    binary = find_tshark(tshark)
    packets = read_packets(pcap_path, binary)
    frame = build_flows(packets, idle_seconds=idle_seconds)
    if run_id is None:
        run_id = next_free_run_id(data_dir)
    parquet_file, meta_file, meta = save_run(
        frame, run_id, pcap_path,
        baseline_seconds=baseline_seconds, window_seconds=window_seconds,
        data_dir=data_dir, force=force,
    )
    return frame, parquet_file, meta_file, meta, len(packets)


# --------------------------------------------------------------------------
# Command line
# --------------------------------------------------------------------------

def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Turn a .pcapng capture into a flow table the pipeline can read."
    )
    parser.add_argument("pcap", help="the capture file, e.g. pcap/data1.pcapng")
    parser.add_argument("--run", default=None,
                        help="run id to save as (default: the next free run_NNN)")
    parser.add_argument("--tshark", default=None,
                        help="path to tshark, if it is not found automatically")
    parser.add_argument("--idle", type=float, default=IDLE_SECONDS,
                        help="seconds of silence that end a flow (default %d)" % IDLE_SECONDS)
    parser.add_argument("--window", type=int, default=windows.WINDOW_SECONDS,
                        help="feature window width in seconds (default %d)" % windows.WINDOW_SECONDS)
    parser.add_argument("--baseline", type=float, default=None,
                        help="baseline length in seconds (default: half the capture)")
    parser.add_argument("--rows", type=int, default=10, help="how many rows to print")
    parser.add_argument("--force", action="store_true",
                        help="allow overwriting an existing run")
    args = parser.parse_args(argv)

    try:
        frame, parquet_file, meta_file, meta, n_packets = capture_to_run(
            Path(args.pcap), run_id=args.run, tshark=args.tshark,
            idle_seconds=args.idle, baseline_seconds=args.baseline,
            window_seconds=args.window, force=args.force,
        )
    except (FileNotFoundError, FileExistsError, RuntimeError) as exc:
        print("\n  %s\n" % exc, file=sys.stderr)
        return 1

    n_windows = -(-meta["capture_seconds"] // meta["window_seconds"])
    print("\n  %s  ->  %s" % (args.pcap, meta["run_id"]))
    print("  %d packets  ->  %d flows over %ds (%d windows, baseline = first %d)"
          % (n_packets, len(frame), meta["capture_seconds"],
             n_windows, meta["baseline_windows"]))
    print("  devices: %s" % ", ".join(meta["device_names"]))
    print("  wrote %s" % parquet_file)
    print("        %s" % meta_file)

    if args.rows > 0:
        print("\n  first %d rows" % min(args.rows, len(frame)))
        print("  " + "-" * 88)
        print("  %-9s %9s  %-14s %-18s %6s %10s %10s %6s"
              % ("conn_id", "t", "src", "dst", "dport", "bytes_out", "bytes_in", "pkts"))
        for _, r in frame.head(args.rows).iterrows():
            print("  %-9s %9.3f  %-14s %-18s %6d %10d %10d %6d"
                  % (r["conn_id"], r["t"], r["src"], r["dst"],
                     r["dport"], r["bytes_out"], r["bytes_in"], r["pkts"]))
    print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
