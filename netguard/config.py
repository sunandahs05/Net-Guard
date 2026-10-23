"""
Central settings for NetGuard.

All detection thresholds live here so you can tune the system in ONE place
without touching the detection code.
"""
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DB_PATH = BASE_DIR / "netguard.db"      # SQLite file (created automatically)
DATA_DIR = BASE_DIR / "data"            # put CIC-IDS2017 CSV files here
SAMPLE_CSV = DATA_DIR / "sample_flows.csv"

# ---------------------------------------------------------------------------
# Rules for LIVE packets / PCAP files (packet-by-packet detector)
# Every rule looks at a sliding time window of the most recent packets.
# ---------------------------------------------------------------------------
PACKET_RULES = {
    "window_seconds": 10,      # how far back we look
    "port_scan_ports": 15,     # distinct (host, port) targets probed by ONE source
    "syn_flood_count": 100,    # SYN-only packets aimed at ONE host:port
    "icmp_flood_count": 50,    # ICMP echo requests sent by ONE source
    "max_connections": 120,    # SYN-only packets from ONE source (any targets)
    "alert_cooldown": 30,      # seconds before the same alert is raised again
}

# ---------------------------------------------------------------------------
# Rules for OFFLINE flow datasets such as CIC-IDS2017 (flow-by-flow detector)
# ---------------------------------------------------------------------------
FLOW_RULES = {
    "window_seconds": 60,      # flows are grouped into time buckets of this size
    "port_scan_ports": 15,     # distinct destination ports tried by ONE source
    "syn_flood_count": 100,    # half-open flows (SYN, no reply) to ONE destination
    "icmp_flood_count": 100,   # ICMP flows from ONE source
    "max_connections": 300,    # total flows opened by ONE source
}

SEVERITY = {
    "Port Scan": "Medium",
    "SYN Flood": "High",
    "ICMP Flood": "High",
    "Excessive Connections": "Medium",
}
