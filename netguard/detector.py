"""
Rule-based detection logic.

Two detectors are provided:

PacketDetector  - for live capture and .pcap files. Looks at ONE packet at a
                  time and keeps a sliding window of recent activity.
FlowDetector    - for flow datasets (CSV files such as CIC-IDS2017). Looks at a
                  whole table (a pandas DataFrame) at once.

Both detect the same four threats:
    Port Scan, SYN Flood, ICMP Flood, Excessive Connections
"""
from collections import Counter, defaultdict, deque
from datetime import datetime

import pandas as pd

from .config import FLOW_RULES, PACKET_RULES, SEVERITY

PORT_SCAN = "Port Scan"
SYN_FLOOD = "SYN Flood"
ICMP_FLOOD = "ICMP Flood"
EXCESSIVE = "Excessive Connections"


def _fmt(ts):
    """Turn a Unix timestamp (seconds) into 'YYYY-MM-DD HH:MM:SS'."""
    return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")


# =============================================================================
# 1. PACKET DETECTOR  (live traffic / pcap)
# =============================================================================
class PacketDetector:
    """
    Feed packets in with process(packet). A packet is a plain dictionary:

        {"ts": 1700000000.0, "src": "10.0.0.5", "dst": "10.0.0.9",
         "proto": "TCP", "sport": 4444, "dport": 80, "flags": "S",
         "icmp_type": None, "length": 60}

    process() returns a list of alerts (usually empty).
    """

    def __init__(self, rules=None):
        self.rules = dict(PACKET_RULES)
        if rules:
            self.rules.update(rules)
        # Each dictionary maps a key -> deque of (timestamp, ...) tuples.
        self._scan = defaultdict(deque)   # key: source IP
        self._syn = defaultdict(deque)    # key: (dst IP, dst port)
        self._icmp = defaultdict(deque)   # key: source IP
        self._conn = defaultdict(deque)   # key: source IP
        self._last_alert = {}             # (type, key) -> time of last alert
        self._src_last_alert = {}         # source IP -> time of last alert
        self._last_cleanup = 0.0

    # ----- helpers ---------------------------------------------------------
    def _trim(self, dq, now):
        """Remove entries older than the window from the left of the deque."""
        limit = now - self.rules["window_seconds"]
        while dq and dq[0][0] < limit:
            dq.popleft()

    def _cooldown_ok(self, key, now):
        """Return True if enough time has passed since the same alert fired."""
        last = self._last_alert.get(key)
        if last is not None and now - last < self.rules["alert_cooldown"]:
            return False
        self._last_alert[key] = now
        return True

    def _alert(self, kind, now, src, dst, details):
        return {
            "timestamp": _fmt(now),
            "alert_type": kind,
            "severity": SEVERITY[kind],
            "src_ip": src,
            "dst_ip": dst,
            "details": details,
        }

    def _cleanup(self, now):
        """Every minute, delete empty windows so memory does not grow forever."""
        if now - self._last_cleanup < 60:
            return
        self._last_cleanup = now
        for table in (self._scan, self._syn, self._icmp, self._conn):
            for key in list(table.keys()):
                self._trim(table[key], now)
                if not table[key]:
                    del table[key]
        horizon = now - 2 * self.rules["alert_cooldown"]
        self._last_alert = {k: v for k, v in self._last_alert.items() if v >= horizon}
        self._src_last_alert = {k: v for k, v in self._src_last_alert.items() if v >= horizon}

    # ----- the four rules --------------------------------------------------
    def _check_port_scan(self, now, src, dst, dport):
        dq = self._scan[src]
        dq.append((now, dst, dport))
        self._trim(dq, now)
        if len(dq) < self.rules["port_scan_ports"]:
            return None
        targets = {(d, p) for _, d, p in dq}
        if len(targets) >= self.rules["port_scan_ports"] and self._cooldown_ok((PORT_SCAN, src), now):
            hosts = {d for d, _ in targets}
            self._src_last_alert[src] = now
            shown = dst if len(hosts) == 1 else f"{len(hosts)} hosts"
            return self._alert(
                PORT_SCAN, now, src, shown,
                f"{len(targets)} different ports probed in {self.rules['window_seconds']}s")
        return None

    def _check_syn_flood(self, now, src, dst, dport):
        key = (dst, dport)
        dq = self._syn[key]
        dq.append((now, src))
        self._trim(dq, now)
        if len(dq) >= self.rules["syn_flood_count"] and self._cooldown_ok((SYN_FLOOD, key), now):
            sources = Counter(s for _, s in dq)
            for s in sources:
                self._src_last_alert[s] = now
            shown_src = next(iter(sources)) if len(sources) == 1 else f"{len(sources)} sources"
            return self._alert(
                SYN_FLOOD, now, shown_src, f"{dst}:{dport}",
                f"{len(dq)} SYN packets (no handshake) in {self.rules['window_seconds']}s")
        return None

    def _check_icmp_flood(self, now, src, dst):
        dq = self._icmp[src]
        dq.append((now, dst))
        self._trim(dq, now)
        if len(dq) >= self.rules["icmp_flood_count"] and self._cooldown_ok((ICMP_FLOOD, src), now):
            self._src_last_alert[src] = now
            return self._alert(
                ICMP_FLOOD, now, src, dst,
                f"{len(dq)} ICMP echo requests in {self.rules['window_seconds']}s")
        return None

    def _check_excessive(self, now, src, dst):
        dq = self._conn[src]
        dq.append((now, dst))
        self._trim(dq, now)
        # If this source was just reported as a scanner/flooder, do not also
        # report it as "excessive connections" - that would be a duplicate.
        recent = now - self._src_last_alert.get(src, float("-inf")) < self.rules["alert_cooldown"]
        if recent:
            return None
        if len(dq) >= self.rules["max_connections"] and self._cooldown_ok((EXCESSIVE, src), now):
            self._src_last_alert[src] = now
            return self._alert(
                EXCESSIVE, now, src, f"{len({d for _, d in dq})} hosts",
                f"{len(dq)} connection attempts in {self.rules['window_seconds']}s")
        return None

    # ----- public entry point ---------------------------------------------
    def process(self, pkt):
        now = pkt["ts"]
        src, dst = pkt["src"], pkt["dst"]
        alerts = []

        if pkt.get("proto") == "TCP":
            flags = pkt.get("flags") or ""
            # "SYN-only" = a brand-new connection attempt (SYN set, ACK not set)
            if "S" in flags and "A" not in flags:
                dport = pkt.get("dport")
                for found in (
                    self._check_port_scan(now, src, dst, dport),
                    self._check_syn_flood(now, src, dst, dport),
                    self._check_excessive(now, src, dst),
                ):
                    if found:
                        alerts.append(found)
        elif pkt.get("proto") == "ICMP" and pkt.get("icmp_type") == 8:  # 8 = echo request
            found = self._check_icmp_flood(now, src, dst)
            if found:
                alerts.append(found)

        self._cleanup(now)
        return alerts


# =============================================================================
# 2. FLOW DETECTOR  (CSV datasets such as CIC-IDS2017)
# =============================================================================
def _num(df, name, default=0):
    """Get a numeric column, or a column of defaults if it does not exist."""
    if name in df.columns:
        return pd.to_numeric(df[name], errors="coerce").fillna(default)
    return pd.Series(default, index=df.index, dtype="float64")


def _parse_time(series):
    """Parse timestamps. CIC-IDS2017 uses day-first dates with mixed formats."""
    try:
        return pd.to_datetime(series, errors="coerce", dayfirst=True, format="mixed")
    except (TypeError, ValueError):       # older pandas without format="mixed"
        return pd.to_datetime(series, errors="coerce", dayfirst=True)


class FlowDetector:
    """
    analyze(df) adds two columns to a copy of the data:
        predicted : True if any rule flagged the flow
        rule      : name of the rule that flagged it ('' if none)

    If the CSV has 'Source IP' and 'Timestamp' columns (the
    "GeneratedLabelledFlows" version of CIC-IDS2017) we group flows per source
    per time window. If not (the "MachineLearningCVE" version has no IPs) we
    fall back to simpler per-flow rules.
    """

    def __init__(self, rules=None):
        self.rules = dict(FLOW_RULES)
        if rules:
            self.rules.update(rules)

    def analyze(self, df):
        df = df.copy()
        df.columns = [str(c).strip() for c in df.columns]
        r = self.rules

        syn = _num(df, "SYN Flag Count")
        fwd = _num(df, "Total Fwd Packets")
        bwd = _num(df, "Total Backward Packets")
        proto = _num(df, "Protocol", -1)
        pps = _num(df, "Flow Packets/s")
        half_open = (syn > 0) & (bwd == 0)      # SYN sent, nothing came back
        is_icmp = proto == 1

        if "Source IP" in df.columns and "Timestamp" in df.columns:
            win = int(r["window_seconds"])
            ts = _parse_time(df["Timestamp"])
            bucket = ts.dt.floor(f"{win}s").fillna(pd.Timestamp("1970-01-01"))
            src = df["Source IP"].astype(str)
            dst = df["Destination IP"].astype(str) if "Destination IP" in df.columns \
                else pd.Series("?", index=df.index)
            dport = _num(df, "Destination Port", -1)

            ports_per_src = dport.groupby([src, bucket]).transform("nunique")
            half_per_dst = half_open.astype(int).groupby([dst, bucket]).transform("sum")
            icmp_per_src = is_icmp.astype(int).groupby([src, bucket]).transform("sum")
            flows_per_src = pd.Series(1, index=df.index).groupby([src, bucket]).transform("sum")

            m_scan = ports_per_src >= r["port_scan_ports"]
            m_icmp = is_icmp & (icmp_per_src >= r["icmp_flood_count"])
            m_syn = half_open & (half_per_dst >= r["syn_flood_count"])
            m_conn = flows_per_src >= r["max_connections"]
        else:
            # Fallback rules (no IP addresses available in this CSV)
            m_scan = (syn > 0) & (fwd <= 2) & (bwd <= 1)
            m_icmp = is_icmp & (pps >= 1000)
            m_syn = half_open & (pps >= 5000)
            m_conn = pd.Series(False, index=df.index)

        df["rule"] = ""
        # Written in reverse so the FIRST rule in this list wins when several match.
        for name, mask in reversed([
            (PORT_SCAN, m_scan), (ICMP_FLOOD, m_icmp),
            (SYN_FLOOD, m_syn), (EXCESSIVE, m_conn),
        ]):
            df.loc[mask, "rule"] = name
        df["predicted"] = df["rule"] != ""
        return df

    @staticmethod
    def to_alerts(analyzed):
        """Summarise flagged flows into alerts: one per (rule, source IP)."""
        flagged = analyzed[analyzed["predicted"]]
        if flagged.empty:
            return []
        has_src = "Source IP" in flagged.columns
        has_dst = "Destination IP" in flagged.columns
        has_ts = "Timestamp" in flagged.columns
        times = _parse_time(flagged["Timestamp"]) if has_ts else None
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        alerts = []
        keys = ["rule", "Source IP"] if has_src else ["rule"]
        for key, grp in flagged.groupby(keys):
            rule = key[0] if isinstance(key, tuple) else key
            src = key[1] if has_src else "N/A"
            dst = f"{grp['Destination IP'].nunique()} host(s)" if has_dst else "N/A"
            when = now_str
            if has_ts:
                first = times.loc[grp.index].min()
                if pd.notna(first):
                    when = first.strftime("%Y-%m-%d %H:%M:%S")
            alerts.append({
                "timestamp": when, "alert_type": rule, "severity": SEVERITY[rule],
                "src_ip": src, "dst_ip": dst,
                "details": f"{len(grp)} flows flagged by the {rule} rule",
                "mode": "offline",
            })
        return alerts
