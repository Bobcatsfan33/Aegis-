"""
DNS Monitor — tunneling detection and anomaly-based traffic profiling.

Detection methods:
  1. High-entropy subdomain labels (characteristic of DNS tunneling, data exfiltration)
  2. Excessive query rate to single domain (DGA, C&C beaconing)
  3. Unusually long subdomain labels (> 50 chars — typical of encoded payloads)
  4. TXT record abuse (high-volume TXT queries to same domain)
  5. DGA (Domain Generation Algorithm) candidate detection via entropy and bigram analysis

Two modes:
  1. scapy mode (preferred): Captures live DNS traffic on port 53 for a configurable window.
  2. fallback mode: Reads from a DNS log file (JSON or flat-text format) if scapy unavailable.

Configuration via config dict:
  - capture_interface: Network interface for packet capture (default: "eth0")
  - capture_window_seconds: Duration of packet capture (default: 60)
  - dns_log_path: Path to DNS log file for fallback mode
  - blocklist_path: Path to file with one blocked domain per line (optional)
  - baseline_db_path: SQLite database path for persistent baseline (optional; default: in-memory)
  - entropy_threshold: Shannon entropy threshold for tunneling detection (default: 3.5)
  - entropy_label_min_length: Minimum label length to consider for entropy (default: 10)
  - max_label_length: Threshold for "unusually long" labels (default: 50)
  - query_rate_threshold: Max queries per minute for single domain/host pair (default: 100)
  - txt_query_threshold: Max TXT queries per minute to single domain (default: 50)

Install scapy (optional):
  pip install scapy

Set DNS_LOG_PATH in .env for fallback mode (if scapy unavailable).
"""

import json
import logging
import math
import re
import sqlite3
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from modules.scanners.base import BaseScanner, Finding

logger = logging.getLogger(__name__)

try:
    from scapy.all import IP, UDP, DNS, DNSQR, sniff
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


# ────────────────────────────────────────────────────────────────────────────
# Data Classes
# ────────────────────────────────────────────────────────────────────────────

@dataclass
class DnsQuery:
    """
    A single DNS query captured from network traffic or logs.

    Attributes:
        timestamp: When the query was made (UTC)
        source_ip: IP address that issued the query
        query_name: FQDN being queried (e.g., "example.com", "subdomain.example.com")
        query_type: DNS record type (A, AAAA, CNAME, MX, TXT, etc.)
        response_code: Response code (NOERROR, NXDOMAIN, SERVFAIL, etc.)
        response_ips: List of resolved IP addresses (if any)
        ttl: Time-to-live from response (optional)
    """
    timestamp: datetime
    source_ip: str
    query_name: str
    query_type: str
    response_code: str
    response_ips: List[str] = field(default_factory=list)
    ttl: Optional[int] = None


# ────────────────────────────────────────────────────────────────────────────
# Utility Functions
# ────────────────────────────────────────────────────────────────────────────

def shannon_entropy(s: str) -> float:
    """
    Calculate Shannon entropy of a string.

    High entropy (> 3.5) suggests random or encoded data.
    Low entropy (< 2.0) suggests natural language or common patterns.

    Args:
        s: String to analyze

    Returns:
        Shannon entropy value (0.0 to ~5.2 for ASCII)
    """
    if not s:
        return 0.0

    freq = {}
    for char in s.lower():
        freq[char] = freq.get(char, 0) + 1

    entropy = 0.0
    length = len(s)
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)

    return entropy


def extract_subdomain_labels(fqdn: str) -> List[str]:
    """
    Extract all subdomain labels from an FQDN, excluding the TLD and SLD.

    Examples:
        "example.com" → []
        "www.example.com" → ["www"]
        "api.v1.internal.example.com" → ["api", "v1", "internal"]

    Args:
        fqdn: Fully qualified domain name

    Returns:
        List of subdomain labels (may be empty)
    """
    labels = fqdn.lower().rstrip(".").split(".")
    if len(labels) <= 2:
        return []
    return labels[:-2]


def is_dga_candidate(domain: str) -> Tuple[bool, float]:
    """
    Heuristic detection of Domain Generation Algorithm (DGA) candidates.

    DGA domains typically exhibit:
      - High consonant clustering (bqkxz together)
      - Unusual bigram frequencies
      - Entropy > 3.0 in subdomain labels
      - Avoiding common English words

    Args:
        domain: Domain name to analyze

    Returns:
        (is_candidate: bool, confidence: float 0.0-1.0)
    """
    labels = extract_subdomain_labels(domain)
    if not labels:
        labels = domain.lower().rstrip(".").split(".")

    # Weighted scoring
    score = 0.0

    for label in labels:
        if len(label) < 6:
            continue

        # Check entropy
        label_entropy = shannon_entropy(label)
        if label_entropy > 3.0:
            score += 0.3

        # Detect consonant clusters (common in DGA)
        consonant_pairs = len(re.findall(r"[bcdfghjklmnpqrstvwxyz]{2,}", label))
        if consonant_pairs > 1:
            score += 0.2

        # Detect unusual bigram frequencies (chi-squared on English)
        # Simplified: look for repeated bigrams (suggests DGA generator output)
        bigrams = [label[i:i+2] for i in range(len(label) - 1)]
        if len(bigrams) > 0:
            unique_bigrams = len(set(bigrams))
            bigram_entropy = shannon_entropy("".join(bigrams))
            if unique_bigrams > len(bigrams) * 0.7 and bigram_entropy > 2.5:
                score += 0.2

    # Normalize to 0-1
    confidence = min(score, 1.0)
    return confidence > 0.4, confidence


# ────────────────────────────────────────────────────────────────────────────
# Baseline Management
# ────────────────────────────────────────────────────────────────────────────

class DnsBaseline:
    """
    Maintains per-host DNS statistics for anomaly detection.

    Tracks rolling averages over configurable windows (default 1 hour),
    with optional SQLite persistence for long-term baselines.
    """

    def __init__(self, db_path: Optional[str] = None, window_minutes: int = 60):
        """
        Initialize baseline tracker.

        Args:
            db_path: Path to SQLite database for persistent storage (None = in-memory only)
            window_minutes: Rolling window size for statistics (default: 60 minutes)
        """
        self.db_path = db_path
        self.window_minutes = window_minutes

        # In-memory rolling statistics keyed by source_ip
        self.query_history: Dict[str, deque] = defaultdict(
            lambda: deque(maxlen=10000)  # Ring buffer for queries
        )
        self.domain_history: Dict[str, set] = defaultdict(set)
        self.tld_frequency: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))
        self.query_type_freq: Dict[str, Dict[str, int]] = defaultdict(
            lambda: defaultdict(int)
        )
        self.peak_hour: Dict[str, int] = defaultdict(lambda: 0)

        # Initialize SQLite if requested
        self.conn: Optional[sqlite3.Connection] = None
        if db_path:
            self._init_db()

    def _init_db(self) -> None:
        """Initialize SQLite schema if db_path is provided."""
        try:
            self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
            self.conn.execute("""
                CREATE TABLE IF NOT EXISTS dns_baseline (
                    source_ip TEXT PRIMARY KEY,
                    query_volume_per_hour REAL,
                    unique_domains_per_hour INTEGER,
                    avg_subdomain_entropy REAL,
                    tld_distribution TEXT,
                    query_type_distribution TEXT,
                    peak_hour INTEGER,
                    last_updated TIMESTAMP
                )
            """)
            self.conn.commit()
            logger.info(f"Initialized DNS baseline database at {self.db_path}")
        except Exception as e:
            logger.warning(f"Failed to initialize baseline DB: {e}; using in-memory only")
            self.conn = None

    def update(self, query: DnsQuery) -> None:
        """
        Update baseline statistics with a new DNS query.

        Args:
            query: DnsQuery to record
        """
        src = query.source_ip
        now = query.timestamp

        # Record query in rolling history
        self.query_history[src].append(now)

        # Track unique domains
        self.domain_history[src].add(query.query_name)

        # Update TLD frequency
        tld = self._extract_tld(query.query_name)
        self.tld_frequency[src][tld] += 1

        # Update query type frequency
        self.query_type_freq[src][query.query_type] += 1

        # Update peak hour
        self.peak_hour[src] = now.hour

    def is_anomalous(self, query: DnsQuery) -> Tuple[bool, str]:
        """
        Check if a DNS query deviates significantly from baseline.

        Returns:
            (is_anomalous: bool, reason: str) — reason is empty if not anomalous
        """
        src = query.source_ip
        now = query.timestamp

        # Not enough baseline data yet
        if len(self.query_history[src]) < 10:
            return False, ""

        # Calculate query rate over last hour
        cutoff = now - timedelta(minutes=self.window_minutes)
        recent_queries = [
            q for q in self.query_history[src]
            if q > cutoff
        ]

        baseline_rate = len(recent_queries) / self.window_minutes
        max_expected_rate = baseline_rate * 2.0  # 2x baseline = anomalous

        # Check current query rate (simplified: assume last query is the test)
        last_minute = now - timedelta(minutes=1)
        last_min_count = len([q for q in recent_queries if q > last_minute])

        if last_min_count > max_expected_rate:
            return True, f"Query rate anomaly: {last_min_count} q/min (baseline: {baseline_rate:.1f})"

        # Check for unusual domain (not seen before)
        unique_domains = len(self.domain_history[src])
        if unique_domains > 0 and query.query_name not in self.domain_history[src]:
            # Allow some growth; flag if > 10% new domains
            if unique_domains > 100:
                return True, f"New domain observed (total unique: {unique_domains})"

        return False, ""

    @staticmethod
    def _extract_tld(fqdn: str) -> str:
        """Extract TLD from FQDN."""
        parts = fqdn.lower().rstrip(".").split(".")
        return parts[-1] if parts else "unknown"


# ────────────────────────────────────────────────────────────────────────────
# DNS Tunneling Detection
# ────────────────────────────────────────────────────────────────────────────

class DnsTunnelingDetector:
    """
    Multi-method detector for DNS tunneling and data exfiltration attempts.

    Each detection method returns a confidence score; the detector combines
    scores for an overall tunneling probability.
    """

    def __init__(
        self,
        entropy_threshold: float = 3.5,
        entropy_label_min_length: int = 10,
        max_label_length: int = 50,
        query_rate_threshold: int = 100,
        txt_query_threshold: int = 50,
    ):
        """
        Initialize tunneling detector with thresholds.

        Args:
            entropy_threshold: Shannon entropy threshold for high-entropy labels
            entropy_label_min_length: Minimum label length to check entropy
            max_label_length: Threshold for "unusually long" labels (chars)
            query_rate_threshold: Max queries per minute (single domain/host)
            txt_query_threshold: Max TXT queries per minute to single domain
        """
        self.entropy_threshold = entropy_threshold
        self.entropy_label_min_length = entropy_label_min_length
        self.max_label_length = max_label_length
        self.query_rate_threshold = query_rate_threshold
        self.txt_query_threshold = txt_query_threshold

        # Rolling windows for rate-based detection
        self.query_windows: Dict[str, deque] = defaultdict(
            lambda: deque(maxlen=5000)
        )
        self.txt_query_windows: Dict[str, deque] = defaultdict(
            lambda: deque(maxlen=5000)
        )

    def detect(self, query: DnsQuery) -> Tuple[bool, float, str]:
        """
        Detect DNS tunneling with confidence score.

        Args:
            query: DnsQuery to analyze

        Returns:
            (is_tunnel: bool, confidence: float 0.0-1.0, reason: str)
        """
        confidence = 0.0
        reasons = []

        # Method 1: High-entropy subdomain labels
        entropy_score, entropy_reason = self._check_entropy(query.query_name)
        confidence += entropy_score * 0.25
        if entropy_score > 0.3:
            reasons.append(entropy_reason)

        # Method 2: Excessive query rate
        rate_score, rate_reason = self._check_query_rate(query)
        confidence += rate_score * 0.25
        if rate_score > 0.3:
            reasons.append(rate_reason)

        # Method 3: Unusually long labels
        length_score, length_reason = self._check_label_length(query.query_name)
        confidence += length_score * 0.2
        if length_score > 0.3:
            reasons.append(length_reason)

        # Method 4: TXT record abuse
        txt_score, txt_reason = self._check_txt_abuse(query)
        confidence += txt_score * 0.15
        if txt_score > 0.3:
            reasons.append(txt_reason)

        # Method 5: DGA candidate
        dga_is_candidate, dga_score = is_dga_candidate(query.query_name)
        if dga_is_candidate:
            confidence += dga_score * 0.15
            reasons.append(f"DGA pattern detected (score: {dga_score:.2f})")

        confidence = min(confidence, 1.0)
        is_tunnel = confidence > 0.5

        return is_tunnel, confidence, " | ".join(reasons) if reasons else ""

    def _check_entropy(self, fqdn: str) -> Tuple[float, str]:
        """Check for high-entropy subdomain labels characteristic of tunneling."""
        labels = extract_subdomain_labels(fqdn)
        if not labels:
            labels = fqdn.lower().rstrip(".").split(".")[:-1]

        max_entropy = 0.0
        high_entropy_label = ""

        for label in labels:
            if len(label) >= self.entropy_label_min_length:
                ent = shannon_entropy(label)
                if ent > max_entropy:
                    max_entropy = ent
                    high_entropy_label = label

        if max_entropy > self.entropy_threshold:
            score = min((max_entropy - self.entropy_threshold) / 2.0, 1.0)
            return score, f"High-entropy label: '{high_entropy_label}' (H={max_entropy:.2f})"

        return 0.0, ""

    def _check_query_rate(self, query: DnsQuery) -> Tuple[float, str]:
        """Check for excessive query rate to single domain from single host."""
        key = f"{query.source_ip}:{query.query_name}"
        now = query.timestamp

        self.query_windows[key].append(now)

        # Count queries in last minute
        cutoff = now - timedelta(minutes=1)
        recent = [q for q in self.query_windows[key] if q > cutoff]

        if len(recent) > self.query_rate_threshold:
            score = min(len(recent) / self.query_rate_threshold * 0.8, 1.0)
            return score, f"High query rate: {len(recent)}/min to {query.query_name}"

        return 0.0, ""

    def _check_label_length(self, fqdn: str) -> Tuple[float, str]:
        """Check for unusually long labels (characteristic of encoded payloads)."""
        labels = fqdn.lower().rstrip(".").split(".")

        max_length = 0
        long_label = ""

        for label in labels:
            if len(label) > max_length:
                max_length = len(label)
                long_label = label

        if max_length > self.max_label_length:
            score = min((max_length - self.max_label_length) / 100.0, 1.0)
            return score, f"Unusually long label: '{long_label[:30]}...' ({max_length} chars)"

        return 0.0, ""

    def _check_txt_abuse(self, query: DnsQuery) -> Tuple[float, str]:
        """Check for TXT record abuse (high-volume TXT queries to same domain)."""
        if query.query_type != "TXT":
            return 0.0, ""

        key = f"TXT:{query.source_ip}:{query.query_name}"
        now = query.timestamp

        self.txt_query_windows[key].append(now)

        # Count TXT queries in last minute
        cutoff = now - timedelta(minutes=1)
        recent = [q for q in self.txt_query_windows[key] if q > cutoff]

        if len(recent) > self.txt_query_threshold:
            score = min(len(recent) / self.txt_query_threshold * 0.8, 1.0)
            return score, f"High TXT query rate: {len(recent)}/min to {query.query_name}"

        return 0.0, ""


# ────────────────────────────────────────────────────────────────────────────
# DNS Monitor Scanner
# ────────────────────────────────────────────────────────────────────────────

class DnsMonitor(BaseScanner):
    """
    DNS traffic monitor with tunneling and anomaly detection.

    Captures DNS queries via scapy (preferred) or reads from log file (fallback).
    """

    provider = "network"

    def __init__(self, config: dict):
        """
        Initialize DNS monitor.

        Args:
            config: Configuration dict with keys:
                - capture_interface: NIC name (default: "eth0")
                - capture_window_seconds: Packet capture duration (default: 60)
                - dns_log_path: Path to DNS log file for fallback
                - blocklist_path: Path to blocklist file (one domain per line)
                - baseline_db_path: SQLite database path (optional)
                - entropy_threshold: Shannon entropy threshold (default: 3.5)
                - entropy_label_min_length: Min label length for entropy (default: 10)
                - max_label_length: Max "normal" label length (default: 50)
                - query_rate_threshold: Max queries/min (default: 100)
                - txt_query_threshold: Max TXT queries/min (default: 50)
        """
        self.config = config
        self.capture_interface = config.get("capture_interface", "eth0")
        self.capture_window_seconds = config.get("capture_window_seconds", 60)
        self.dns_log_path = config.get("dns_log_path", "")
        self.blocklist_path = config.get("blocklist_path", "")

        # Initialize baseline
        self.baseline = DnsBaseline(
            db_path=config.get("baseline_db_path"),
            window_minutes=1,
        )

        # Initialize tunneling detector
        self.detector = DnsTunnelingDetector(
            entropy_threshold=config.get("entropy_threshold", 3.5),
            entropy_label_min_length=config.get("entropy_label_min_length", 10),
            max_label_length=config.get("max_label_length", 50),
            query_rate_threshold=config.get("query_rate_threshold", 100),
            txt_query_threshold=config.get("txt_query_threshold", 50),
        )

        # Load blocklist if available
        self.blocklist = self._load_blocklist()

    def is_available(self) -> bool:
        """Return True if DNS monitoring is available."""
        # Available if scapy is available OR dns_log_path is configured
        return SCAPY_AVAILABLE or bool(self.dns_log_path)

    def scan(self) -> List[Finding]:
        """
        Scan for DNS anomalies and tunneling attempts.

        Returns:
            List of Finding objects for detected issues
        """
        findings: List[Finding] = []

        if not self.is_available():
            logger.warning(
                "DNS monitor unavailable: scapy not installed and dns_log_path not configured"
            )
            return findings

        try:
            if SCAPY_AVAILABLE:
                logger.info(
                    f"Capturing DNS traffic on {self.capture_interface} for "
                    f"{self.capture_window_seconds}s"
                )
                queries = self._capture_dns_traffic()
            else:
                logger.info(f"Reading DNS queries from log file: {self.dns_log_path}")
                queries = self._read_dns_log()

            # Process each query
            for query in queries:
                # Update baseline
                self.baseline.update(query)

                # Check against blocklist
                if self._is_blocked(query.query_name):
                    findings.append(Finding(
                        resource=f"{query.source_ip}:{query.query_name}",
                        issue=f"DNS query to blocklisted domain: {query.query_name}",
                        severity="high",
                        provider="network",
                        resource_type="dns_query",
                        details={
                            "source_ip": query.source_ip,
                            "domain": query.query_name,
                            "query_type": query.query_type,
                            "timestamp": query.timestamp.isoformat(),
                        },
                        remediation_hint="Block this domain at firewall/DNS level",
                        mitre_techniques=["T1071.004"],  # Application Layer Protocol: DNS
                        mitre_tactic="command-and-control",
                        nist_controls=["AC-3", "SC-7"],
                        cwe_id="CWE-94",
                    ))
                    continue

                # Run tunneling detection
                is_tunnel, confidence, reason = self.detector.detect(query)
                if is_tunnel:
                    findings.append(Finding(
                        resource=f"{query.source_ip}:{query.query_name}",
                        issue=f"Potential DNS tunneling or data exfiltration detected",
                        severity="high",
                        provider="network",
                        resource_type="dns_anomaly",
                        details={
                            "source_ip": query.source_ip,
                            "domain": query.query_name,
                            "query_type": query.query_type,
                            "confidence": f"{confidence:.2f}",
                            "detection_reason": reason,
                            "timestamp": query.timestamp.isoformat(),
                        },
                        remediation_hint=(
                            "Investigate source host for data exfiltration; "
                            "consider DNS sinkhole or network segmentation"
                        ),
                        mitre_techniques=["T1048.003"],  # Exfiltration Over Alternative Protocol
                        mitre_tactic="exfiltration",
                        nist_controls=["CA-7", "SC-7"],
                        cwe_id="CWE-522",
                    ))

                # Check baseline anomalies
                is_anomalous, reason = self.baseline.is_anomalous(query)
                if is_anomalous:
                    findings.append(Finding(
                        resource=f"{query.source_ip}:{query.query_name}",
                        issue=f"DNS query anomaly detected",
                        severity="medium",
                        provider="network",
                        resource_type="dns_anomaly",
                        details={
                            "source_ip": query.source_ip,
                            "domain": query.query_name,
                            "reason": reason,
                            "timestamp": query.timestamp.isoformat(),
                        },
                        remediation_hint="Review query patterns for the affected host",
                        mitre_techniques=["T1071.004"],
                        mitre_tactic="command-and-control",
                        nist_controls=["CA-7"],
                    ))

        except Exception as e:
            logger.error(f"DNS monitor scan failed: {e}", exc_info=True)

        return findings

    def _capture_dns_traffic(self) -> List[DnsQuery]:
        """
        Capture DNS queries using scapy.

        Returns:
            List of DnsQuery objects
        """
        if not SCAPY_AVAILABLE:
            logger.error("scapy not available for packet capture")
            return []

        queries: List[DnsQuery] = []

        def packet_callback(pkt):
            try:
                if IP in pkt and UDP in pkt:
                    ip_layer = pkt[IP]
                    udp_layer = pkt[UDP]

                    # Filter for DNS (port 53)
                    if udp_layer.dport != 53 and udp_layer.sport != 53:
                        return

                    if DNS not in pkt:
                        return

                    dns_layer = pkt[DNS]

                    # Process DNS questions
                    if dns_layer.qdcount > 0:
                        for question in dns_layer.qd:
                            query_name = question.qname.decode("utf-8", errors="ignore").rstrip(".")
                            query_type = str(question.qtype)

                            # Resolve query type name
                            type_map = {
                                "1": "A",
                                "28": "AAAA",
                                "5": "CNAME",
                                "15": "MX",
                                "16": "TXT",
                                "2": "NS",
                                "6": "SOA",
                                "33": "SRV",
                                "12": "PTR",
                            }
                            query_type = type_map.get(query_type, f"TYPE{question.qtype}")

                            # Extract response info (if available)
                            response_code = "NOERROR"
                            response_ips = []
                            ttl = None

                            if dns_layer.an:
                                response_code = (
                                    "NOERROR" if dns_layer.rcode == 0
                                    else f"RCODE{dns_layer.rcode}"
                                )
                                for answer in dns_layer.an:
                                    if hasattr(answer, "rdata"):
                                        response_ips.append(str(answer.rdata))
                                    if hasattr(answer, "ttl"):
                                        ttl = answer.ttl

                            query = DnsQuery(
                                timestamp=datetime.now(timezone.utc),
                                source_ip=ip_layer.src,
                                query_name=query_name,
                                query_type=query_type,
                                response_code=response_code,
                                response_ips=response_ips,
                                ttl=ttl,
                            )
                            queries.append(query)
            except Exception as e:
                logger.debug(f"Error parsing packet: {e}")

        try:
            logger.info(f"Starting packet capture on {self.capture_interface}")
            sniff(
                iface=self.capture_interface,
                prn=packet_callback,
                timeout=self.capture_window_seconds,
                store=False,
            )
        except PermissionError:
            logger.error(
                f"Permission denied for packet capture on {self.capture_interface}. "
                "Run with root/sudo or adjust interface permissions."
            )
        except Exception as e:
            logger.error(f"Packet capture failed: {e}")

        logger.info(f"Captured {len(queries)} DNS queries")
        return queries

    def _read_dns_log(self) -> List[DnsQuery]:
        """
        Read DNS queries from a log file.

        Supports:
          - JSON format: one query per line, with keys: timestamp, source_ip, query_name, query_type, response_code
          - Flat text: space-separated: timestamp source_ip domain query_type response_code

        Returns:
            List of DnsQuery objects
        """
        queries: List[DnsQuery] = []

        if not self.dns_log_path or not Path(self.dns_log_path).exists():
            logger.warning(f"DNS log file not found: {self.dns_log_path}")
            return queries

        try:
            with open(self.dns_log_path, "r") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue

                    try:
                        # Try JSON format first
                        if line.startswith("{"):
                            data = json.loads(line)
                            timestamp = datetime.fromisoformat(data.get("timestamp", ""))
                            query = DnsQuery(
                                timestamp=timestamp,
                                source_ip=data.get("source_ip", "0.0.0.0"),
                                query_name=data.get("query_name", ""),
                                query_type=data.get("query_type", "A"),
                                response_code=data.get("response_code", "NOERROR"),
                                response_ips=data.get("response_ips", []),
                                ttl=data.get("ttl"),
                            )
                            queries.append(query)
                        else:
                            # Try flat text format
                            parts = line.split()
                            if len(parts) >= 5:
                                timestamp = datetime.fromisoformat(parts[0])
                                query = DnsQuery(
                                    timestamp=timestamp,
                                    source_ip=parts[1],
                                    query_name=parts[2],
                                    query_type=parts[3],
                                    response_code=parts[4],
                                )
                                queries.append(query)
                    except (json.JSONDecodeError, ValueError, IndexError) as e:
                        logger.debug(f"Skipping malformed log line: {line[:50]}... ({e})")
                        continue

        except Exception as e:
            logger.error(f"Failed to read DNS log file: {e}")

        logger.info(f"Read {len(queries)} DNS queries from log")
        return queries

    def _load_blocklist(self) -> set:
        """
        Load blocklist of known-bad domains from file.

        Format: one domain per line, comments starting with #

        Returns:
            Set of blocked domains (lowercased)
        """
        blocklist = set()

        if not self.blocklist_path or not Path(self.blocklist_path).exists():
            return blocklist

        try:
            with open(self.blocklist_path, "r") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    blocklist.add(line.lower())
            logger.info(f"Loaded {len(blocklist)} blocked domains from {self.blocklist_path}")
        except Exception as e:
            logger.warning(f"Failed to load blocklist: {e}")

        return blocklist

    def _is_blocked(self, fqdn: str) -> bool:
        """
        Check if domain is in blocklist (domain + subdomain matching).

        Args:
            fqdn: Domain name to check

        Returns:
            True if domain or parent domain is blocklisted
        """
        fqdn_lower = fqdn.lower().rstrip(".")

        # Direct match
        if fqdn_lower in self.blocklist:
            return True

        # Check parent domains
        labels = fqdn_lower.split(".")
        for i in range(len(labels) - 1):
            parent = ".".join(labels[i:])
            if parent in self.blocklist:
                return True

        return False
