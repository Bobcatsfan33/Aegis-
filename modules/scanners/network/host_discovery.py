"""
Host discovery and inventory management for network scanning.

This module provides:
  1. ARP sweeps to discover active hosts on a subnet using scapy
  2. Reverse DNS lookups for discovered IPs
  3. OS fingerprinting via nmap (with graceful fallback if unavailable)
  4. MAC OUI lookups to identify manufacturers
  5. Risk scoring based on port counts, OS type, newness, and vendor recognition
  6. SQLite-based host inventory with upsert semantics
  7. Conversion of high-risk hosts to Aegis Finding objects for OpenSearch indexing

HostRecord dataclass represents a single discovered host with all metadata.
HostDiscoveryScanner performs the discovery and returns Finding objects for high-risk hosts.
HostInventory manages persistence and querying of host records.

Dependencies:
  - scapy (for ARP sweeps): pip install scapy
  - nmap binary (for OS fingerprinting): apt install nmap  OR  brew install nmap
  - python-nmap (optional, for OS detection): pip install python-nmap
  - Standard library: sqlite3, socket, uuid, logging, dataclasses, datetime, ipaddress
"""

import ipaddress
import logging
import socket
import sqlite3
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import List, Optional, Set
from uuid import UUID, uuid4

from modules.scanners.base import BaseScanner, Finding

logger = logging.getLogger(__name__)

try:
    from scapy.all import ARP, Ether, srp
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

try:
    import nmap as nmap_lib
    NMAP_AVAILABLE = True
except ImportError:
    NMAP_AVAILABLE = False


# ── MAC OUI lookup table (common vendors) ──────────────────────────────────
# Maps MAC address prefixes (first 6 chars after removing colons)
# to manufacturer names. Sourced from IEEE 802 standards.
MAC_OUI_TABLE = {
    "001018": "Cisco",
    "001a2f": "Cisco",
    "001c42": "Cisco",
    "001f6c": "Cisco",
    "00215a": "Cisco",
    "002687": "Cisco",
    "0026ab": "Apple",
    "0026bb": "Apple",
    "0026ca": "Apple",
    "003065": "Apple",
    "00306b": "Apple",
    "005084": "Apple",
    "0050e4": "Apple",
    "0050f2": "Microsoft",
    "005569": "Apple",
    "008086": "Intel",
    "00aa00": "Intel",
    "08002b": "Intel",
    "1018f6": "Dell",
    "184254": "HP",
    "18a90d": "HP",
    "2c0e5f": "Intel",
    "3c5a37": "Lenovo",
    "3ccafe": "Dell",
    "3cf3f5": "Dell",
    "70f94f": "Dell",
    "78dba0": "Samsung",
    "84f386": "Samsung",
    "a41d6a": "Lenovo",
    "b0e88d": "Samsung",
    "d46e0e": "Lenovo",
    "e0ee08": "Cisco",
    "e8484a": "Lenovo",
    "f0791a": "VMware",
    "f45ee1": "VMware",
    "525400": "VMware",
    "000c29": "VMware",
    "b42e99": "Raspberry Pi",
    "b82f40": "Raspberry Pi",
    "2cc898": "Raspberry Pi",
    "dc5754": "Raspberry Pi",
    "e45f01": "Raspberry Pi",
}


@dataclass
class HostRecord:
    """
    A discovered host on the network with metadata and risk scoring.

    Attributes:
      host_id          UUID auto-generated for persistence
      ip_address       IPv4 or IPv6 address
      mac_address      MAC address (optional, discovered via ARP)
      hostname         FQDN from reverse DNS lookup (optional)
      os_guess         Operating system guess from nmap -O or MAC OUI (optional)
      manufacturer     Vendor name from MAC OUI lookup (optional)
      open_ports       List of discovered open port numbers
      first_seen       Timestamp when host was first discovered
      last_seen        Timestamp when host was last confirmed active
      risk_score       Float 0.0-10.0 reflecting attack surface
      status           "active" (recently seen) | "stale" (not seen recently) | "new" (just discovered)
    """

    host_id: UUID = field(default_factory=uuid4)
    ip_address: str = ""
    mac_address: Optional[str] = None
    hostname: Optional[str] = None
    os_guess: Optional[str] = None
    manufacturer: Optional[str] = None
    open_ports: List[int] = field(default_factory=list)
    first_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    risk_score: float = 0.0
    status: str = "new"  # active | stale | new

    def to_finding(self) -> Optional[Finding]:
        """
        Convert a high-risk host to an Aegis Finding object for indexing.
        Returns None if risk_score is below thresholds.
        """
        if self.risk_score < 5.0:
            return None

        severity = "critical" if self.risk_score >= 8.0 else "high"

        port_list = ", ".join(str(p) for p in sorted(self.open_ports)[:10])
        if len(self.open_ports) > 10:
            port_list += f", ... and {len(self.open_ports) - 10} more"

        issue = f"Host discovered with {len(self.open_ports)} open ports and risk score {self.risk_score:.1f}/10"

        details = {
            "host_id": str(self.host_id),
            "ip_address": self.ip_address,
            "mac_address": self.mac_address,
            "hostname": self.hostname,
            "os_guess": self.os_guess,
            "manufacturer": self.manufacturer,
            "open_ports": self.open_ports[:20],  # Limit to 20 for details
            "open_port_count": len(self.open_ports),
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "status": self.status,
        }

        remediation = (
            f"Investigate host {self.ip_address} ({self.hostname or 'unknown hostname'}). "
            f"Review open ports: {port_list}. "
            "Consider network segmentation, firewall rules, or service hardening."
        )

        return Finding(
            resource=self.ip_address,
            issue=issue,
            severity=severity,
            provider="network",
            resource_type="host",
            details=details,
            remediation_hint=remediation,
            mitre_techniques=["T1526"],  # Network Service Scanning
            mitre_tactic="discovery",
            nist_controls=["SI-4"],  # Information System Monitoring
            cwe_id="CWE-200",  # Exposure of Sensitive Information
        )


@dataclass
class HostDiscoveryScanner(BaseScanner):
    """
    Discovers active hosts on a subnet using ARP sweeps, performs reverse DNS,
    OS fingerprinting, and manufacturer identification, then scores risk.

    Attributes:
      subnet          CIDR notation (e.g. "192.168.1.0/24")
      timeout_sec     Timeout for ARP sweep in seconds (default 3)
      nmap_timeout    Timeout for per-host nmap OS detection in seconds (default 10)
      max_hosts       Limit number of hosts to scan (0 = unlimited)
    """

    provider = "network"
    subnet: str = "192.168.1.0/24"
    timeout_sec: float = 3.0
    nmap_timeout: int = 10
    max_hosts: int = 0

    def is_available(self) -> bool:
        """Check if scapy is available for ARP scanning."""
        return SCAPY_AVAILABLE

    def scan(self) -> List[Finding]:
        """
        Run host discovery on the configured subnet and return findings for
        high-risk hosts. Returns empty list if scapy is not available.
        """
        if not SCAPY_AVAILABLE:
            logger.warning("scapy not installed — cannot perform ARP sweep")
            return []

        try:
            hosts = self._arp_sweep()
            enriched_hosts = self._enrich_hosts(hosts)
            scored_hosts = self._calculate_risk_scores(enriched_hosts)

            findings = [h.to_finding() for h in scored_hosts if h.to_finding()]
            logger.info(
                f"Host discovery complete: {len(hosts)} hosts discovered, "
                f"{len(findings)} high-risk findings generated"
            )
            return findings

        except Exception as e:
            logger.error(f"Host discovery scan failed: {e}", exc_info=True)
            return []

    # ── ARP Sweep ──────────────────────────────────────────────────────────────

    def _arp_sweep(self) -> List[HostRecord]:
        """
        Send ARP requests to all IPs in subnet and collect replies.
        Returns list of HostRecords with ip_address and mac_address populated.
        """
        hosts: List[HostRecord] = []

        try:
            # Parse CIDR subnet
            network = ipaddress.ip_network(self.subnet, strict=False)
            all_ips = list(network.hosts())

            if self.max_hosts > 0:
                all_ips = all_ips[: self.max_hosts]

            logger.info(f"Starting ARP sweep on {self.subnet} ({len(all_ips)} IPs)")

            # Build ARP packets for all IPs
            arp_requests = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=all_ips)

            # Send and collect replies
            answered, unanswered = srp(
                arp_requests,
                timeout=self.timeout_sec,
                verbose=False,
                inter=0.1,
            )

            logger.info(
                f"ARP sweep complete: {len(answered)} responses, {len(unanswered)} no reply"
            )

            now = datetime.now(timezone.utc)
            for sent, received in answered:
                ip = received.psrc
                mac = received.hwsrc

                host = HostRecord(
                    ip_address=ip,
                    mac_address=mac,
                    first_seen=now,
                    last_seen=now,
                    status="new",
                )
                hosts.append(host)

        except ValueError as e:
            logger.error(f"Invalid CIDR subnet '{self.subnet}': {e}")
        except Exception as e:
            logger.error(f"ARP sweep failed: {e}", exc_info=True)

        return hosts

    # ── Enrichment ─────────────────────────────────────────────────────────────

    def _enrich_hosts(self, hosts: List[HostRecord]) -> List[HostRecord]:
        """
        Enrich hosts with reverse DNS, OS fingerprinting, and MAC OUI lookups.
        Modifies hosts in-place and returns them.
        """
        for host in hosts:
            # Reverse DNS
            host.hostname = self._reverse_dns_lookup(host.ip_address)

            # OS fingerprinting via nmap
            if NMAP_AVAILABLE:
                host.os_guess = self._nmap_os_detect(host.ip_address)
                host.open_ports = self._nmap_port_scan(host.ip_address)

            # MAC OUI lookup
            if host.mac_address:
                host.manufacturer = self._mac_oui_lookup(host.mac_address)

        return hosts

    def _reverse_dns_lookup(self, ip_address: str) -> Optional[str]:
        """Perform reverse DNS lookup on IP. Returns FQDN or None."""
        try:
            hostname, _, _ = socket.gethostbyaddr(ip_address)
            return hostname
        except (socket.herror, socket.timeout, OSError):
            return None

    def _nmap_os_detect(self, ip_address: str) -> Optional[str]:
        """
        Use nmap -O to detect OS on target IP.
        Returns OS string (e.g. "Linux 4.15 - 5.6") or None.
        """
        try:
            nm = nmap_lib.PortScanner()
            nm.scan(hosts=ip_address, arguments="-O -T4 --max-retries 1")

            for host in nm.all_hosts():
                if nm[host].state() == "up" and nm[host].has_key("osmatch"):
                    os_matches = nm[host]["osmatch"]
                    if os_matches:
                        # Return best match (highest accuracy)
                        return os_matches[0]["name"]
            return None

        except Exception as e:
            logger.debug(f"nmap OS detection failed for {ip_address}: {e}")
            return None

    def _nmap_port_scan(self, ip_address: str) -> List[int]:
        """
        Quick nmap scan to find open ports on target.
        Returns list of open port numbers (0-65535).
        """
        try:
            nm = nmap_lib.PortScanner()
            nm.scan(
                hosts=ip_address,
                arguments="-p- -T5 --max-retries 1 --open",
            )

            open_ports = []
            for host in nm.all_hosts():
                if nm[host].state() == "up":
                    for proto in nm[host].all_protocols():
                        for port, port_info in nm[host][proto].items():
                            if port_info["state"] == "open":
                                open_ports.append(port)
            return sorted(open_ports)

        except Exception as e:
            logger.debug(f"nmap port scan failed for {ip_address}: {e}")
            return []

    def _mac_oui_lookup(self, mac_address: str) -> Optional[str]:
        """
        Look up MAC address prefix in built-in OUI table.
        MAC format: "aa:bb:cc:dd:ee:ff" → lookup first 6 hex chars as "aabbcc"
        """
        try:
            # Normalize MAC: remove colons/dashes
            mac_clean = mac_address.replace(":", "").replace("-", "").lower()[:6]
            return MAC_OUI_TABLE.get(mac_clean)
        except Exception as e:
            logger.debug(f"MAC OUI lookup failed for {mac_address}: {e}")
            return None

    # ── Risk Scoring ───────────────────────────────────────────────────────────

    def _calculate_risk_scores(self, hosts: List[HostRecord]) -> List[HostRecord]:
        """
        Calculate risk_score (0.0-10.0) for each host based on:
          - Number of open ports (more ports = higher risk)
          - OS type (unknown = higher risk)
          - Newness (very new = higher risk)
          - Vendor recognition (unknown vendor = higher risk)
        """
        for host in hosts:
            risk = 0.0

            # Open ports contribution (max 5.0)
            # 10+ ports = 5.0, 5-9 ports = 3.0, 1-4 ports = 1.0
            if len(host.open_ports) >= 10:
                risk += 5.0
            elif len(host.open_ports) >= 5:
                risk += 3.0
            elif len(host.open_ports) >= 1:
                risk += 1.0

            # Unknown OS contribution (max 2.0)
            if not host.os_guess:
                risk += 2.0
            elif "unknown" in host.os_guess.lower():
                risk += 1.5

            # Newness contribution (max 2.0)
            age = datetime.now(timezone.utc) - host.first_seen
            if age < timedelta(minutes=5):
                risk += 2.0
            elif age < timedelta(hours=1):
                risk += 1.0

            # Unrecognized vendor contribution (max 1.0)
            if not host.manufacturer:
                risk += 1.0

            host.risk_score = min(risk, 10.0)

        return hosts


@dataclass
class HostInventory:
    """
    SQLite-based persistent storage and querying of HostRecords.

    Manages:
      - Creation and migration of schema
      - Upsert semantics (insert or update by MAC/IP)
      - Stale host detection and marking
      - Conversion to Findings for high-risk hosts
      - Thread-safe SQLite access via connection pooling pattern

    Attributes:
      db_path       Path to SQLite database file (default: /data/aegis_hosts.db)
    """

    db_path: str = "/data/aegis_hosts.db"
    _local = threading.local()  # Thread-local storage for DB connections

    def _get_connection(self) -> sqlite3.Connection:
        """Get or create thread-local SQLite connection."""
        if not hasattr(self._local, "connection") or self._local.connection is None:
            self._local.connection = sqlite3.connect(self.db_path, check_same_thread=False)
            self._local.connection.row_factory = sqlite3.Row
        return self._local.connection

    def create_tables(self) -> None:
        """Create hosts table if it doesn't exist."""
        conn = self._get_connection()
        cursor = conn.cursor()

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS hosts (
                host_id TEXT PRIMARY KEY,
                ip_address TEXT NOT NULL UNIQUE,
                mac_address TEXT,
                hostname TEXT,
                os_guess TEXT,
                manufacturer TEXT,
                open_ports TEXT,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                risk_score REAL NOT NULL DEFAULT 0.0,
                status TEXT NOT NULL DEFAULT 'new',
                created_at TEXT NOT NULL
            )
            """
        )

        # Create index for faster queries
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_status ON hosts(status)"
        )
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_last_seen ON hosts(last_seen)"
        )

        conn.commit()
        logger.info(f"Host inventory tables created/verified in {self.db_path}")

    def upsert_host(self, record: HostRecord) -> None:
        """
        Insert or update a HostRecord by IP address.
        Updates all fields including last_seen and status.
        """
        conn = self._get_connection()
        cursor = conn.cursor()

        now = datetime.now(timezone.utc).isoformat()
        ports_json = ",".join(str(p) for p in record.open_ports)

        cursor.execute(
            """
            INSERT INTO hosts (
                host_id, ip_address, mac_address, hostname, os_guess,
                manufacturer, open_ports, first_seen, last_seen, risk_score, status, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(ip_address) DO UPDATE SET
                mac_address = excluded.mac_address,
                hostname = excluded.hostname,
                os_guess = excluded.os_guess,
                manufacturer = excluded.manufacturer,
                open_ports = excluded.open_ports,
                last_seen = excluded.last_seen,
                risk_score = excluded.risk_score,
                status = excluded.status
            """,
            (
                str(record.host_id),
                record.ip_address,
                record.mac_address,
                record.hostname,
                record.os_guess,
                record.manufacturer,
                ports_json,
                record.first_seen.isoformat(),
                record.last_seen.isoformat(),
                record.risk_score,
                record.status,
                now,
            ),
        )

        conn.commit()
        logger.debug(f"Upserted host {record.ip_address} (risk: {record.risk_score:.1f})")

    def get_all_hosts(self) -> List[HostRecord]:
        """Retrieve all hosts from inventory."""
        conn = self._get_connection()
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM hosts ORDER BY last_seen DESC")
        rows = cursor.fetchall()

        return [self._row_to_record(row) for row in rows]

    def get_host(self, host_id: UUID) -> Optional[HostRecord]:
        """Retrieve single host by host_id."""
        conn = self._get_connection()
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM hosts WHERE host_id = ?", (str(host_id),))
        row = cursor.fetchone()

        return self._row_to_record(row) if row else None

    def get_new_hosts(self, since: datetime) -> List[HostRecord]:
        """Retrieve hosts first_seen after given timestamp."""
        conn = self._get_connection()
        cursor = conn.cursor()

        cursor.execute(
            "SELECT * FROM hosts WHERE first_seen >= ? ORDER BY first_seen DESC",
            (since.isoformat(),),
        )
        rows = cursor.fetchall()

        return [self._row_to_record(row) for row in rows]

    def get_stale_hosts(self, threshold_hours: int = 24) -> List[HostRecord]:
        """
        Retrieve hosts that have not been seen within the last threshold_hours.
        These are candidates for marking as stale.
        """
        conn = self._get_connection()
        cursor = conn.cursor()

        cutoff = (
            datetime.now(timezone.utc) - timedelta(hours=threshold_hours)
        ).isoformat()

        cursor.execute(
            "SELECT * FROM hosts WHERE last_seen < ? ORDER BY last_seen ASC",
            (cutoff,),
        )
        rows = cursor.fetchall()

        return [self._row_to_record(row) for row in rows]

    def mark_stale(self, threshold_hours: int = 24) -> int:
        """
        Mark hosts as stale if last_seen is older than threshold_hours.
        Returns count of hosts marked stale.
        """
        conn = self._get_connection()
        cursor = conn.cursor()

        cutoff = (
            datetime.now(timezone.utc) - timedelta(hours=threshold_hours)
        ).isoformat()

        cursor.execute(
            "UPDATE hosts SET status = 'stale' WHERE last_seen < ? AND status != 'stale'",
            (cutoff,),
        )

        conn.commit()
        count = cursor.rowcount
        logger.info(f"Marked {count} hosts as stale (last seen > {threshold_hours}h ago)")

        return count

    def to_findings(self, min_risk: float = 5.0) -> List[Finding]:
        """
        Convert all high-risk hosts (risk_score >= min_risk) to Finding objects
        suitable for OpenSearch indexing.
        """
        hosts = self.get_all_hosts()
        findings = []

        for host in hosts:
            if host.risk_score >= min_risk:
                finding = host.to_finding()
                if finding:
                    findings.append(finding)

        logger.info(f"Generated {len(findings)} findings from {len(hosts)} hosts")
        return findings

    # ── Utilities ──────────────────────────────────────────────────────────────

    def _row_to_record(self, row: sqlite3.Row) -> HostRecord:
        """Convert SQLite row to HostRecord dataclass."""
        ports_str = row["open_ports"] or ""
        open_ports = [int(p) for p in ports_str.split(",") if p]

        return HostRecord(
            host_id=UUID(row["host_id"]),
            ip_address=row["ip_address"],
            mac_address=row["mac_address"],
            hostname=row["hostname"],
            os_guess=row["os_guess"],
            manufacturer=row["manufacturer"],
            open_ports=open_ports,
            first_seen=datetime.fromisoformat(row["first_seen"]),
            last_seen=datetime.fromisoformat(row["last_seen"]),
            risk_score=row["risk_score"],
            status=row["status"],
        )
