"""
Search Backend Indexer — ships findings, remediation results, and scan summaries
to a search/analytics backend for Kibana / OpenSearch Dashboards visualisation.

Supported backends (both are API-compatible):
  opensearch    OpenSearch ≥ 2.x  (Apache 2.0 — fully open source)
                https://opensearch.org
                Install: pip install opensearch-py
  elasticsearch Elasticsearch ≥ 8.x (Elastic License 2.0 / SSPL)
                https://www.elastic.co
                Install: pip install elasticsearch

Priority: opensearch-py is tried first. If it is not installed, the code falls
back to elasticsearch-py. Both have nearly identical Python APIs.

Set SEARCH_BACKEND=opensearch (default) or SEARCH_BACKEND=elasticsearch in .env.

Three indices are created:
  <prefix>-findings        one document per security finding
  <prefix>-remediations    one document per agent action taken
  <prefix>-scans           one document per completed scan (summary)
"""

import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from config import (
    ELASTICSEARCH_API_KEY,
    ELASTICSEARCH_INDEX_PREFIX,
    ELASTICSEARCH_PASSWORD,
    ELASTICSEARCH_URL,
    ELASTICSEARCH_USERNAME,
    SEARCH_BACKEND,
)
from modules.scanners.base import Finding

logger = logging.getLogger(__name__)

# ── Client import — prefer opensearch-py (Apache 2.0) ────────────────────────

_client_lib = None
_helpers_lib = None

if SEARCH_BACKEND == "opensearch":
    try:
        from opensearchpy import OpenSearch as _Client
        from opensearchpy import helpers as _helpers
        _client_lib = _Client
        _helpers_lib = _helpers
        logger.debug("Using opensearch-py client (Apache 2.0)")
    except ImportError:
        pass

if _client_lib is None:
    try:
        from elasticsearch import Elasticsearch as _Client
        from elasticsearch import helpers as _helpers
        _client_lib = _Client
        _helpers_lib = _helpers
        logger.debug("Using elasticsearch-py client (Elastic License)")
    except ImportError:
        pass

SEARCH_CLIENT_AVAILABLE = _client_lib is not None


# ── Index mappings ─────────────────────────────────────────────────────────────

FINDINGS_MAPPING = {
    "mappings": {
        "properties": {
            "@timestamp":       {"type": "date"},
            "scan_id":          {"type": "keyword"},
            "resource":         {"type": "keyword"},
            "issue":            {"type": "text", "fields": {"keyword": {"type": "keyword"}}},
            "severity":         {"type": "keyword"},
            "provider":         {"type": "keyword"},
            "region":           {"type": "keyword"},
            "resource_type":    {"type": "keyword"},
            "details":          {"type": "object", "dynamic": True},
            "remediation_hint": {"type": "text"},
        }
    },
    "settings": {"number_of_shards": 1, "number_of_replicas": 1},
}

REMEDIATIONS_MAPPING = {
    "mappings": {
        "properties": {
            "@timestamp":   {"type": "date"},
            "scan_id":      {"type": "keyword"},
            "finding_id":   {"type": "keyword"},
            "resource":     {"type": "keyword"},
            "provider":     {"type": "keyword"},
            "severity":     {"type": "keyword"},
            "tool":         {"type": "keyword"},
            "action_taken": {"type": "keyword"},
            "success":      {"type": "boolean"},
            "dry_run":      {"type": "boolean"},
            "details":      {"type": "text"},
            "error":        {"type": "keyword"},
        }
    },
    "settings": {"number_of_shards": 1, "number_of_replicas": 1},
}

SCANS_MAPPING = {
    "mappings": {
        "properties": {
            "@timestamp":              {"type": "date"},
            "scan_id":                 {"type": "keyword"},
            "duration_seconds":        {"type": "float"},
            "total":                   {"type": "integer"},
            "critical":                {"type": "integer"},
            "high":                    {"type": "integer"},
            "medium":                  {"type": "integer"},
            "low":                     {"type": "integer"},
            "providers_scanned":       {"type": "keyword"},
            "dry_run":                 {"type": "boolean"},
            "auto_remediate":          {"type": "boolean"},
            "remediations_attempted":  {"type": "integer"},
            "remediations_succeeded":  {"type": "integer"},
        }
    },
    "settings": {"number_of_shards": 1, "number_of_replicas": 1},
}


class ElasticIndexer:
    """
    Vendor-agnostic indexer.  Works with OpenSearch (preferred) or Elasticsearch.
    All methods degrade gracefully when the backend is unreachable.
    """

    def __init__(self):
        self._client: Optional[Any] = None
        self.prefix = ELASTICSEARCH_INDEX_PREFIX
        self._indices_ready = False

    # ── Connection ─────────────────────────────────────────────────────────────

    def _get_client(self) -> Optional[Any]:
        if not SEARCH_CLIENT_AVAILABLE:
            logger.warning(
                "No search client installed. "
                "For OpenSearch (recommended, Apache 2.0): pip install opensearch-py  "
                "For Elasticsearch: pip install elasticsearch"
            )
            return None

        if self._client is not None:
            return self._client

        try:
            kwargs: dict = {}

            if ELASTICSEARCH_API_KEY:
                # Both clients accept http_auth or headers for API key auth
                kwargs["http_auth"] = ("", ELASTICSEARCH_API_KEY)
                # opensearch-py uses headers; elasticsearch uses api_key param
                if SEARCH_BACKEND != "opensearch":
                    kwargs = {"api_key": ELASTICSEARCH_API_KEY}
            elif ELASTICSEARCH_USERNAME and ELASTICSEARCH_PASSWORD:
                kwargs["http_auth"] = (ELASTICSEARCH_USERNAME, ELASTICSEARCH_PASSWORD)

            client = _client_lib(ELASTICSEARCH_URL, **kwargs)

            # Connectivity check — both clients support .info()
            info = client.info()
            version = (
                info.get("version", {}).get("number")
                or info.get("version", {}).get("distribution", "unknown")
            )
            logger.info(
                f"Connected to {SEARCH_BACKEND} {version} at {ELASTICSEARCH_URL}"
            )
            self._client = client
            return client

        except Exception as e:
            logger.error(
                f"Failed to connect to {SEARCH_BACKEND} at {ELASTICSEARCH_URL}: {e}"
            )
            return None

    def is_available(self) -> bool:
        return self._get_client() is not None

    # ── Index management ───────────────────────────────────────────────────────

    def ensure_indices(self) -> bool:
        client = self._get_client()
        if not client:
            return False

        indices = {
            f"{self.prefix}-findings":     FINDINGS_MAPPING,
            f"{self.prefix}-remediations": REMEDIATIONS_MAPPING,
            f"{self.prefix}-scans":        SCANS_MAPPING,
        }

        for name, mapping in indices.items():
            try:
                if not client.indices.exists(index=name):
                    client.indices.create(index=name, body=mapping)
                    logger.info(f"Created index: {name}")
            except Exception as e:
                logger.error(f"Failed to create index {name}: {e}")
                return False

        self._indices_ready = True
        return True

    def _lazy_ensure(self):
        if not self._indices_ready:
            self.ensure_indices()

    # ── Indexing ───────────────────────────────────────────────────────────────

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat()

    def _index(self, index: str, doc: dict) -> bool:
        client = self._get_client()
        if not client:
            return False
        try:
            doc_id = doc.pop("_id", None) or str(uuid.uuid4())
            client.index(index=index, id=doc_id, body=doc)
            return True
        except Exception as e:
            logger.error(f"Failed to index into {index}: {e}")
            return False

    def index_scan_summary(
        self,
        scan_id: str,
        summary: dict,
        providers_scanned: list,
        dry_run: bool,
        auto_remediate: bool,
        duration_seconds: float = 0.0,
        remediations_attempted: int = 0,
        remediations_succeeded: int = 0,
    ) -> bool:
        self._lazy_ensure()
        doc = {
            "@timestamp":              self._now(),
            "scan_id":                 scan_id,
            "duration_seconds":        duration_seconds,
            "total":                   summary.get("total", 0),
            "critical":                summary.get("critical", 0),
            "high":                    summary.get("high", 0),
            "medium":                  summary.get("medium", 0),
            "low":                     summary.get("low", 0),
            "providers_scanned":       providers_scanned,
            "dry_run":                 dry_run,
            "auto_remediate":          auto_remediate,
            "remediations_attempted":  remediations_attempted,
            "remediations_succeeded":  remediations_succeeded,
        }
        return self._index(f"{self.prefix}-scans", doc)

    def bulk_index_scan_results(
        self,
        scan_id: str,
        remediation_results: list,
        summary: dict,
        providers_scanned: list,
        dry_run: bool,
        auto_remediate: bool,
        duration_seconds: float = 0.0,
    ) -> dict:
        client = self._get_client()
        if not client:
            return {"findings": 0, "remediations": 0, "scans": 0}

        self._lazy_ensure()
        now = self._now()
        actions = []
        rem_attempted = 0
        rem_succeeded = 0

        for item in remediation_results:
            if "finding" not in item:
                continue

            finding_data = item["finding"]
            finding_id = str(uuid.uuid4())

            actions.append({
                "_index":  f"{self.prefix}-findings",
                "_id":     finding_id,
                "_source": {
                    "@timestamp": finding_data.get("timestamp", now),
                    "scan_id":    scan_id,
                    **finding_data,
                },
            })

            for action_record in item.get("actions_taken", []):
                result = action_record.get("result", {})
                if not result or action_record.get("tool") == "explain_risk":
                    continue
                rem_attempted += 1
                if result.get("success"):
                    rem_succeeded += 1
                actions.append({
                    "_index":  f"{self.prefix}-remediations",
                    "_id":     str(uuid.uuid4()),
                    "_source": {
                        "@timestamp":   now,
                        "scan_id":      scan_id,
                        "finding_id":   finding_id,
                        "resource":     finding_data.get("resource"),
                        "provider":     finding_data.get("provider"),
                        "severity":     finding_data.get("severity"),
                        "tool":         action_record.get("tool"),
                        "action_taken": result.get("action_taken"),
                        "success":      result.get("success", False),
                        "dry_run":      result.get("dry_run", True),
                        "details":      result.get("details", ""),
                        "error":        result.get("error"),
                    },
                })

        findings_indexed = 0
        remediations_indexed = 0

        if actions:
            try:
                _helpers_lib.bulk(client, actions, raise_on_error=False)
                findings_indexed = sum(
                    1 for a in actions if a["_index"].endswith("-findings")
                )
                remediations_indexed = sum(
                    1 for a in actions if a["_index"].endswith("-remediations")
                )
                logger.info(
                    f"Bulk indexed {findings_indexed} findings, "
                    f"{remediations_indexed} remediations for scan {scan_id}"
                )
            except Exception as e:
                logger.error(f"Bulk index failed: {e}")

        scans_indexed = int(
            self.index_scan_summary(
                scan_id=scan_id,
                summary=summary,
                providers_scanned=providers_scanned,
                dry_run=dry_run,
                auto_remediate=auto_remediate,
                duration_seconds=duration_seconds,
                remediations_attempted=rem_attempted,
                remediations_succeeded=rem_succeeded,
            )
        )

        return {
            "findings":     findings_indexed,
            "remediations": remediations_indexed,
            "scans":        scans_indexed,
        }
