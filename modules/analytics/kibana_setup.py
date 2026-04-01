"""
Aegis — Dashboard Setup Script

Supports two fully open-source dashboard backends:
  opensearch   OpenSearch Dashboards (Apache 2.0)  ← default / recommended
               https://opensearch.org/docs/latest/dashboards/
  kibana       Kibana (Elastic License 2.0 / SSPL)
               https://www.elastic.co/kibana

Both expose compatible Saved Objects and Index Pattern APIs so the same script
works for either. Set DASHBOARD_BACKEND in .env to select.

What this script creates:
  1. Search backend index template (typed field mappings)
  2. A Dashboard index pattern / data view covering <prefix>-*
  3. A dashboard with:
       Total Findings · Critical · High · Remediation Success Rate (metrics)
       Findings by Severity (donut) · Findings by Provider (bar)
       Findings Over Time (area) · Findings by Resource Type (horizontal bar)

Run once after standing up OpenSearch + OpenSearch Dashboards:
    python -m modules.analytics.kibana_setup

Or from the project root:
    PYTHONPATH=. python modules/analytics/kibana_setup.py
"""

import base64
import json
import logging
import sys

import requests

from config import (
    DASHBOARD_API_KEY,
    DASHBOARD_BACKEND,
    DASHBOARD_URL,
    ELASTICSEARCH_API_KEY,
    ELASTICSEARCH_INDEX_PREFIX,
    ELASTICSEARCH_PASSWORD,
    ELASTICSEARCH_URL,
    ELASTICSEARCH_USERNAME,
)

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)

PREFIX        = ELASTICSEARCH_INDEX_PREFIX
DATA_VIEW_ID  = f"{PREFIX}-data-view"
DATA_VIEW_PAT = f"{PREFIX}-*"


# ── Auth helpers ───────────────────────────────────────────────────────────────

def _auth_header() -> str:
    if DASHBOARD_API_KEY or ELASTICSEARCH_API_KEY:
        key = DASHBOARD_API_KEY or ELASTICSEARCH_API_KEY
        return f"ApiKey {key}"
    if ELASTICSEARCH_USERNAME and ELASTICSEARCH_PASSWORD:
        creds = base64.b64encode(
            f"{ELASTICSEARCH_USERNAME}:{ELASTICSEARCH_PASSWORD}".encode()
        ).decode()
        return f"Basic {creds}"
    return ""


def _es_headers() -> dict:
    h = {"Content-Type": "application/json"}
    if ELASTICSEARCH_API_KEY:
        h["Authorization"] = f"ApiKey {ELASTICSEARCH_API_KEY}"
    elif ELASTICSEARCH_USERNAME and ELASTICSEARCH_PASSWORD:
        creds = base64.b64encode(
            f"{ELASTICSEARCH_USERNAME}:{ELASTICSEARCH_PASSWORD}".encode()
        ).decode()
        h["Authorization"] = f"Basic {creds}"
    return h


def _dash_headers() -> dict:
    h = {"osd-xsrf": "true", "kbn-xsrf": "true", "Content-Type": "application/json"}
    auth = _auth_header()
    if auth:
        h["Authorization"] = auth
    return h


def es_put(path: str, body: dict) -> requests.Response:
    return requests.put(
        f"{ELASTICSEARCH_URL}{path}",
        headers=_es_headers(),
        json=body,
        timeout=15,
    )


def dash_post(path: str, body: dict) -> requests.Response:
    return requests.post(
        f"{DASHBOARD_URL}{path}",
        headers=_dash_headers(),
        json=body,
        timeout=15,
    )


def dash_get(path: str) -> requests.Response:
    return requests.get(
        f"{DASHBOARD_URL}{path}",
        headers=_dash_headers(),
        timeout=15,
    )


# ── Step 1: Index template ─────────────────────────────────────────────────────

def create_index_template() -> bool:
    logger.info("Creating search backend index template...")
    template = {
        "index_patterns": [f"{PREFIX}-*"],
        "template": {
            "settings": {"number_of_shards": 1, "number_of_replicas": 1},
            "mappings": {
                "dynamic_templates": [{
                    "strings_as_keywords": {
                        "match_mapping_type": "string",
                        "mapping": {
                            "type": "keyword",
                            "fields": {"text": {"type": "text"}},
                        },
                    }
                }],
                "properties": {
                    "@timestamp":             {"type": "date"},
                    "scan_id":                {"type": "keyword"},
                    "resource":               {"type": "keyword"},
                    "issue":                  {"type": "text", "fields": {"keyword": {"type": "keyword"}}},
                    "severity":               {"type": "keyword"},
                    "provider":               {"type": "keyword"},
                    "region":                 {"type": "keyword"},
                    "resource_type":          {"type": "keyword"},
                    "tool":                   {"type": "keyword"},
                    "action_taken":           {"type": "keyword"},
                    "success":                {"type": "boolean"},
                    "dry_run":                {"type": "boolean"},
                    "auto_remediate":         {"type": "boolean"},
                    "total":                  {"type": "integer"},
                    "critical":               {"type": "integer"},
                    "high":                   {"type": "integer"},
                    "medium":                 {"type": "integer"},
                    "low":                    {"type": "integer"},
                    "duration_seconds":       {"type": "float"},
                    "remediations_attempted": {"type": "integer"},
                    "remediations_succeeded": {"type": "integer"},
                },
            },
        },
        "priority": 200,
    }
    resp = es_put(f"/_index_template/{PREFIX}-template", template)
    if resp.status_code in (200, 201):
        logger.info(f"  ✓ Index template '{PREFIX}-template' created")
        return True
    logger.error(f"  ✗ Index template failed: {resp.status_code} {resp.text[:200]}")
    return False


# ── Step 2: Index pattern / Data View ─────────────────────────────────────────

def create_index_pattern() -> bool:
    logger.info(f"Creating index pattern for '{DATA_VIEW_PAT}'...")

    # OpenSearch Dashboards uses /api/saved_objects/index-pattern
    # Kibana ≥ 8.x uses /api/data_views/data_view (newer endpoint)
    # We try the modern endpoint first, fall back to the legacy one.

    # Modern endpoint (Kibana 8.x / OpenSearch Dashboards 2.x)
    modern_body = {
        "data_view": {
            "id":            DATA_VIEW_ID,
            "title":         DATA_VIEW_PAT,
            "timeFieldName": "@timestamp",
            "name":          "Aegis",
        },
        "override": True,
    }
    resp = dash_post("/api/data_views/data_view", modern_body)
    if resp.status_code in (200, 201, 409):
        logger.info(f"  ✓ Data view created (modern API)")
        return True

    # Legacy endpoint (OpenSearch Dashboards < 2.11 / Kibana 7.x)
    # Note: "overwrite" must only be in the query string, NOT in the body.
    legacy_body = {
        "attributes": {
            "title":         DATA_VIEW_PAT,
            "timeFieldName": "@timestamp",
        },
    }
    resp = dash_post(
        f"/api/saved_objects/index-pattern/{DATA_VIEW_ID}?overwrite=true",
        legacy_body,
    )
    if resp.status_code in (200, 201):
        logger.info(f"  ✓ Index pattern created (legacy API)")
        return True

    logger.error(f"  ✗ Failed to create index pattern: {resp.status_code} {resp.text[:300]}")
    return False


# ── Step 3: Dashboard (OpenSearch Dashboards native visualizations) ───────────

def _osd_vis(vis_id: str, title: str, vis_type: str, aggs: list,
             params: dict, index_filter: str = "") -> dict:
    """Build an OpenSearch Dashboards-native visualization saved object.

    Uses the standard visState format supported by OpenSearch Dashboards 2.x.
    vis_type: metric, pie, histogram, area, horizontal_bar, table, etc.
    """
    search_source = {"index": DATA_VIEW_ID, "query": {"query": "", "language": "kuery"}, "filter": []}
    if index_filter:
        search_source["query"]["query"] = index_filter

    vis_state = {
        "title": title,
        "type": vis_type,
        "aggs": aggs,
        "params": params,
    }

    return {
        "id":   vis_id,
        "type": "visualization",
        "attributes": {
            "title":       title,
            "visState":    json.dumps(vis_state),
            "uiStateJSON": "{}",
            "description": "",
            "kibanaSavedObjectMeta": {
                "searchSourceJSON": json.dumps(search_source),
            },
        },
        "references": [{
            "id":   DATA_VIEW_ID,
            "name": "kibanaSavedObjectMeta.searchSourceJSON.index",
            "type": "index-pattern",
        }],
    }


def _build_saved_objects() -> list:
    """Build all OpenSearch Dashboards-native saved objects."""

    # ── Metric: Total Findings ────────────────────────────────────────────────
    total_findings = _osd_vis(
        f"{PREFIX}-vis-total", "Total Findings", "metric",
        aggs=[{"id": "1", "enabled": True, "type": "count", "params": {},
               "schema": "metric"}],
        params={
            "addTooltip": True, "addLegend": False, "type": "metric",
            "metric": {
                "percentageMode": False, "colorSchema": "Green to Red",
                "metricColorMode": "None", "useRanges": False,
                "style": {"bgFill": "#000", "bgColor": False,
                           "labelColor": False, "subText": "", "fontSize": 60},
            },
        },
    )

    # ── Metric: Critical Findings ─────────────────────────────────────────────
    critical_findings = _osd_vis(
        f"{PREFIX}-vis-critical", "Critical Findings", "metric",
        aggs=[{"id": "1", "enabled": True, "type": "count", "params": {},
               "schema": "metric"}],
        params={
            "addTooltip": True, "addLegend": False, "type": "metric",
            "metric": {
                "percentageMode": False, "colorSchema": "Green to Red",
                "metricColorMode": "Background", "useRanges": True,
                "colorsRange": [{"from": 0, "to": 1}, {"from": 1, "to": 1000}],
                "style": {"bgFill": "#000", "bgColor": True,
                           "labelColor": False, "subText": "", "fontSize": 60},
            },
        },
        index_filter="severity:critical",
    )

    # ── Metric: High Severity ─────────────────────────────────────────────────
    high_findings = _osd_vis(
        f"{PREFIX}-vis-high", "High Severity Findings", "metric",
        aggs=[{"id": "1", "enabled": True, "type": "count", "params": {},
               "schema": "metric"}],
        params={
            "addTooltip": True, "addLegend": False, "type": "metric",
            "metric": {
                "percentageMode": False, "colorSchema": "Green to Red",
                "metricColorMode": "Background", "useRanges": True,
                "colorsRange": [{"from": 0, "to": 1}, {"from": 1, "to": 1000}],
                "style": {"bgFill": "#000", "bgColor": True,
                           "labelColor": False, "subText": "", "fontSize": 60},
            },
        },
        index_filter="severity:high",
    )

    # ── Metric: Medium + Low ──────────────────────────────────────────────────
    medium_low = _osd_vis(
        f"{PREFIX}-vis-medlow", "Medium + Low Findings", "metric",
        aggs=[{"id": "1", "enabled": True, "type": "count", "params": {},
               "schema": "metric"}],
        params={
            "addTooltip": True, "addLegend": False, "type": "metric",
            "metric": {
                "percentageMode": False, "colorSchema": "Green to Red",
                "metricColorMode": "None", "useRanges": False,
                "style": {"bgFill": "#000", "bgColor": False,
                           "labelColor": False, "subText": "", "fontSize": 60},
            },
        },
        index_filter="severity:medium OR severity:low",
    )

    # ── Pie: Findings by Severity ─────────────────────────────────────────────
    severity_pie = _osd_vis(
        f"{PREFIX}-vis-severity", "Findings by Severity", "pie",
        aggs=[
            {"id": "1", "enabled": True, "type": "count", "params": {},
             "schema": "metric"},
            {"id": "2", "enabled": True, "type": "terms", "params": {
                "field": "severity", "orderBy": "1", "order": "desc",
                "size": 6, "otherBucket": False, "missingBucket": False,
             }, "schema": "segment"},
        ],
        params={
            "type": "pie", "addTooltip": True, "addLegend": True,
            "legendPosition": "right", "isDonut": True,
            "labels": {"show": True, "values": True, "last_level": True, "truncate": 100},
        },
    )

    # ── Bar: Findings by Provider ─────────────────────────────────────────────
    provider_bar = _osd_vis(
        f"{PREFIX}-vis-provider", "Findings by Provider", "histogram",
        aggs=[
            {"id": "1", "enabled": True, "type": "count", "params": {},
             "schema": "metric"},
            {"id": "2", "enabled": True, "type": "terms", "params": {
                "field": "provider", "orderBy": "1", "order": "desc",
                "size": 10, "otherBucket": False, "missingBucket": False,
             }, "schema": "segment"},
        ],
        params={
            "type": "histogram", "addTooltip": True, "addLegend": True,
            "legendPosition": "right", "addTimeMarker": False,
            "categoryAxes": [{"id": "CategoryAxis-1", "type": "category",
                              "position": "bottom", "show": True,
                              "labels": {"show": True, "truncate": 100},
                              "title": {}}],
            "valueAxes": [{"id": "ValueAxis-1", "name": "LeftAxis-1",
                           "type": "value", "position": "left", "show": True,
                           "labels": {"show": True}, "title": {"text": "Count"}}],
            "seriesParams": [{"show": True, "type": "histogram", "mode": "stacked",
                              "data": {"label": "Count", "id": "1"},
                              "valueAxis": "ValueAxis-1"}],
            "grid": {"categoryLines": False},
        },
    )

    # ── Area: Findings Over Time ──────────────────────────────────────────────
    timeline_area = _osd_vis(
        f"{PREFIX}-vis-timeline", "Findings Over Time", "area",
        aggs=[
            {"id": "1", "enabled": True, "type": "count", "params": {},
             "schema": "metric"},
            {"id": "2", "enabled": True, "type": "date_histogram", "params": {
                "field": "@timestamp", "useNormalizedOpenSearchInterval": True,
                "scaleMetricValues": False, "interval": "auto",
                "drop_partials": False, "min_doc_count": 1,
                "extended_bounds": {},
             }, "schema": "segment"},
        ],
        params={
            "type": "area", "addTooltip": True, "addLegend": True,
            "legendPosition": "right", "addTimeMarker": False,
            "categoryAxes": [{"id": "CategoryAxis-1", "type": "category",
                              "position": "bottom", "show": True,
                              "labels": {"show": True, "truncate": 100},
                              "title": {}}],
            "valueAxes": [{"id": "ValueAxis-1", "name": "LeftAxis-1",
                           "type": "value", "position": "left", "show": True,
                           "labels": {"show": True}, "title": {"text": "Count"}}],
            "seriesParams": [{"show": True, "type": "area", "mode": "stacked",
                              "data": {"label": "Count", "id": "1"},
                              "valueAxis": "ValueAxis-1",
                              "drawLinesBetweenPoints": True,
                              "lineWidth": 2, "showCircles": True}],
            "grid": {"categoryLines": False},
        },
    )

    # ── Horizontal bar: Findings by Resource Type ─────────────────────────────
    rtype_bar = _osd_vis(
        f"{PREFIX}-vis-rtype", "Findings by Resource Type", "horizontal_bar",
        aggs=[
            {"id": "1", "enabled": True, "type": "count", "params": {},
             "schema": "metric"},
            {"id": "2", "enabled": True, "type": "terms", "params": {
                "field": "resource_type", "orderBy": "1", "order": "desc",
                "size": 15, "otherBucket": False, "missingBucket": False,
             }, "schema": "segment"},
        ],
        params={
            "type": "horizontal_bar", "addTooltip": True, "addLegend": True,
            "legendPosition": "right",
            "categoryAxes": [{"id": "CategoryAxis-1", "type": "category",
                              "position": "left", "show": True,
                              "labels": {"show": True, "truncate": 100},
                              "title": {}}],
            "valueAxes": [{"id": "ValueAxis-1", "name": "BottomAxis-1",
                           "type": "value", "position": "bottom", "show": True,
                           "labels": {"show": True}, "title": {"text": "Count"}}],
            "seriesParams": [{"show": True, "type": "histogram", "mode": "stacked",
                              "data": {"label": "Count", "id": "1"},
                              "valueAxis": "ValueAxis-1"}],
            "grid": {"categoryLines": False},
        },
    )

    objects = [total_findings, critical_findings, high_findings, medium_low,
               severity_pie, provider_bar, timeline_area, rtype_bar]

    # ── Dashboard shell ───────────────────────────────────────────────────────
    # Use the legacy panel format with direct 'id' references.
    # This avoids the panelRefName migration bug in OpenSearch Dashboards 2.x.
    vis_ids = [o["id"] for o in objects]
    panels = [
        {"version": "2.13.0",
         "panelIndex": str(i+1), "type": "visualization",
         "id": vid,
         "embeddableConfig": {},
         "gridData": {"x": x, "y": y, "w": w, "h": h, "i": str(i+1)}}
        for i, (vid, (x, y, w, h)) in enumerate(zip(vis_ids, [
            (0,  0,  6, 5),  (6,  0,  6, 5),  (12, 0,  6, 5),  (18, 0,  6, 5),
            (0,  5, 12, 12), (12, 5, 12, 12),
            (0, 17, 24, 10),
            (0, 27, 24, 12),
        ]))
    ]

    objects.append({
        "id":   f"{PREFIX}-dashboard",
        "type": "dashboard",
        "attributes": {
            "title":       "Aegis — Security Posture",
            "description": "Real-time cloud and network security findings, severity breakdown, and remediation tracking.",
            "panelsJSON":  json.dumps(panels),
            "optionsJSON": json.dumps({"useMargins": True, "syncColors": False, "hidePanelTitles": False}),
            "timeRestore": False,
            "kibanaSavedObjectMeta": {
                "searchSourceJSON": json.dumps({"query": {"query": "", "language": "kuery"}, "filter": []})
            },
        },
        "references": [],
    })
    return objects


def create_dashboard() -> bool:
    logger.info("Creating visualisations and dashboard...")
    objects = _build_saved_objects()
    ok = 0
    fail = 0
    for obj in objects:
        obj_type = obj["type"]
        obj_id   = obj["id"]
        resp = dash_post(
            f"/api/saved_objects/{obj_type}/{obj_id}?overwrite=true",
            {"attributes": obj["attributes"], "references": obj.get("references", [])},
        )
        if resp.status_code in (200, 201):
            ok += 1
            logger.info(f"  ✓ {obj_type}: {obj.get('attributes', {}).get('title', obj_id)}")
        else:
            fail += 1
            logger.error(
                f"  ✗ {obj_type} '{obj_id}': {resp.status_code} {resp.text[:200]}"
            )
    logger.info(f"  Created {ok} objects, {fail} failed.")
    return fail == 0


# ── Connectivity checks ────────────────────────────────────────────────────────

def check_search_backend() -> bool:
    try:
        resp = requests.get(ELASTICSEARCH_URL, headers=_es_headers(), timeout=10)
        if resp.ok:
            info = resp.json()
            name = info.get("name", "")
            ver  = info.get("version", {}).get("number", "?")
            dist = info.get("version", {}).get("distribution", "elasticsearch")
            logger.info(f"  ✓ {dist} {ver} ({name}) at {ELASTICSEARCH_URL}")
            return True
        logger.error(f"  ✗ Search backend returned {resp.status_code}")
        return False
    except Exception as e:
        logger.error(f"  ✗ Cannot reach {ELASTICSEARCH_URL}: {e}")
        return False


def check_dashboard() -> bool:
    try:
        resp = dash_get("/api/status")
        if resp.ok:
            level = (resp.json().get("status", {})
                     .get("overall", {}).get("level", "unknown"))
            backend_label = "OpenSearch Dashboards" if DASHBOARD_BACKEND == "opensearch" else "Kibana"
            logger.info(f"  ✓ {backend_label} at {DASHBOARD_URL} (status: {level})")
            return True
        logger.error(f"  ✗ Dashboard returned {resp.status_code}")
        return False
    except Exception as e:
        logger.error(f"  ✗ Cannot reach dashboard at {DASHBOARD_URL}: {e}")
        return False


# ── Main ───────────────────────────────────────────────────────────────────────

def run_setup():
    backend_label = (
        "OpenSearch Dashboards (Apache 2.0)"
        if DASHBOARD_BACKEND == "opensearch"
        else "Kibana (Elastic License)"
    )
    print("\n" + "=" * 60)
    print(f"  Aegis — Dashboard Setup")
    print(f"  Backend: {backend_label}")
    print("=" * 60)

    logger.info("Checking connectivity...")
    if not check_search_backend():
        logger.error(f"Search backend not reachable. Check ELASTICSEARCH_URL in .env")
        sys.exit(1)
    if not check_dashboard():
        logger.error(f"Dashboard not reachable. Check DASHBOARD_URL in .env")
        sys.exit(1)

    if not create_index_template():
        sys.exit(1)
    if not create_index_pattern():
        sys.exit(1)

    create_dashboard()

    print("\n" + "=" * 60)
    print("  Setup complete!")
    print(f"  Open dashboard: {DASHBOARD_URL}/app/dashboards")
    print(f"  Search for:     Aegis")
    print("=" * 60 + "\n")


if __name__ == "__main__":
    run_setup()
