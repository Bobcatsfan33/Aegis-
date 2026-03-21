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
    legacy_body = {
        "attributes": {
            "title":         DATA_VIEW_PAT,
            "timeFieldName": "@timestamp",
        },
        "overwrite": True,
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


# ── Step 3: Dashboard ──────────────────────────────────────────────────────────

def _lens_vis(vis_id: str, title: str, vis_type: str, state: dict) -> dict:
    return {
        "id":   vis_id,
        "type": "lens",
        "attributes": {
            "title":             title,
            "visualizationType": vis_type,
            "state":             state,
            "references": [{
                "id":   DATA_VIEW_ID,
                "name": "indexpattern-datasource-layer-layer0",
                "type": "index-pattern",
            }],
        },
        "references": [{
            "id":   DATA_VIEW_ID,
            "name": "indexpattern-datasource-layer-layer0",
            "type": "index-pattern",
        }],
    }


def _build_saved_objects() -> list:
    """Build all Kibana / OpenSearch Dashboards Lens saved objects."""

    def count_by_field(field: str, size: int = 10) -> dict:
        return {"layers": {"layer0": {
            "columnOrder": ["grp", "cnt"],
            "columns": {
                "grp": {
                    "label": field, "dataType": "string",
                    "operationType": "terms", "sourceField": field,
                    "isBucketed": True,
                    "params": {"size": size,
                               "orderBy": {"type": "column", "columnId": "cnt"},
                               "orderDirection": "desc"},
                },
                "cnt": {"label": "Count", "dataType": "number",
                        "operationType": "count", "isBucketed": False},
            },
            "incompleteColumns": {},
            "indexPatternId": DATA_VIEW_ID,
        }}}

    def date_histogram() -> dict:
        return {"layers": {"layer0": {
            "columnOrder": ["date", "cnt"],
            "columns": {
                "date": {
                    "label": "@timestamp", "dataType": "date",
                    "operationType": "date_histogram", "sourceField": "@timestamp",
                    "isBucketed": True, "params": {"interval": "auto"},
                },
                "cnt": {"label": "Count", "dataType": "number",
                        "operationType": "count", "isBucketed": False},
            },
            "incompleteColumns": {},
            "indexPatternId": DATA_VIEW_ID,
        }}}

    def metric_count(kuery: str = "") -> dict:
        col: dict = {"label": "Count", "dataType": "number",
                     "operationType": "count", "isBucketed": False}
        if kuery:
            col["filter"] = {"query": kuery, "language": "kuery"}
        return {"layers": {"layer0": {
            "columnOrder": ["cnt"], "columns": {"cnt": col},
            "incompleteColumns": {}, "indexPatternId": DATA_VIEW_ID,
        }}}

    def success_rate() -> dict:
        return {"layers": {"layer0": {
            "columnOrder": ["total", "success", "pct"],
            "columns": {
                "total":   {"label": "Total", "dataType": "number",
                            "operationType": "count", "isBucketed": False},
                "success": {"label": "Successful", "dataType": "number",
                            "operationType": "count", "isBucketed": False,
                            "filter": {"query": "success:true", "language": "kuery"}},
                "pct":     {"label": "Success %", "dataType": "number",
                            "operationType": "formula", "isBucketed": False,
                            "params": {"formula": "count(kql='success:true') / count() * 100",
                                       "isFormulaBroken": False,
                                       "format": {"id": "percent", "params": {"decimals": 1}}}},
            },
            "incompleteColumns": {},
            "indexPatternId": DATA_VIEW_ID,
        }}}

    objects = [
        _lens_vis(f"{PREFIX}-vis-total",    "Total Findings",             "lnsMetric",
                  {"datasourceStates": {"formBased": metric_count()},
                   "visualization": {"layerId": "layer0", "layerType": "data", "metricAccessor": "cnt"},
                   "query": {"query": f"_index:{PREFIX}-findings", "language": "kuery"}, "filters": []}),
        _lens_vis(f"{PREFIX}-vis-critical", "Critical Findings",           "lnsMetric",
                  {"datasourceStates": {"formBased": metric_count("severity:critical")},
                   "visualization": {"layerId": "layer0", "layerType": "data",
                                     "metricAccessor": "cnt", "color": "#D32F2F"},
                   "query": {"query": f"_index:{PREFIX}-findings", "language": "kuery"}, "filters": []}),
        _lens_vis(f"{PREFIX}-vis-high",     "High Severity Findings",      "lnsMetric",
                  {"datasourceStates": {"formBased": metric_count("severity:high")},
                   "visualization": {"layerId": "layer0", "layerType": "data",
                                     "metricAccessor": "cnt", "color": "#F57C00"},
                   "query": {"query": f"_index:{PREFIX}-findings", "language": "kuery"}, "filters": []}),
        _lens_vis(f"{PREFIX}-vis-rem-rate", "Remediation Success Rate",    "lnsMetric",
                  {"datasourceStates": {"formBased": success_rate()},
                   "visualization": {"layerId": "layer0", "layerType": "data",
                                     "metricAccessor": "pct", "color": "#1B5E20"},
                   "query": {"query": f"_index:{PREFIX}-remediations", "language": "kuery"}, "filters": []}),
        _lens_vis(f"{PREFIX}-vis-severity", "Findings by Severity",         "lnsPie",
                  {"datasourceStates": {"formBased": count_by_field("severity", 6)},
                   "visualization": {"shape": "donut", "layers": [{
                       "layerId": "layer0", "layerType": "data",
                       "primaryGroups": ["grp"], "metric": "cnt",
                       "numberDisplay": "percent", "categoryDisplay": "default",
                       "legendDisplay": "default"}]},
                   "query": {"query": f"_index:{PREFIX}-findings", "language": "kuery"}, "filters": []}),
        _lens_vis(f"{PREFIX}-vis-provider", "Findings by Cloud Provider",   "lnsXY",
                  {"datasourceStates": {"formBased": count_by_field("provider", 10)},
                   "visualization": {
                       "legend": {"isVisible": True, "position": "right"},
                       "preferredSeriesType": "bar",
                       "layers": [{"layerId": "layer0", "layerType": "data",
                                   "seriesType": "bar", "xAccessor": "grp", "accessors": ["cnt"]}]},
                   "query": {"query": f"_index:{PREFIX}-findings", "language": "kuery"}, "filters": []}),
        _lens_vis(f"{PREFIX}-vis-timeline", "Findings Over Time",           "lnsXY",
                  {"datasourceStates": {"formBased": date_histogram()},
                   "visualization": {
                       "legend": {"isVisible": True, "position": "right"},
                       "preferredSeriesType": "area",
                       "layers": [{"layerId": "layer0", "layerType": "data",
                                   "seriesType": "area", "xAccessor": "date", "accessors": ["cnt"]}]},
                   "query": {"query": f"_index:{PREFIX}-findings", "language": "kuery"}, "filters": []}),
        _lens_vis(f"{PREFIX}-vis-rtype",    "Findings by Resource Type",   "lnsXY",
                  {"datasourceStates": {"formBased": count_by_field("resource_type", 15)},
                   "visualization": {
                       "legend": {"isVisible": True, "position": "right"},
                       "preferredSeriesType": "bar_horizontal",
                       "layers": [{"layerId": "layer0", "layerType": "data",
                                   "seriesType": "bar_horizontal",
                                   "xAccessor": "grp", "accessors": ["cnt"]}]},
                   "query": {"query": f"_index:{PREFIX}-findings", "language": "kuery"}, "filters": []}),
    ]

    vis_ids = [o["id"] for o in objects]
    panels = [
        {"panelIndex": str(i+1), "type": "lens", "panelRefName": f"panel_{i+1}",
         "gridData": {"x": x, "y": y, "w": w, "h": h, "i": str(i+1)}}
        for i, (x, y, w, h) in enumerate([
            (0,  0,  6, 4), (6,  0,  6, 4), (12, 0,  6, 4), (18, 0,  6, 4),
            (0,  4, 12, 15), (12, 4, 12, 15),
            (0, 19, 24, 12),
            (0, 31, 24, 15),
        ])
    ]

    references = [
        {"id": vid, "name": f"panel_{i+1}", "type": "lens"}
        for i, vid in enumerate(vis_ids)
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
        "references": references,
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
