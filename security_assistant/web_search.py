#!/usr/bin/env python3
"""
Advanced Web Search Module for Security Agent
"""

import json
import time
import logging
import re
from typing import List, Dict, Any, Optional
from datetime import datetime

import requests

logger = logging.getLogger(__name__)


class VulnerabilitySearchEngine:
    """Web search engine for vulnerability research"""

    def __init__(self):
        self.initialized = True

    def search_vulnerabilities(self, query: str, limit: int = 10) -> List[Dict[str, Any]]:
        """Search for vulnerability information via CVE or keyword (extract CVE from anywhere in query)"""
        results = []
        query = query.strip()
        cve_search = re.search(r"CVE-\d{4}-\d{4,}", query, re.IGNORECASE)

        if cve_search:
            cve_id = cve_search.group(0).upper()
            results += self._search_nvd(cve_id)
            results += self._search_osv(cve_id)
            return results[:limit]

        # Fallback for keyword search (non-CVE)
        results += self._build_keyword_links(query)
        return results[:limit]

    def _search_nvd(self, cve_id: str) -> List[Dict[str, Any]]:
        """Search CVE on NVD API"""
        nvd_results = []
        nvd_url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
        try:
            resp = requests.get(nvd_url, timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                vulns = data.get("vulnerabilities", [])
                if vulns:
                    cve_data = vulns[0].get("cve", {})
                    desc = next(
                        (d.get("value", "") for d in cve_data.get("descriptions", []) if d.get("lang") == "en"),
                        "No description available"
                    )
                    nvd_results.append({
                        "title": cve_data.get("id", cve_id),
                        "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                        "snippet": desc,
                        "source": "NVD",
                        "timestamp": cve_data.get("published", datetime.now().isoformat()),
                        "query": cve_id
                    })
            else:
                logger.warning(f"NVD API error: {resp.status_code}")
                nvd_results.append({
                    "title": cve_id,
                    "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                    "snippet": f"NVD API error: {resp.status_code}",
                    "source": "NVD",
                    "timestamp": datetime.now().isoformat(),
                    "query": cve_id
                })
        except Exception as e:
            logger.error(f"NVD API error: {e}")
            nvd_results.append({
                "title": cve_id,
                "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                "snippet": f"NVD API exception: {str(e)}",
                "source": "NVD",
                "timestamp": datetime.now().isoformat(),
                "query": cve_id
            })

        return nvd_results

    def _search_osv(self, cve_id: str) -> List[Dict[str, Any]]:
        """Search CVE on OSV API"""
        osv_results = []
        osv_url = f"https://api.osv.dev/v1/vulns/{cve_id}"
        try:
            resp = requests.get(osv_url, timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                summary = data.get("summary", "")
                details = data.get("details", "")
                ref_url = next(
                    (ref.get("url") for ref in data.get("references", []) if ref.get("type") == "WEB"),
                    f"https://osv.dev/vulnerability/{cve_id}"
                )
                osv_results.append({
                    "title": data.get("id", cve_id),
                    "url": ref_url,
                    "snippet": summary or details or "No description available",
                    "source": "OSV",
                    "timestamp": data.get("published", datetime.now().isoformat()),
                    "query": cve_id
                })
            else:
                osv_results.append({
                    "title": cve_id,
                    "url": f"https://osv.dev/vulnerability/{cve_id}",
                    "snippet": f"OSV API error: {resp.status_code}",
                    "source": "OSV",
                    "timestamp": datetime.now().isoformat(),
                    "query": cve_id
                })
        except Exception as e:
            logger.error(f"OSV API error: {e}")
            osv_results.append({
                "title": cve_id,
                "url": f"https://osv.dev/vulnerability/{cve_id}",
                "snippet": f"OSV API exception: {str(e)}",
                "source": "OSV",
                "timestamp": datetime.now().isoformat(),
                "query": cve_id
            })

        return osv_results

    def _build_keyword_links(self, query: str) -> List[Dict[str, str]]:
        """Build keyword search links to public databases"""
        encoded = requests.utils.quote(query)
        now = datetime.now().isoformat()
        return [
            {
                "title": "Search on NVD",
                "url": f"https://nvd.nist.gov/vuln/search/results?query={encoded}",
                "snippet": "Search NVD for vulnerabilities related to your query.",
                "source": "Web",
                "timestamp": now,
                "query": query
            },
            {
                "title": "Search on OSV",
                "url": f"https://osv.dev/list?search={encoded}",
                "snippet": "Search OSV for open source vulnerabilities.",
                "source": "Web",
                "timestamp": now,
                "query": query
            },
            {
                "title": "Search on Exploit-DB",
                "url": f"https://www.exploit-db.com/search?description={encoded}",
                "snippet": "Search Exploit-DB for public exploits.",
                "source": "Web",
                "timestamp": now,
                "query": query
            },
            {
                "title": "Search on MITRE",
                "url": f"https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword={encoded}",
                "snippet": "Search MITRE CVE list by keyword.",
                "source": "Web",
                "timestamp": now,
                "query": query
            },
            {
                "title": "Google Search",
                "url": f"https://www.google.com/search?q={encoded}+site:nvd.nist.gov",
                "snippet": "Google search for vulnerability details (filtered to NVD).",
                "source": "Web",
                "timestamp": now,
                "query": query
            }
        ]


class SearchEnabledAssistant:
    """Assistant with web search capabilities"""

    def __init__(self):
        self.search_engine = VulnerabilitySearchEngine()

    def search_enhanced_cve(self, cve_id: str) -> Dict[str, Any]:
        """Enhanced CVE search with web results"""
        try:
            results = self.search_engine.search_vulnerabilities(cve_id)
            return {
                "cve_id": cve_id,
                "search_results": results,
                "timestamp": datetime.now().isoformat()
            }
        except Exception as e:
            logger.error(f"CVE search error: {e}")
            return {"error": f"Search failed: {str(e)}"}


__all__ = ["VulnerabilitySearchEngine", "SearchEnabledAssistant"]
