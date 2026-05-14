#!/usr/bin/env python3
"""
VulnSec - Elasticsearch Index Setup
Run once before scanning to create the index template and ILM policy.
Usage: python3 setup_elasticsearch.py
"""

import requests
import json
import sys

ES_HOST = "http://localhost:9200"


def create_ilm_policy():
    """Hot-warm-cold-delete lifecycle: keep hot 7d, warm 30d, delete after 90d."""
    policy = {
        "policy": {
            "phases": {
                "hot":  {"min_age": "0ms", "actions": {"rollover": {"max_age": "7d", "max_size": "50GB"}, "set_priority": {"priority": 100}}},
                "warm": {"min_age": "7d",  "actions": {"shrink": {"number_of_shards": 1}, "set_priority": {"priority": 50}}},
                "cold": {"min_age": "30d", "actions": {"set_priority": {"priority": 0}}},
                "delete": {"min_age": "90d", "actions": {"delete": {}}}
            }
        }
    }
    r = requests.put(f"{ES_HOST}/_ilm/policy/vulnsec-ilm", json=policy)
    print(f"ILM Policy: {r.status_code}")


def create_index_template():
    """Define field mappings for all vuln-findings-* indices."""
    template = {
        "index_patterns": ["vuln-findings-*"],
        "template": {
            "settings": {
                "number_of_shards": 1,
                "number_of_replicas": 0,
                "index.lifecycle.name": "vulnsec-ilm",
                "index.lifecycle.rollover_alias": "vuln-findings"
            },
            "mappings": {
                "properties": {
                    "@timestamp":      {"type": "date"},
                    "timestamp":       {"type": "date"},
                    "scanner":         {"type": "keyword"},
                    "vuln_type":       {"type": "keyword"},
                    "vuln_family":     {"type": "keyword"},
                    "severity":        {"type": "keyword"},
                    "severity_level":  {"type": "integer"},
                    "cvss_score":      {"type": "float"},
                    "risk_band":       {"type": "keyword"},
                    "url":             {"type": "keyword"},
                    "url_host":        {"type": "keyword"},
                    "url_path":        {"type": "keyword"},
                    "url_scheme":      {"type": "keyword"},
                    "parameter":       {"type": "keyword"},
                    "payload":         {"type": "text", "fields": {"keyword": {"type": "keyword"}}},
                    "evidence":        {"type": "text"},
                    "description":     {"type": "text"},
                    "owasp_category":  {"type": "keyword"},
                }
            }
        }
    }
    r = requests.put(f"{ES_HOST}/_index_template/vulnsec-template", json=template)
    print(f"Index Template: {r.status_code}")


def create_initial_index():
    r = requests.put(f"{ES_HOST}/vuln-findings-000001", json={
        "aliases": {"vuln-findings": {"is_write_index": True}}
    })
    print(f"Initial Index: {r.status_code}")


def verify():
    r = requests.get(f"{ES_HOST}/_cat/indices/vuln-findings*?v")
    print("\nIndices:\n", r.text)
    r2 = requests.get(f"{ES_HOST}/_cluster/health?pretty")
    health = r2.json()
    print(f"Cluster health: {health.get('status','?')} | nodes: {health.get('number_of_nodes','?')}")


if __name__ == "__main__":
    print("Setting up Elasticsearch for VulnSec...")
    try:
        create_ilm_policy()
        create_index_template()
        create_initial_index()
        verify()
        print("\nElasticsearch setup complete.")
    except Exception as e:
        print(f"Error: {e}")
        print("Is Elasticsearch running at localhost:9200?")
        sys.exit(1)
