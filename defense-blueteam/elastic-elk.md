# Elastic Stack (ELK)

> The open-source search, storage, and visualization backend behind much of blue
> team tooling — Elasticsearch to index logs, Kibana to explore them, and Beats
> to ship them. It's the SIEM engine that Security Onion, Suricata, and Wazuh
> dashboards feed into.

- **Link:** https://github.com/elastic/elasticsearch
- **Type:** open source (free/open Basic tier; some features require a licence)
- **Platform:** cross-platform (Linux/Windows/macOS; containers)

## Description

"ELK" (now often "the Elastic Stack") is three components working together:
**Elasticsearch**, a distributed JSON document store and search engine;
**Kibana**, the web UI for querying, dashboards, and alerting; and **Beats**
(plus Logstash), the lightweight shippers that collect and forward data. In a
SOC it is the aggregation layer — the place logs and alerts land so analysts can
search across hosts and time. You rarely deploy it in isolation: it's the backend
under [Security Onion](security-onion.md), the destination for
[Suricata](suricata.md)'s `eve.json` and [Zeek](../network-analysis/zeek.md)
logs, and the engine that renders [Wazuh](wazuh.md) dashboards. Knowing the stack
directly lets you build your own detections and visualizations instead of relying
on a prepackaged distro.

## Installation

```bash
# Quickest lab setup: run the stack with Docker Compose (single-node)
docker run -d --name es -p 9200:9200 -e "discovery.type=single-node" \
  docker.elastic.co/elasticsearch/elasticsearch:8.14.0

# Kibana, pointed at the Elasticsearch container
docker run -d --name kibana -p 5601:5601 \
  -e "ELASTICSEARCH_HOSTS=http://es:9200" \
  docker.elastic.co/kibana/kibana:8.14.0
```

## Usage examples

```bash
# Confirm the cluster is up and healthy
curl http://localhost:9200/_cluster/health?pretty

# List all indices (where your log data lives)
curl http://localhost:9200/_cat/indices?v

# Index a single document into a "logs" index
curl -X POST http://localhost:9200/logs/_doc \
  -H 'Content-Type: application/json' \
  -d '{"src_ip":"10.0.0.5","event":"login_failed"}'

# Search an index with a query DSL request
curl -X GET http://localhost:9200/logs/_search \
  -H 'Content-Type: application/json' \
  -d '{"query":{"match":{"event":"login_failed"}}}'
```

### Shipping logs with Beats

```bash
# Filebeat ships log files (and has prebuilt modules for Suricata, Zeek, etc.)
sudo filebeat modules enable suricata
sudo filebeat setup            # loads index templates and Kibana dashboards
sudo systemctl start filebeat
```

## Notes & references

- **Licensing matters:** the default distribution ships under the free **Basic**
  tier (search, dashboards, and a usable feature set), but parts of *SIEM /
  Security*, machine learning, and advanced alerting are **licensed** (Platinum/
  Enterprise). The Apache-2.0 **OpenSearch** fork is a fully-open alternative
  used by tools like [Arkime](../network-analysis/arkime.md).
- Explore data in Kibana via **Discover**; build detections in the **Security**
  app; write queries in KQL or the Query DSL.
- Common sources into the stack: [Suricata](suricata.md) `eve.json`,
  [Zeek](../network-analysis/zeek.md) logs, [Wazuh](wazuh.md) alerts,
  [Sysmon](sysmon.md) via Winlogbeat, and [osquery](osquery.md) results.
- [Sigma](sigma.md) rules convert cleanly to Elasticsearch/Kibana queries, so
  you can deploy vendor-neutral detections here.
- Docs: https://www.elastic.co/guide/ ; OpenSearch: https://opensearch.org/
