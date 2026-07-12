# Timesketch

> A web-based, collaborative timeline analysis platform: load super-timelines from
> multiple sources, search and filter across millions of events, tag and comment
> findings, and let a whole team investigate the same case at once.

- **Link:** https://github.com/google/timesketch
- **Type:** open source (by Google)
- **Platform:** Linux server (web UI; Docker deployment)

## Description

A single analyst can work a CSV timeline in a spreadsheet, but a team investigating
a large incident needs something shared and searchable. Timesketch ingests
timelines — most commonly [Plaso](plaso-timeline.md) storage files, but also CSV
and JSONL — into an OpenSearch backend and presents them in a browser. Analysts
run structured queries, build saved views, annotate events with **tags, stars, and
comments**, draw the story together in the timeline canvas, and run **analyzers**
that automatically flag things like browser artifacts, logins, and known-bad
indicators. It's the collaboration and correlation layer on top of the raw
timeline data.

## Installation

```bash
# Recommended: the official Docker Compose deployment
git clone https://github.com/google/timesketch.git
cd timesketch/docker/release
docker compose up -d

# Create the first user (interactive) after the stack is up
docker compose exec timesketch-web tsctl create-user admin
```

## Typical workflow

1. **Deploy** the Docker stack and create a user; open the web UI and create a new
   **sketch** for the case.
2. **Ingest timelines** — upload a [Plaso](plaso-timeline.md) file or CSV/JSONL
   (via the UI or the `timesketch_importer` CLI); each source becomes a timeline in
   the sketch.
3. **Search & filter** — query with the Lucene-style search bar and time ranges,
   save useful queries as **views**, and pivot around the incident window.
4. **Annotate** — star key events, apply tags, and add comments so the team builds
   a shared narrative; run **analyzers** to auto-surface artifacts.
5. **Correlate & report** — combine multiple hosts/sources in one sketch, use the
   graph/aggregation features, and export the findings.

## Notes & references

- The `timesketch_importer` CLI is the easy way to push data from another box:
  `timesketch_importer -u user -p pass --host https://... timeline.plaso`.
- Ingesting huge Plaso files is resource-heavy — size the OpenSearch backend
  accordingly and scope the timeline (see [Plaso](plaso-timeline.md) filtering).
- Feed it output from [Hayabusa](hayabusa.md), [Plaso](plaso-timeline.md), and
  other CSV-producing tools to correlate log, disk, and memory events in one view.
- Docs and analyzer list: https://timesketch.org
