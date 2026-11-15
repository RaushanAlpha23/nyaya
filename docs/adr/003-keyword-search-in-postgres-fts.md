# ADR 003: Keyword search uses Postgres full-text search, not Elasticsearch

- Status: PROPOSED (draft by assistant; rewrite in my own words before marking Accepted)
- Date: 2026-11-09
- Milestone: decided in M1, built in M4
- Changes: brief sections 4, 5 (stage 13), 7 (`keyword_search`), 10 and 14.

## Context

The brief's hybrid retrieval is Qdrant dense vectors plus Elasticsearch BM25, merged with
reciprocal rank fusion (RRF) and reranked. The keyword half exists for exact terms: clause
numbers like "Exclusion 4.2", defined terms and product names, where dense vectors are weak.

Elasticsearch needs about 1 GB of RAM by the brief's own estimate and is one more service to
run and host. My machine is a laptop, my stores are cloud-hosted (Supabase, Qdrant Cloud,
Atlas), and nothing free hosts Elasticsearch comfortably.

## Decision

- The keyword half runs in Postgres full-text search: a `tsvector` column on the chunks table
  with a GIN index. This table is created in M4, so M1 is unaffected.
- Clause lookup by ID or section number is a plain SQL query on the clause tree, not a search.
- Merging is unchanged: RRF in the app layer, then the cross-encoder reranker.
- One ablation compares three setups on the same labelled set: dense only, dense plus Postgres
  full-text search, and dense plus Qdrant sparse vectors. The numbers pick the final design.
- The tool name `keyword_search` stays; only its backend changes.

## Alternatives considered

| Option | Why not (now) |
|---|---|
| Elasticsearch | True BM25 and mature analyzers, but RAM-heavy, an extra service, and no good free hosting. |
| Qdrant sparse vectors only | One store instead of two, but needs a sparse encoder and I have not verified the current API. Kept as an ablation arm. |
| Postgres extension for BM25 | Not evaluated; availability on Supabase is unchecked. |
| `pg_trgm` | Useful for typo-tolerant clause IDs, not for ranking text. May be added later for IDs. |

## Consequences

Good:
- No new service. Roughly 1 GB of RAM saved.
- Chunks, clause tree and keyword index live in one database, so version filters, tenant
  filters and deletes of stale chunks are ordinary SQL and use the existing repository layer.
- The Elasticsearch isolation test disappears; the Qdrant payload-filter test stays.

Costs and risks:
- `ts_rank` is **not BM25**. I must call this "keyword search" and never "BM25" in the README or
  in interviews.
- Default text-search configurations stem words and may mangle tokens such as "4.2". Mitigation to
  test in M4: keep a second `simple` (no stemming) column for identifiers, and rely on exact
  clause lookup for numbers.
- Ranking quality on long legal text is unmeasured. The ablation exists to measure it.
- "Elasticsearch" can no longer be listed as a built skill. It can come back as an optional
  Compose profile with a documented ablation; do not claim it before then.

## Revisit when

- The ablation shows the keyword half is the retrieval bottleneck: add an Elasticsearch profile
  and compare.
- Corpus size makes Postgres full-text queries slow (measure first).

## To verify in M4

- Qdrant sparse-vector and fusion API, against current docs.
- Postgres text-search configuration and ranking behaviour on real clause text.
