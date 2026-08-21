# zebra — TODO & roadmap

Missing capabilities and a checklist toward a complete tool. Roughly ordered by
value-to-effort. See `DESIGN.md` for the seams these build on.

## Legend
- [ ] not started · [~] partial / stubbed · [x] done

---

## Core coverage & masks
- [x] Exact per-mask keyspace + union coverage engine (`services/coverage.py`)
- [x] Redundancy/overlap warning when planning a mask
- [x] Coverage-by-length dashboard
- [ ] **Grand-total / cross-length coverage summary** (headline "N candidates
      covered", campaign progress) rather than only per-length rows
- [ ] **Visualize remaining vs. covered** more richly (per-length stacked bars,
      log-scale option — keyspaces span many orders of magnitude)
- [ ] **Suggest uncovered mask boxes** for a given length (decompose the uncovered
      region into candidate masks) — precursor to the recommender
- [ ] Support **`--increment`** style variable-length masks (expand to fixed lengths)
- [ ] Handle **`?b`/binary and non-printable** universes in the UI gracefully
- [ ] Cache coverage results (invalidate on mask add) for large projects

## Runs (make executions first-class)
- [x] `Run` model surfaced: recording an attack creates a `Run` (mask + targeted
      hashtype's hashes + device + status)
- [x] Coverage/redundancy driven off **exhausted** runs (`covered_masks`); planned
      etc. don't count
- [x] Dashboard **Attacks** table (mask, status, hashtype, #hashes, cracks, keyspace, when)
- [ ] Edit/delete a run; re-open an exhausted run
- [ ] Capture real **wall-clock/speed** on a run (timing fields exist, not filled from UI)
- [ ] Per-run cracked-plaintext drill-down

## Non-mask attack types (wordlist / combinator / rules / hybrid)
- [x] Record straight (`-a 0`, +rule files), combinator (`-a 1`), hybrids (`-a 6/7`)
- [x] First-class `Wordlist` / `RuleSet` refs (basename identity), admin CRUD
- [x] Similarity engine (`services/similarity.py`) — duplicate / near-duplicate
      detection (subset rules, reversed combinator, hybrid direction swap)
- [x] Attacks table shows type + spec across all modes
- [ ] **Hybrid keyspace** from `Wordlist.line_count` (× mask keyspace) — fields exist
- [ ] Multiple wordlists per straight run (model supports M2M; form takes one)
- [ ] Wordlist/RuleSet **usage stats** ("rockyou used in N runs") + management page
- [ ] Capture wordlist `line_count` / rule `rule_count` (from file or hashcat)
- [ ] Similarity threshold / weighting tuning; expose "why" more prominently

## Hashcat integration
- [x] Read-only wrapper: `benchmark`, `keyspace`, `plan`, potfile/status parsers
- [x] Import potfile → mark cracked + create `Crack` rows
- [~] `--status-json` parsing exists; **wire it to update a specific `Run`** in the UI
- [ ] **Run benchmarks from the UI** and persist `Benchmark` rows (currently no view)
- [ ] **Active launcher** (`HashcatRunner.launch/poll`): spawn/manage jobs, stream
      `--status-json`, auto-ingest cracks. Needs a background worker (RQ/Celery or a
      status-file watcher) — the biggest single feature
- [ ] File **upload** for potfiles/hashlists (currently paste-only)
- [ ] Detect/validate hashtype of pasted hashes (length/format heuristics)

## Recommender (deferred, seams in place)
- [ ] `services/recommend.py`: rank uncovered masks by hit-probability
- [ ] Import a mask/keyspace corpus (Hashcat `masks/*.hcmask` and/or PACK maskgen)
- [ ] Filter recommendations by **time budget** using `Benchmark` speeds
      (`feasible = speed × time`) and exclude covered/subsumed masks
- [ ] Present a **queue** with estimated runtime + cumulative hit probability
- [ ] Mask families / rotations generator (e.g. one digit floating through letter
      positions), per the original design notes

## Data model & scope
- [ ] Optional **`Hashlist`** grouping within a project (multiple hashlists / types)
- [ ] Per-project **wildcard/charset scoping** (wildcards are currently global)
- [ ] Track **wordlist + rules** attacks (attack modes 0/6/7), not just masks
- [ ] Add `hashcat_module` **uniqueness** constraint on `HashType` (seeded 1:1 today)

## UI / UX
- [x] Create project + hashlist, hashtype dropdown
- [x] Add a hashlist (any hashtype) to an existing project; duplicates skipped
- [x] Masks-tried list on the dashboard
- [ ] **Edit/delete** projects, masks, hashes from the UI (admin-only today)
- [ ] Mask **input validation feedback** inline (live keyspace as you type)
- [ ] Pagination / search for large hashlists and mask lists
- [ ] Show cracked plaintexts on the dashboard (join `Crack`)
- [ ] Copy-to-clipboard for generated commands

## Quality, ops, packaging
- [ ] Tests for **views** (currently engine-only in `tests.py`; E2E done ad-hoc)
- [ ] Tests for `services/hashcat.py` parsers and `coverage_helpers.py`
- [ ] CI (GitHub Actions): `uv run … test`, `makemigrations --check`, lint
- [ ] Linting/formatting config (ruff) in `pyproject.toml`
- [ ] Production settings: real `SECRET_KEY`, `DEBUG=False`, `ALLOWED_HOSTS`,
      static-files handling (dev settings only today)
- [ ] Remove the obsolete `~/.env/zebra` virtualenv (superseded by uv `.venv`)
- [ ] README with quickstart (currently `CLAUDE.md` covers running it)
- [ ] Decide on committing `db.sqlite3` vs. relying on migrations (now gitignored)

## Nice-to-have
- [ ] Export a campaign report (masks tried, coverage, cracks) as HTML/CSV
- [ ] Multi-user / auth if used by a team
- [ ] Time/cost estimates per candidate next-run given hardware
