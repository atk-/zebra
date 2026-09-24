# zebra — TODO & roadmap

Missing capabilities and a checklist toward a complete tool. Roughly ordered by
value-to-effort. See `DESIGN.md` for the seams these build on.

## Legend
- [ ] not started · [~] partial / stubbed · [x] done

---

## Core coverage & masks
- [x] Exact per-mask keyspace + union coverage engine (`services/coverage.py`)
- [x] Redundancy/overlap warning when planning a mask (+ overlap % "X of Y (Z%)")
- [x] Coverage-by-length dashboard (scientific >12 digits; per-length remaining ETA)
- [x] **Grand-total / cross-length coverage summary** (headline "N candidates
      covered", campaign progress) above the per-length rows
- [ ] **Visualize remaining vs. covered** more richly (per-length stacked bars,
      log-scale option — keyspaces span many orders of magnitude). Per-length
      search-space decomposition viz exists; a cross-length rollup chart does not.
- [x] **Suggest uncovered mask boxes** for a given length ("Fill gaps"): exact
      complement of the tried region within the universe, rendered as masks
      (`coverage.complement_boxes`/`merge_boxes`/`render_box` →
      `coverage_helpers.project_complement_masks` → `complement.json` + per-length
      modal). Compact (custom-charset) or builtin-only; exact-under-a-cap; "Queue
      all gaps"; excludes exhausted+planned/queued.
- [x] Support **`--increment`** variable-length masks (expand to length-prefixes):
      recorded, launchable, coverage per swept length, recommender-aware
- [~] Handle **`?b`/binary and non-printable** universes in the UI: added `?b`
      (any byte) and `?c` (perfect complement of `?a`, backed by
      `b_complement.hcchr`); dashboard clamps remaining≥0 / coverage≤100%. Still
      deferred: the underlying universe/keyspace mismatch (covered can exceed the
      universe total) is only papered over for display.
- [ ] Cache coverage results (invalidate on mask add) for large projects

## Runs (make executions first-class)
- [x] `Run` model surfaced: recording an attack creates a `Run` (mask + targeted
      hashtype's hashes + device + status)
- [x] Coverage/redundancy driven off **exhausted** runs (`covered_masks`); planned
      etc. don't count
- [x] Dashboard **Attacks** table (mask, status, hashtype, #hashes, cracks, keyspace, when)
- [~] Edit/delete a run: **delete** exists; crash/rogue-run recovery is its own
      feature (see Hashcat integration below). Edit / re-open an exhausted run still open
- [~] Capture real **wall-clock/speed** on a run: launcher fills `speed_hs` /
      timing from `--status-json`; manual entry from the UI still open
- [x] Per-run cracked-plaintext drill-down (run detail lists this run's cracks)
- [x] Live run progress via AJAX polling (no full-page reload) + incremental
      "(X/Y runs)" sweep counter

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
- [x] `--status-json` parsing wired to update a specific `Run` live in the UI
- [~] **Run benchmarks from the UI**: "Run benchmark" button + manual entry, stored
      on `Project.benchmark_hs` and used for run-time estimates. Still open:
      persisting historical `Benchmark` rows (per hashtype/device)
- [x] **Active launcher, first cut** (`services/launcher.py`): run a **mask** attack
      from its page in a background thread; live progress; final status + crack import
- [x] **Attack queue / playbook**: queue planned mask runs and chain them sequentially
      unattended (auto-start next on finish), machine-wide, with cumulative ETA,
      reorder, remove (`/zebra/queue/`). Distinct from the worker/queue item below
      (this is in-process sequential, not RQ/Celery).
- [x] **Queue master switch (Off / On / Auto)** in the header (`Settings.queue_mode`):
      Off pauses, On runs queued attacks, **Auto** keeps the queue full via
      `autopilot.py` (records the top recommender suggestion sized to
      `Settings.auto_task_seconds`) — set on the Settings page.
- [x] **Optimized kernels (`-O`)** default per run, with a per-attack toggle
      (`Run.optimized`) so runtimes match the `-O` benchmark.
- [x] **Smart `--increment`**: auto-raise `--increment-min` past leading lengths
      already fully covered/queued (`coverage_helpers.evaluate_candidate`).
- [ ] Launch **wordlist/combinator/hybrid** attacks (needs `Wordlist`/`RuleSet` paths
      validated on disk)

- [x] **Crash / rogue-process recovery**: runs are spawned detached (survive a zebra
      restart) with a persistent potfile + `--session`/`--restore-file-path`. Lost
      contact is recovered by adopting a live orphan (potfile-tail watcher) or, for a
      dead one, a **Resume from checkpoint** button (`hashcat --restore`). See
      `services/launcher.py` (`reconcile_stale_runs`/`adopt_live_orphans`/`_adopt`/
      `resume_run`) and `DESIGN.md` §6b.
- [ ] **Worker/queue** (RQ/Celery) so runs can run in parallel (survival + recovery
      now handled above; a real queue would add parallelism/robustness).
- [x] **Global Settings page** (`/settings/`): override the hashcat binary path,
      overriding any copy on `PATH` (`Settings` singleton → `hashcat.configured_runner`)
- [x] File **upload** for hashlists (New project + Add hashes; combines with paste)
- [ ] File **upload** for potfiles / `--status-json` on the import page (paste-only)
- [ ] Detect/validate hashtype of pasted hashes (length/format heuristics)

## Recommender (budget-based suggester shipped; corpus/queue deferred)
- [x] `services/recommend.py`: suggest masks fitting a time budget, prefer zero
      overlap, span applicable lengths, plus a `--increment` "sweep" option
- [x] Filter recommendations by **time budget** using the project benchmark
      (`target = speed × time`); exclude covered/subsumed (100%-overlap) masks
- [ ] Import a mask/keyspace corpus (Hashcat `masks/*.hcmask` and/or PACK maskgen)
      to rank by real-world hit-probability (current ranking is budget + novelty)
- [ ] Present a **queue** with estimated runtime + cumulative hit probability
- [ ] Mask families / rotations generator (e.g. one digit floating through letter
      positions), per the original design notes

## Data model & scope
- [x] **One hash type per project** (`Project.hashtype`); hashes/attacks inherit it;
      coverage scope is per (project, length)
- [x] **Hybrid hash source**: DB-backed (ingested `Hash` rows) OR file-backed
      (`Project.hashfile_path` → external file, read zero-copy; cracks via a
      persistent per-project potfile, no `Crack` rows) for millions-of-hashes lists.
      Line-counted once (`services/hashfile.py`); see `DESIGN.md` §4a
- [ ] **Case / superproject** layer grouping related projects (e.g. all hash types
      from one AD dump) for an engagement-level rollup
- [ ] Per-project **wildcard/charset scoping** (wildcards are currently global)
- [ ] Add `hashcat_module` **uniqueness** constraint on `HashType` (seeded 1:1 today)

## UI / UX
- [x] Create project + hashlist, hashtype dropdown
- [x] Add a hashlist (any hashtype) to an existing project; duplicates skipped
- [x] Masks-tried / Attacks list on the dashboard
- [x] Breadcrumb trail from a project back to the dashboard
- [x] **Record & run** in one click: from the recommender popup or the Evaluate
      panel, record a mask attack and launch it, landing on the live run page
      (mask mode + hashcat only; non-mask degrades to plain record)
- [x] **Delete a project** from the UI, behind a strict typed-confirmation page
      (removes zebra-managed potfiles/hashfiles/checkpoints); **delete a run** too.
- [ ] **Edit** projects, masks, hashes from the UI, and delete masks/hashes
      (admin-only today)
- [ ] Mask **input validation feedback** inline (live keyspace as you type)
      (Evaluate button gives keyspace/overlap/runtime on submit; not yet live)
- [ ] Pagination / search for large hashlists and mask lists
- [ ] Show cracked plaintexts on the dashboard (join `Crack`)
- [ ] Copy-to-clipboard for generated commands

## Quality, ops, packaging
- [x] Tests for **views** (record/evaluate, benchmark, recommend, run status/launch)
- [x] Tests for `services/hashcat.py` parsers and `coverage_helpers.py`
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
- [x] Time/cost estimates per candidate next-run given hardware (Evaluate runtime,
      recommender ETAs, per-length + grand-total remaining ETA)
