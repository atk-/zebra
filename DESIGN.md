# zebra — design & architecture

This document records the architectural and design decisions behind zebra and the
reasoning for them. For a high-level overview see `CLAUDE.md`; for planned work see
`TODO.md`.

## 1. Goals and scope

- **Primary value:** exact coverage/overlap math over Hashcat mask keyspace, so a
  user can see what's been tried, what's left, and whether a new mask is redundant —
  before spending GPU time on it.
- **Secondary value:** ordinary campaign bookkeeping (projects, hashlists, cracked
  results) with as little ceremony as possible.
- **Now also built (were once out of scope):** an active launcher that runs and
  manages mask jobs — a machine-wide sequential queue with an Off/On/Auto master
  switch, autopilot, and crash recovery (§6b/§6c) — and a budget-based next-mask
  recommender plus an untried-region "fill gaps" generator (§3/§7).
- **Still out of scope:** multi-user/auth, a real worker/queue (RQ/Celery) for
  parallelism, distributed cracking (see `TODO.md`).

## 2. Key decisions

### 2.1 Hybrid Hashcat integration (reads + an active launcher)
`services/hashcat.py` stays a thin, read-only wrapper (benchmarks, keyspace
cross-check, result-import parsers) and the app still works with no `hashcat` binary
(manual data entry). The **active launcher** that actually runs jobs is a separate
module, `services/launcher.py` (§6b/§6c) — it builds argv via
`HashcatRunner.build_run_args`, so `hashcat.py` itself never spawns a process.

### 2.2 Exact coverage from day one (atom decomposition)
We compute *exact* union coverage rather than approximations. This is tractable
because of the structure of the problem (see §3). The alternative — tracking only
per-mask keyspace and hand-waving overlap — was rejected because overlap is exactly
the thing a spreadsheet can't do and the reason zebra exists.

### 2.3 Pure engine, DB-aware glue
`services/coverage.py` has **no Django imports**: it operates on plain data
(strings, sets, ints) and is unit-tested with `SimpleTestCase` (no database). All
persistence/ORM concerns live in `coverage_helpers.py`. This keeps the interesting
math fast to test and easy to reason about.

### 2.4 Big-integer arithmetic
Mask keyspaces routinely exceed 2⁶³. All engine arithmetic uses native Python
`int`; cached DB values use `DecimalField(max_digits=80, decimal_places=0)`. Django
`BigIntegerField` is deliberately avoided.

### 2.5 `--keyspace` is not the candidate count
For attack mode 3, `hashcat --keyspace` returns a host-side chunking value (product
of all charsets except the innermost), not the number of candidates. zebra therefore
treats its own product as authoritative for coverage and uses `--keyspace` only for
Hashcat-terms runtime estimates. This is verified against the real binary
(`?d?d?d` → `--keyspace` 100 vs. candidate count 1000).

### 2.6 Server-rendered UI, no build step
Plain Django templates with a small inline theme in `base.html` (CSS custom
properties, no external CDN, no JS framework, no bundler). The tool is a
local/single-operator utility; a SPA would be overhead. Coverage bars are CSS
widths. The only JavaScript is a ~50-line vanilla combobox in `base.html` that
progressively enhances the hashtype picker (`templates/zebra/_hashtype_combobox.html`)
so 590 options are filterable by name or module number; it submits the chosen pk via
a hidden field.

### 2.7 uv + Python 3.12 + latest stable Django
The project was migrated off a broken Python 3.8 virtualenvwrapper env to a
uv-managed `.venv` (`pyproject.toml` + `uv.lock`), Python 3.12, Django 6.1. uv gives
reproducible, lockfile-based environments and removes manual `PYTHONPATH` juggling.

### 2.8 Hashtypes seeded as reference data
All 590 Hashcat modules are bundled in-app (`data/hashtypes.tsv`) and loaded by an
idempotent data migration (`0006_seed_hashtypes`), keyed on `hashcat_module` via
`update_or_create`, so fresh databases are seeded automatically on `migrate`. A
`seed_hashtypes` management command re-seeds when Hashcat's list grows. The
new-project form uses a **dropdown of existing hashtypes** (a deliberate choice — see
§6).

## 3. The coverage engine (`services/coverage.py`)

The core idea and why exact is feasible:

1. **Length partitioning.** Candidate sets of different lengths are disjoint (a
   6-char string is never an 8-char string), so masks are grouped by length and each
   length is solved independently.
2. **Boxes.** Within a length *L*, a mask is an *L*-tuple of character sets
   `(S₁,…,S_L)`; its candidate set is the axis-aligned box `S₁ × … × S_L` over the
   character universe.
3. **Atom decomposition.** Partition the character universe into *atoms* — maximal
   groups of characters with identical membership across all sets in play. Every set
   is then exactly a union of atoms, so a position becomes a **bitmask over atoms**
   and any set/intersection size is a sum of integer atom weights.
4. **Exact union volume** via a **disjoint-cell sum**. Over the shared atom
   partition each mask's box is a disjoint union of grid *cells* (one atom per
   position), so the union of all masks is the union of their cell-sets and its
   volume is simply the sum of the **distinct** cells' sizes — overlap is absorbed
   by de-duplicating cells, with no inclusion–exclusion. This is **linear in the
   mask count** (an already-covered mask contributes no new cells); its cost is
   instead bounded by the number of distinct covered cells (≤ (atoms per position)^L).
   Above `UNION_CELL_CAP` (200 000 distinct cells) — reachable only by a long mask
   over a finely-split partition, e.g. an all-`?a` mask of length ≥ 9 — it falls back
   to the older **inclusion–exclusion DFS** (`_union_inclusion_exclusion`), which
   prunes the moment an intersection becomes empty but is 2ⁿ in the mask count.

Public surface:

- `parse_mask(pattern, custom_charsets, wildcard_map) -> [frozenset,…]` — resolves
  Hashcat built-ins (`?l ?u ?d ?s ?a ?b ?h ?H`), custom charsets (`-1..-4`),
  project-defined wildcards, literals, and `??` (literal `?`).
- `mask_keyspace(positions)` — product of per-position sizes.
- `atom_partition(charsets)` — `(weights, bitmasks)`.
- `union_keyspace(masks_same_length)` — exact union size (disjoint-cell sum;
  inclusion–exclusion `_union_inclusion_exclusion` fallback past the cell cap).
- `marginal_keyspace` / `is_subsumed` / `overlap_keyspace` — redundancy checks used
  by the mask-planning UI.
- `coverage_by_length(masks, universe)` — per-length `{covered, total, masks}`.
- `complement_boxes(covered, universe, length)` — the **untried region**
  (`U^length` minus the tried boxes) as a disjoint set of boxes, via orthogonal
  box-subtraction (staircase difference) with a cap-and-drop-smallest bound;
  `merge_boxes` (Quine-McCluskey cube merge) compacts it and `render_box` emits each
  box as a hashcat mask (`?token`/literal, or a `-1..-4` custom charset, never `?c`).
  Powers the "Fill gaps" UI via `coverage_helpers.project_complement_masks`.

**Complexity note.** Union-of-boxes volume is #P-hard in general dimension. The
disjoint-cell sum trades inclusion–exclusion's cost — exponential in the *mask
count* — for one bounded by the covered region's distinct-cell count
(≤ (atoms per position)^L). That is the right trade for zebra: lengths are modest
(~6–12) and masks reuse a few character classes (so the cell count stays small),
whereas the mask count grows without bound as a campaign accumulates work. The
result is memoized per project (`Project.coverage_cache`, keyed by a signature of
the covered masks + universe + wildcards; see `coverage_helpers.project_coverage`),
so it recomputes only when the covered-mask set changes, not on every dashboard
load.

The retained inclusion–exclusion fallback (past `UNION_CELL_CAP`) is still 2ⁿ in
the mask count, so a project that **both** exceeds the cell cap (long masks and/or
many custom charsets) **and** piles up dozens of overlapping masks at that same
length can still be slow. A genuinely better exact method for that corner
(coordinate-compressed sweep / Klee's-measure family) is **deferred** — see TODO.
This is a deliberate, documented trade-off.

## 3b. Similarity engine (`services/similarity.py`)

Non-mask attacks (straight `-a 0`, combinator `-a 1`, hybrids `-a 6`/`-a 7`) have no
computable keyspace, so instead of exact coverage zebra detects **duplicate /
near-duplicate** runs — the same "don't repeat work" value applied to attacks it can
only track, not measure. Like `coverage.py`, this module is **pure and DB-free**
(operates on plain spec dicts) and unit-tested without a database; `run_helpers.py`
is the DB glue (mirroring `coverage_helpers.py`).

- File references are normalized to **basename + lowercase**
  (`/usr/share/wordlists/rockyou.txt` ≡ `rockyou.txt`).
- `signature(spec)` is a canonical dedup key stored on each `Run`.
- `similarity(a, b)` compares only compatible modes and returns
  `{exact, score, reasons}` with per-mode rules: straight — same wordlist(s) with
  equal / subset-or-superset / disjoint rules; combinator — reversed pair or
  same-pair-different-`-j`/`-k`; hybrid — same wordlist different mask, same mask
  different wordlist, or 6↔7 direction swap.
- `find_similar(candidate, existing, threshold)` ranks matches, exact first.

The **mask coverage engine is untouched**: only mode-3 runs carry a `Mask`, so hybrid
masks (stored in `Run.params`) never leak into coverage-by-length.

## 4. Data model (`models.py`)

- **`Project`** — `name` (unique), `description`, **`hashtype` FK** (the one type the
  project targets), `universe` (optional in-scope charset used as the coverage-%
  denominator; falls back to a per-position union when blank). The universe is stored
  as a hashcat charset spec — a preset (`?d`, `?l?u?d`, `?a`) or a custom string that
  may use shorthands (`?l?u?d?s`) or literals — and expanded to characters by
  `coverage.expand_charset` at compute time.
- **`HashType`** — `name` (unique), `hashcat_module`, `comment`. Seeded (§2.8).
- **`Hash`** — `hashstring`, `project` FK, `cracked` (denormalized flag), `comment`.
  Its type is `project.hashtype`.
- **`CharacterSet` / `Wildcard`** — user-definable charsets and mask symbols; the
  engine consumes wildcard symbol→characters maps.
- **`Mask`** — the central object: `project` FK, `pattern`, optional
  `custom_charsets` (JSON), derived `length`, cached `keyspace` (Decimal), and
  optional `increment_min`/`increment_max` (a `--increment` sweep expands to its
  length-prefixes). A mask counts as **covered only when it has an `exhausted` run**
  (see `coverage_helpers.covered_masks`), not merely by existing.
- **`Wordlist` / `RuleSet`** — global reusable references (name, path, optional
  line/rule count) for non-mask attacks; enable usage stats and future hybrid
  keyspace. Identity is the normalized basename.
- **`Run`** — one attack execution: `project` FK (direct link so non-mask runs
  belong to a project — backfilled from `mask.project` in migration 0007), `mask` FK
  (mode-3 only; feeds coverage), `attack_mode` (0/1/3/6/7), `wordlists`/`rules` M2M,
  `params` JSON (combinator order + inline `-j`/`-k`; hybrid mask + charsets),
  `signature` (canonical dedup key), `device`, `optimized` (`-O`, default on),
  generated `command` (its `-m` comes from `project.hashtype`), `status`
  (`planned/queued/running/exhausted/aborted/cracked/error`), `speed_hs`, `progress`,
  live-crack fields (`recovered`, and `crack_baseline`/`crack_range_end` pinpointing
  this run's slice of a shared potfile), `queue_position`, `hashes` M2M, and launch/
  recovery bookkeeping (`pid`, `session`, `potfile_path`, `restore_path` — §6b). Runs
  are M2M to individual hashes (DB-backed only) so new hashes are flagged
  not-yet-covered. `describe()` renders a per-mode one-line spec for the dashboard.
- **`Crack`** — recovered plaintext for a hash (`hash` FK, `plaintext`, `run` FK,
  `found_at`); richer than the bare `cracked` bool, which is kept as a fast flag.
  (File-backed projects skip `Crack` rows — their potfile is the source of truth.)
- **`Benchmark`** — measured `speed_hs` per `hashtype`/`device`; grounds runtime
  estimates and the recommender's budget sizing (`feasible = speed × time_budget`).
- **`Settings`** — a singleton (pk=1, `Settings.load()`): program-wide options
  independent of any project — the hashcat-binary override, the queue master switch
  `queue_mode` (`off`/`on`/`auto`), and `auto_task_seconds` (autopilot task length).

**One hash type per project.** `Project.hashtype` fixes the type (a hashcat run takes
one `-m`); `Hash` and `Run` carry no type of their own and inherit it. Coverage scope
is therefore per **(project, length)**. Multi-type dumps (AD, mixed `/etc/shadow`)
become **one project per type** — cleaner, since fast and slow types deserve separate
coverage/similarity histories. This supersedes the earlier `Hashlist`-grouping idea;
a future **case / superproject** layer can group related projects for an
engagement-level rollup. `Run`↔`Hash` still records which hashes a run targeted (all
current project hashes), so hashes added later are flagged as not-yet-covered — but
only for DB-backed projects (see below).

### 4a. Hybrid hash source (DB-backed **or** file-backed)

The coverage/overlap engine never touches `Hash` (it works purely off masks), and
hashcat only ever needs a flat file — so hashes in the DB are just an intermediate
store on the way to a file. For campaigns of millions of hashes, ingesting one `Hash`
row per line duplicates gigabytes of data (and `_create_hashes` loads every existing
hashstring into memory to dedup). So hash storage is a **per-project choice**, keyed
on one nullable field:

- **`Project.hashfile_path`** — NULL ⇒ **DB-backed** (unchanged: paste/upload → `Hash`
  rows, `Crack` rows, the `cracked` flag). Set ⇒ **file-backed**: the project
  references an on-disk file zebra **never ingests**; hashcat reads it directly
  (zero-copy). A file-backed project may reference a **server-side path** (referenced
  as-is) or an **uploaded file** saved once into `ZEBRA_DATA_DIR/hashfiles/`
  (`Project.hashfile_managed=True`).
- **Counts** route through `Project` methods so call sites don't branch: `hash_count_value()`
  (file-backed → cached `hash_count`, scanned once via `services/hashfile.count_lines`;
  DB → live row count), `cracked_count()`, `has_hashes()`, and `Run.target_count()`.
  The pure, DB-free file work (streamed line counting, path validation, potfile line
  counting with an mtime/size cache) lives in **`services/hashfile.py`** (mirrors the
  `coverage.py` + glue split).
- **Cracks for file-backed projects use a persistent per-project potfile**
  (`Project.resolve_potfile_path()` → `ZEBRA_DATA_DIR/potfiles/project-<pk>.pot`,
  passed to hashcat as `--potfile-path`) as the source of truth — **no `Crack` rows,
  no `cracked` bool**. Cracked count = potfile line count. A persistent potfile also
  makes hashcat auto-skip already-cracked hashes on later runs. DB-backed runs still
  ingest their potfile into `Crack` rows — but they too now write to a **persistent
  per-run potfile** (`ZEBRA_DATA_DIR/potfiles/run-<pk>.pot`, stored on the `Run` and
  kept outside the `workdir` that `rmtree` deletes) so a run orphaned by a restart is
  still tail-able for recovery (§6b); it's removed on a clean finalize. The Run↔Hash
  M2M is **skipped** for file-backed projects (millions of join rows won't scale).
- Backward compatible: existing projects have `hashfile_path IS NULL`, so every method
  takes the DB branch — behavior is identical to before. No data migration.

## 5. Hashcat service (`services/hashcat.py`)

A thin, optional, read-only wrapper (the active launcher lives in `services/launcher.py`,
§6b):

- `HashcatRunner.available()` / `benchmark()` / `keyspace()` / `plan()` /
  `build_run_args()` / `plan_run()` (the latter two build argv the launcher spawns;
  `-O` optimized kernels and `--increment` flags included).
- Pure parsers — `parse_potfile`, `parse_status_json`, `parse_benchmark` — kept
  DB-free and unit-friendly.
- DB-side ingest — `ingest_cracks`, `ingest_status` — import models lazily so the
  parsers remain usable outside a configured Django environment.
- Fails soft when the binary is missing (`HashcatError`), so the app never *requires*
  Hashcat to be installed.

## 6. Notable trade-offs

- **Hashtype selection = dropdown of existing rows.** Chosen for a clean UI; the
  cost is that a database with zero hashtypes can't create a project through the
  form. Mitigated by (a) seeding all 590 modules and (b) the form degrading to an
  "add a hashtype in admin first" notice when none exist.
- **Coverage `total`/`%` needs a `universe`.** Absolute covered counts are always
  meaningful; the percentage needs a denominator. Projects carry an optional
  `universe`; without it the engine uses a per-position fallback, which is honest but
  project-relative.
- **Coverage counts only exhausted runs.** Recording an attack creates a `Run`
  against a chosen hashtype's hashes; `coverage_helpers.covered_masks` selects masks
  with a `status='exhausted'` run, and both `project_coverage` and
  `evaluate_candidate` build on it. Planned/running/aborted/cracked don't count —
  "covered" means "searched to the end". (Consequence: a mask saved without an
  exhausted run does not contribute to coverage.)

## 6b. Active launcher (`services/launcher.py`)

Runs a recorded **mask** attack with hashcat — from the attack page, the queue, or
autopilot (§6c). Mask attacks only (other modes need on-disk wordlist/rule files).

- **Background thread**, not a blocking request: `start_run` spawns hashcat and a
  daemon thread streams `--status-json` into the `Run` (progress/speed via the
  existing `ingest_status`); the request returns immediately and the detail page
  self-refreshes while `running`. The real work lives in a synchronous `_execute`
  (the thread target) so it's unit-testable with a stub binary, without threads or
  cross-thread SQLite.
- **argv, never a shell string** — executes `HashcatRunner.build_run_args(...)`
  as a list, so masks/paths can't inject shell.
- **Guards:** hashcat installed, `attack_mode == 3` only (mask attacks need no
  external files — other modes are a follow-up), project has hashes, and **one run at
  a time** (the GPU is exclusive; refuse if a *live* `Run` is `running`). The
  one-at-a-time check runs `reconcile_stale_runs()` first, which aborts any
  `running` row not backed by a live process (in the in-process registry, or a live
  hashcat pid) — see the self-healing note below.
- **Finalisation** from the exit code via `_final_status` (`0 cracked, 1 exhausted,
  2/3/4 aborted, else error`); cracks are imported from the run's potfile
  (`parse_potfile` → `ingest_cracks`). `Run.pid` + an in-process registry back the
  **Stop** button (SIGINT = hashcat's clean checkpoint-abort).
- **Orphan recovery (restart / lost contact).** A run is spawned **detached**
  (`start_new_session=True`) with a persistent per-run potfile, hashcat `--session`,
  and `--restore-file-path` (all stored on the `Run`), so the process **survives a
  zebra restart and keeps cracking** (verified: a detached child ignores the
  reader's PTY closing). When contact is lost (restart, or a dead reader thread),
  `reconcile_stale_runs()` classifies each untracked `running` row by whether its
  `pid` is *our* hashcat (cmdline must contain both `hashcat` and the run's
  `--session` name, defeating PID reuse):
  - **live** → `_adopt()` it: a watcher thread tails the potfile for the live crack
    count (unambiguous under one-at-a-time; DB-backed also re-ingests to `Crack`
    rows) and finalises when the pid disappears — `aborted` + note, or `cracked`
    if every targeted hash was recovered (no exit code is available, so exhaustion
    is never claimed). Progress/speed can't be recovered without the stream.
  - **dead** → `aborted`, leaving the `--restore` checkpoint on disk so the run
    page offers **Resume from checkpoint** (`resume_run` relaunches `hashcat
    --session <n> --restore`, which replays the original command line and restores
    full live streaming — also works for a run you deliberately Stopped).
  Recovery fires lazily: `adopt_live_orphans()` (non-mutating, GET-safe) on the
  dashboard/queue/run-detail views, and full `reconcile_stale_runs()` on the
  launch/queue action paths. The fully robust fix is still the worker/queue below.

## 6c. Attack queue, master switch, and autopilot (`services/launcher.py`, `autopilot.py`)

A machine-wide, **in-process sequential** queue (the GPU is one exclusive resource):
`enqueue`/`dequeue`/`move` reorder planned mask runs; when the active run finalises,
`_advance_queue` starts the next (lowest `queue_position`). The header **master
switch** (`Settings.queue_mode`) has three states: **off** (don't auto-start —
`is_paused`), **on** (run queued attacks), **auto** (also *fill* an empty queue).
In **auto**, `autopilot.next_auto_run` picks an eligible project (hashtype +
benchmark + hashes) and records the top recommender suggestion sized to
`auto_task_seconds`, so the machine keeps finding new keyspace unattended. This is
distinct from the deferred RQ/Celery worker (§7) — it's a single-process chain, not
parallel or restart-durable on its own (recovery in §6b covers restarts).

## 7. Extensibility seams (designed, not built)

- **Recommender corpus:** the budget-based recommender (`services/recommend.py`) and
  the untried-region "fill gaps" generator (`coverage.complement_boxes`) are **built**;
  still open is ranking by real-world hit-probability from a mask corpus (Hashcat
  `masks/*.hcmask` or PACK) rather than budget + novelty.
- **Launcher, next increments:** launch wordlist/combinator/hybrid attacks (needs
  `Wordlist.path`/`RuleSet.path` validated on disk); a **worker/queue** (RQ/Celery)
  for parallelism (survival + recovery are handled in §6b).

## 8. Testing

- Engine correctness is covered by `tests.py` (`SimpleTestCase`, DB-free): keyspace
  products, subsumption, overlapping/​disjoint unions, inclusion–exclusion, and
  coverage-by-length (explicit and fallback universes).
- End-to-end flows (project creation, mask evaluation/save, redundancy warnings,
  potfile import, dashboard rendering) have been exercised via `django.test.Client`.
- `makemigrations --check` guards against silent model drift.
