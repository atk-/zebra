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
- **Explicitly out of scope (for now):** launching/managing Hashcat jobs, a
  next-mask recommender, multi-user/auth, distributed cracking. These are designed
  *for* but not *built* (see §7 and `TODO.md`).

## 2. Key decisions

### 2.1 Hybrid Hashcat integration (read-only), launcher-ready
zebra reads from Hashcat (benchmarks, keyspace cross-check, result import) but does
not launch jobs. This gives most of the value at a fraction of the complexity of
process/queue management, and keeps the app usable when Hashcat isn't installed.
The `Run` model already carries the live-run fields (`status`, `progress`,
`speed_hs`, `started_at`/`ended_at`) and `HashcatRunner` exposes `plan()` today with
`launch()`/`poll()` as explicit stubs — so an active launcher is an additive change.

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
4. **Exact union volume** via **inclusion–exclusion** over the masks of a length,
   using a DFS that prunes the moment an intersection becomes empty. Real mask sets
   overlap sparsely, so this runs far below the 2ⁿ worst case. (If a length ever
   accumulates too many mutually overlapping masks, the documented fallback is
   per-axis atom refinement / disjoint-box decomposition.)

Public surface:

- `parse_mask(pattern, custom_charsets, wildcard_map) -> [frozenset,…]` — resolves
  Hashcat built-ins (`?l ?u ?d ?s ?a ?b ?h ?H`), custom charsets (`-1..-4`),
  project-defined wildcards, literals, and `??` (literal `?`).
- `mask_keyspace(positions)` — product of per-position sizes.
- `atom_partition(charsets)` — `(weights, bitmasks)`.
- `union_keyspace(masks_same_length)` — exact union size.
- `marginal_keyspace` / `is_subsumed` / `overlap_keyspace` — redundancy checks used
  by the mask-planning UI.
- `coverage_by_length(masks, universe)` — per-length `{covered, total, masks}`.

**Complexity note.** Union-of-boxes volume is #P-hard in general dimension, but here
dimension = password length (small, ~6–12) and atoms per position are few, so
inclusion–exclusion with pruning is fine in practice. This is a deliberate,
documented trade-off.

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

- **`Project`** — `name` (unique), `description`, `universe` (optional in-scope
  charset used as the coverage-% denominator; falls back to a per-position union
  when blank).
- **`HashType`** — `name` (unique), `hashcat_module`, `comment`. Seeded (§2.8).
- **`Hash`** — `hashstring`, `hashtype` FK, `project` FK, `cracked` (denormalized
  flag), `comment`.
- **`CharacterSet` / `Wildcard`** — user-definable charsets and mask symbols; the
  engine consumes wildcard symbol→characters maps.
- **`Mask`** — the central object: `project` FK, `pattern`, optional
  `custom_charsets` (JSON), derived `length`, cached `keyspace` (Decimal). A mask
  counts as **covered only when it has an `exhausted` run** (see
  `coverage_helpers.covered_masks`), not merely by existing.
- **`Wordlist` / `RuleSet`** — global reusable references (name, path, optional
  line/rule count) for non-mask attacks; enable usage stats and future hybrid
  keyspace. Identity is the normalized basename.
- **`Run`** — one attack execution: `project` FK (direct link so non-mask runs
  belong to a project — backfilled from `mask.project` in migration 0007), `mask` FK
  (mode-3 only; feeds coverage), `attack_mode` (0/1/3/6/7), `wordlists`/`rules` M2M,
  `params` JSON (combinator order + inline `-j`/`-k`; hybrid mask + charsets),
  `signature` (canonical dedup key), `hashtype`, `device`, generated `command`,
  `status` (`planned/running/exhausted/aborted/cracked/error`), `speed_hs`,
  `progress`, timing, `hashes` M2M. Runs are M2M to individual hashes so new hashes
  added to a project are naturally flagged as not-yet-covered. `describe()` renders a
  per-mode one-line spec for the dashboard.
- **`Crack`** — recovered plaintext for a hash (`hash` FK, `plaintext`, `run` FK,
  `found_at`); richer than the bare `cracked` bool, which is kept as a fast flag.
- **`Benchmark`** — measured `speed_hs` per `hashtype`/`device`; grounds runtime
  estimates now and the recommender later (`feasible = speed × time_budget`).

Scope is **per (project, hashtype, length)**; there is intentionally no separate
`Hashlist` model — a project holds its hashes directly and `Run`↔`Hash` answers
"which hashes has this run covered". A `Hashlist` grouping is a possible future
addition.

## 5. Hashcat service (`services/hashcat.py`)

A thin, optional, read-only wrapper:

- `HashcatRunner.available()` / `benchmark()` / `keyspace()` / `plan()`, with
  `launch()`/`poll()` reserved for the future active launcher.
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

## 7. Extensibility seams (designed, not built)

- **Recommender** (`services/recommend.py`, future): rank uncovered masks by
  hit-probability from a corpus (Hashcat `masks/*.hcmask` or PACK), filter by
  `Benchmark`-derived time budget, exclude covered/subsumed masks.
- **Active launcher:** the `Run` status/progress/speed fields and the
  `HashcatRunner.launch/poll` stubs are the only hooks needed.

## 8. Testing

- Engine correctness is covered by `tests.py` (`SimpleTestCase`, DB-free): keyspace
  products, subsumption, overlapping/​disjoint unions, inclusion–exclusion, and
  coverage-by-length (explicit and fallback universes).
- End-to-end flows (project creation, mask evaluation/save, redundancy warnings,
  potfile import, dashboard rendering) have been exercised via `django.test.Client`.
- `makemigrations --check` guards against silent model drift.
