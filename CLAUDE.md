# zebra

**zebra** is a password-recovery campaign tracker for Hashcat mask attacks. It
remembers which masks have already been run against a hashlist, computes **exactly**
how much of the candidate keyspace is covered and how much is left (broken down by
password length), and warns before you launch a mask that overlaps work you've
already done.

## The problem it solves

Cracking an unknown password is an iterative campaign: you run mask after mask
(`?u?l?l?l?d?d`, `?a?a?a?a`, …) against a set of hashes. In practice people track
what they've tried in their head, a scratch `.txt`, or a spreadsheet — and end up
re-running overlapping keyspace, losing track of what's exhausted, or mis-judging
what remains. zebra is the memory and the coverage math for that campaign. Its
differentiator over a spreadsheet is **exact coverage/overlap computation** over the
mask keyspace, not just a list of commands.

## What it does today

- **Projects & hashlists** — create a project with a hashlist and hashtype (seeded
  with all 590 Hashcat modules), and add more hashlists (of any hashtype) to an
  existing project at any time; duplicates are skipped.
- **Record attacks** — enter a candidate mask; see its exact keyspace and whether it's
  redundant / partially overlapping / all-new against already-**exhausted** keyspace,
  plus a generated `hashcat` command; record it as a `Run` (mask + targeted
  hashtype's hashes + status).
- **Coverage dashboard** — per password length: candidate space covered (from
  exhausted runs), total, remaining, and % covered; plus an Attacks log.
- **Result import** — paste a Hashcat potfile (`hash:plain`) to mark hashes cracked;
  parse `--status-json` output.

zebra is **hybrid** with respect to Hashcat: it reads from the binary (keyspace
cross-check, benchmarks, result import) but does **not** launch or manage cracking
jobs. The data model and run state machine are shaped so an active launcher can be
added later without rework. See `DESIGN.md`.

## Stack

- Python **3.12**, Django **6.1**, SQLite (dev).
- **uv** for environment/dependency management (`pyproject.toml` + `uv.lock`).
- Single Django app `zebra`, project config in `config/`.

## Layout

```
zebra/                         # git repo root (uv project: pyproject.toml, uv.lock)
  zebra/                       # Django project root (manage.py lives here)
    config/                    # settings, root urlconf, wsgi/asgi
    zebra/                     # the app
      models.py                # Project, HashType, Hash, Mask, Run, Crack, Benchmark, CharacterSet, Wildcard
      services/
        coverage.py            # pure exact-coverage engine (no Django imports)
        hashcat.py             # read-only hashcat wrapper + parsers + ingest
      coverage_helpers.py      # DB-aware glue between models and the engine
      views.py / urls.py       # web UI (index, project_new, project_detail, mask_new, import_results)
      templates/zebra/         # server-rendered templates (theme in base.html)
      management/commands/     # seed_hashtypes
      data/hashtypes.tsv       # bundled Hashcat module list (seed source)
      migrations/              # incl. 0006_seed_hashtypes (data migration)
      tests.py                 # engine unit tests (SimpleTestCase, DB-free)
```

## Running it

All commands go through `uv run` (it uses the project `.venv`, ignoring any active
shell venv):

```bash
uv run python zebra/manage.py migrate          # apply migrations (also seeds hashtypes)
uv run python zebra/manage.py runserver        # dev server -> http://127.0.0.1:8000/zebra/
uv run python zebra/manage.py test zebra       # run the test suite
uv run python zebra/manage.py seed_hashtypes   # re-seed / refresh hashtypes
uv run python zebra/manage.py createsuperuser  # to reach /admin/
```

The main UI is under `/zebra/`; Django admin (CRUD for charsets, wildcards,
hashtypes, etc.) is under `/admin/`.

## Conventions & gotchas

- **Keyspaces are big integers.** Cached keyspace/speed fields are
  `DecimalField(max_digits=80)`; the engine does all math with native Python `int`
  (arbitrary precision). Never use `BigIntegerField` for a keyspace — it overflows.
- **The engine is the source of truth for candidate counts, not `hashcat --keyspace`.**
  For attack mode 3, Hashcat's `--keyspace` returns a host-side *chunking* number
  (product of all-but-the-innermost charset), e.g. `?d?d?d` → 100, whereas the true
  candidate count is 1000. `services/hashcat.py` uses `--keyspace` only for runtime
  estimates, and the code/comments call this out.
- **`services/coverage.py` stays pure** (no Django imports) so it's unit-testable
  without a database; DB-aware logic lives in `coverage_helpers.py`.
- **Hashcat is optional at runtime.** `services/hashcat.py` degrades gracefully when
  the binary is absent so the app works with manual data entry.
