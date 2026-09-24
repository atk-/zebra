# Code review findings

Reviewed 2026-09-24. Scope: application models, views, services, template call sites, configuration, and existing tests. No application code was changed.

Validation: all **262 existing tests passed** using `uv run python zebra/manage.py test zebra --noinput`. The test run also emitted ignored `Bad file descriptor` finalizer exceptions. Additional targeted checks used an isolated in-memory database, temporary files, and mocked process launches; they did not use the application database or launch GPU attacks. Findings labelled “reproduced” were checked this way. Other findings follow directly from the indicated control flow; actual Hashcat restart/resume behavior was not integration-tested.

Priority: **P1** = incorrect campaign state, lost recovery/data, or broken execution exclusivity; **P2** = other correctness or availability problems.

## 1. [P1] The launch guard does not reserve the execution slot

**Locations:** `zebra/zebra/services/launcher.py:134`, `:170`, `:522`.

`start_run()` releases `_lock` immediately after checking for running rows, then prepares files before saving `status='running'`. Another request can pass the same check in that interval. `resume_run()` has the same separation. The lock is also process-local, so it cannot coordinate multiple server workers. There is a further interval between saving a running row and registering its PID where reconciliation can incorrectly abort that row.

**Reproduced:** interleaving a second launch during the first call's `launch_hashfile()` produced two successful launch results, two spawn calls, and two running rows. This violates GPU exclusivity and the shared-potfile attribution assumption.

**Suggested fix:** atomically claim a machine-wide execution slot before preparing/spawning, distinguish starting from orphaned runs, and release the claim on failure.

## 2. [P1] Normal abort finalization deletes the checkpoint needed to resume

**Locations:** `zebra/zebra/services/launcher.py:281`, `:296`, `:303`.

`_execute()` calls `_cleanup_run_files()` after every normal process exit, including aborted exits. That removes the restore file, and its `finally` block always deletes the working directory, including a DB-backed run's materialized hashfile. Even exception paths that retain the restore file discard its input directory.

**Reproduced:** a simulated exit code 2 left the run `aborted`, with both its checkpoint and working directory deleted. Consequently, a stopped run loses the resume option; preserving only the checkpoint on other paths is insufficient when its original input files have disappeared.

**Suggested fix:** retain the checkpoint, input files, and required execution directory while a run remains resumable; clean them only after completion or explicit abandonment.

## 3. [P1] Deleting a running attack or project leaves its process running

**Locations:** `zebra/zebra/views.py:524`, `:574`.

Both deletion handlers remove recovery files and database rows without checking for or stopping live processes. The attack delete form is available on the detail page. Once the running row disappears, the launch guard permits a second attack, while the original process continues untracked. Its reader also attempts to update deleted rows, and removing its potfile/checkpoint can destroy recovery data.

**Suggested fix:** reject deletion while starting/running, or explicitly stop and wait for finalization before removing rows and files. Apply the same rule to project cascades.

## 4. [P1] Changing the hashlist leaves old coverage valid for new targets

**Locations:** `zebra/zebra/views.py:672`, `zebra/zebra/coverage_helpers.py:61`, `:78`, `zebra/zebra/models.py:375`.

Adding DB-backed hashes or replacing a file-backed hashlist does not invalidate prior coverage or recommendations. Coverage is selected solely by project and run status, ignoring which hashes were actually targeted. For example, exhaust `?d` for hash A, then add hash B: `?d` remains fully covered and excluded from suggestions even though B was never attacked. Replacing a file also preserves the previous file's potfile counts. DB-backed run snapshots exist but are not consulted by coverage; execution materializes the current project list instead of the snapshot.

**Suggested fix:** version target lists and associate coverage, execution inputs, and recovery counts with a target version, or explicitly reset campaign state when targets change.

## 5. [P1] Stopping an orphan releases the slot before the process exits

**Location:** `zebra/zebra/services/launcher.py:483`.

When a run is not in `_active` (including adopted runs), `stop_run()` sends SIGINT and immediately marks it aborted and clears its PID. A signal request is not proof of process exit, so another attack can start while the old one is still running. Its adopter may continue writing counts against the same potfile. The PID check here also omits the session argument used by other recovery paths, allowing a reused PID belonging to another Hashcat session to be signalled.

**Suggested fix:** verify the session identity and keep the execution slot occupied until process exit is confirmed; coordinate stopping with the adopter.

## 6. [P2] Adopted file-backed runs subtract the crack baseline twice

**Locations:** `zebra/zebra/services/launcher.py:410`, `:419`, `:439`; `zebra/zebra/models.py:118`, `:393`.

Normal file-backed execution stores cumulative recovered counts. Adoption instead stores `potfile_count - crack_baseline`, while `Run.crack_count()` subtracts the baseline again and project displays expect a cumulative count. Finalization also compares this delta with the full target count.

**Reproduced:** three recovered hashes with a baseline of two produced `recovered=1`, a live run count of zero, and a project count of one. Finalization marked the fully recovered three-hash project `aborted` instead of `cracked`.

**Suggested fix:** preserve cumulative `recovered` semantics throughout adoption and calculate the per-run delta only when displaying attribution.

## 7. [P2] Auto mode keeps selecting fully cracked projects

**Location:** `zebra/zebra/autopilot.py:22`.

Eligibility only checks for a hash type, benchmark, and presence of hashes. It does not exclude projects whose targets are all cracked. A completed project remains eligible and, because recent activity is prioritized, can repeatedly receive new attacks ahead of unfinished projects. DB-backed runs use separate potfiles, so they can also repeat recovery work already committed to the database.

**Reproduced:** a project containing only a hash with `cracked=True` was returned by `_eligible_projects()`.

**Suggested fix:** exclude completed projects and ensure DB-backed launches reuse known recoveries or target only unresolved hashes.

## 8. [P2] Custom charset collisions cause “Queue all” to skip untried masks

**Locations:** `zebra/zebra/services/similarity.py:61`, `zebra/zebra/views.py:1095`.

Mode-3 signatures include the mask text and increment bounds but omit custom charset definitions. “Queue all” uses that signature as an exact-duplicate gate, although `?1` with `1=ab` and `?1` with `1=cd` are disjoint attacks.

**Reproduced:** for universe `abcd`, recording `?1` with `1=ab` leaves the complement `?1` with `1=cd`. Queueing that complement returned `queued=0, skipped=1`.

**Suggested fix:** include canonical custom charset definitions in mask signatures and update all signature producers and existing stored signatures.

## 9. [P2] SQLite rounds supposedly exact cached keyspaces

**Locations:** `zebra/zebra/models.py:231`, `:61`, `:324`, `:502`; `zebra/config/settings.py` database configuration.

The configured SQLite backend does not preserve arbitrary-precision integers merely because the Django field is `DecimalField(max_digits=80)`. Large values round during persistence. Cached keyspace displays and queue estimates therefore disagree with the exact Python engine; larger benchmark/speed values have the same storage risk.

**Reproduced:** saving and reloading the keyspace of `?a` repeated 12 times changed `540360087662636962890625` into `540360087662637000000000`.

**Suggested fix:** use exact integer text storage with explicit conversion, or a database representation that actually preserves these values, and recalculate cached values after migration.

## 10. [P2] Out-of-universe work is counted as coverage inside the universe

**Locations:** `zebra/zebra/services/coverage.py:257`, `zebra/zebra/coverage_helpers.py:88`.

Coverage computes the union of complete masks but divides by the project universe size. The display clamps the result instead of clipping masks to the universe. This is already acknowledged in `TODO.md`, but it gives materially incorrect campaign results.

**Reproduced:** universe `?d` with exhausted mask `?l` returns covered 26, total 10, and displays 100% coverage with zero remaining, although none of the ten digits was searched. The complement engine correctly still finds all ten digits, so the two features disagree.

**Suggested fix:** intersect each mask position with the universe for in-scope coverage, and report out-of-scope work separately if desired.

## 11. [P2] Complement rendering can recurse forever on whitespace/nonprintable positions

**Location:** `zebra/zebra/services/coverage.py:661`.

When a box needs more than four custom charsets, `_render_box()` splits its first custom position. A singleton space or nonprintable character remains a custom position after `_split_builtin_pieces()` returns that identical singleton, so recursion makes no progress.

**Reproduced:** `render_box([frozenset(' '), frozenset('ab'), frozenset('cd'), frozenset('ef'), frozenset('gh')])` raises `RecursionError`. These boxes are representable using the existing splitting strategy if a genuinely splittable position is chosen.

**Suggested fix:** select a position whose split reduces custom charset requirements and explicitly handle unsplittable positions.

## 12. [P2] Coverage/complement size caps are applied after unbounded expansion

**Locations:** `zebra/zebra/services/coverage.py:394`, `:596`; `zebra/zebra/coverage_helpers.py:267`.

The decomposition enumerates a mask's entire Cartesian product before checking `cell_cap`. A broad mask partitioned into four atoms at each of 16 positions can allocate up to `4**16` cells despite the 20,000-cell cap. Similarly, builtin complement expansion builds the full product before the 200-mask display cap is applied; an alphanumeric box can expand to `3**L` boxes.

**Suggested fix:** check limits inside enumeration, stream expansion, and calculate omitted volumes without constructing every omitted cell or mask. Add bounded-work tests using a high-dimensional input.

## 13. [P2] Inclusion-exclusion scales exponentially even for redundant masks

**Location:** `zebra/zebra/services/coverage.py:193`.

`union_keyspace()` explores every nonempty subset intersection without first deduplicating or removing contained masks. Repeated/nested masks therefore produce exponential work even when their union is trivial. This is reachable through incremental masks: different sweeps can contribute identical prefixes, and coverage/recommendations expand all of them. Twenty-five identical length-one prefixes already require roughly 33 million subset visits per union calculation; recommendations call the function repeatedly.

**Suggested fix:** eliminate duplicate and contained masks before traversal, then use memoization or a bounded alternative for heavily overlapping collections.

## 14. [P2] Truncated complement accounting includes gaps later covered

**Locations:** `zebra/zebra/services/coverage.py:512`, `zebra/zebra/coverage_helpers.py:296`.

When the box cap drops a region, its full volume is permanently added to `omitted_keyspace`. Later masks may cover some of that dropped region, but the omitted count is never adjusted. The view then computes `shown = untried - omitted_keyspace`, which can disagree with the masks actually returned.

**Reproduced:** universe `01`, length 2, covered masks `00` then `01`, and `box_cap=1` yield actual `shown=2`, `untried=2`, but `omitted_keyspace=1`. The view would report shown as one. A small cap demonstrates the same logic used at the production cap.

**Suggested fix:** derive omitted volume from the final exact untried count minus retained box volume, rather than accumulating pre-subtraction volumes.

## 15. [P2] Potfile parsing cannot recover hashes containing colons

**Location:** `zebra/zebra/services/hashcat.py:260`.

`parse_potfile()` always splits at the first colon, even though the stored hash string may itself contain separators. For a stored hash `digest:salt`, the line `digest:salt:password` parses as hash `digest`, plaintext `salt:password`, so ingestion cannot match the target. Splitting at the last colon would instead break plaintexts containing colons.

**Reproduced:** the parser returns `[('digest', 'salt:password')]` for that input.

**Suggested fix:** use known target hashes or format-aware parsing to identify the hash boundary, preserving support for colons in plaintexts.

## 16. [P2] File-backed imports inflate counts and corrupt run attribution

**Location:** `zebra/zebra/views.py:891` (`import_results`).

File-backed imports append every parsed pair directly to the shared potfile, without deduplication, target membership checks, or coordination with a running attack. Importing the same result twice counts it twice and can push the cracked percentage above 100%. Importing during a run inserts unrelated rows into that run's assumed contiguous crack range. In contrast, DB-backed imports match known hashes and avoid repeated plaintext rows.

**Suggested fix:** validate and deduplicate imports, preserve potfile encoding, and serialize imports with active-run attribution or track attribution independently of line offsets.

## 17. [P2] DB-backed project progress replaces the campaign total with one run's count

**Locations:** `zebra/zebra/models.py:118`, `zebra/zebra/views.py:345` (`project_runs_status_json`).

Both project display paths use a running run's `recovered` directly as the campaign count. For DB-backed projects, each launch has its own potfile, so this value is specific to the current attack. If earlier attacks cracked 80 targets and a new run currently reports two, the project card falls from 80 to two until the run ends. A simple addition would also double-count hashes recovered again by the new run.

**Suggested fix:** compute the union of committed and live recovered targets, or use cumulative potfile semantics consistently for DB-backed campaigns.

## 18. [P2] Displayed commands are not safely copyable shell commands

**Locations:** `zebra/zebra/services/hashcat.py:143`, `:79`.

Command planners join argv elements with spaces without shell quoting. Paths/project names containing spaces split into multiple arguments, mask question marks undergo filename expansion, and valid literal mask characters such as `;`, `$`, and backticks acquire shell meaning. The active launcher correctly uses an argv list, but the saved/displayed command does not reliably reproduce it when pasted into a terminal.

**Suggested fix:** use shell-aware quoting such as `shlex.join()` for displayed POSIX commands while retaining argv lists for execution.
