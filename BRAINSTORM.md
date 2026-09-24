# zebra — brainstorm & moonshots

Blue-sky ideas for making zebra more **usable**, **robust**, and **smart**. This is a
dreaming document, not a roadmap — some of it is a weekend, some is a rewrite, some is
probably a bad idea. `TODO.md` holds the committed, incremental work; this is where we
let ourselves be ambitious. Ideas note the existing seam they'd build on where one
exists.

The north star: zebra already knows *exactly* what keyspace you've searched. Almost
every idea below is "what becomes possible once the tool has that ground truth?"

---

## 1. Coverage intelligence — lean into the differentiator

- **Cross-length campaign map.** One picture of the whole campaign: a length × coverage
  heatmap (or treemap) showing, per length, what's exhausted, planned/queued, and
  virgin — log-scaled because keyspaces span 20 orders of magnitude. Click a cell → the
  gaps for that length (reuse `complement_boxes`). The dashboard has per-length rows and
  a per-length decomposition viz; this is the zoom-out.
- **"What should I never run again" ledger.** Given the covered set, surface the masks
  that are now fully redundant (100% subsumed) so a user importing an old playbook sees
  which lines to delete. `is_subsumed` already computes this per candidate.
- **Coverage diff / time-lapse.** Snapshot coverage per day; show "you searched 4.1e12
  new candidates this week; here's the shape of it." Turns a grind into visible
  progress.
- **Universe inference.** Watch the plaintexts that *do* crack and suggest a tighter
  universe (e.g. "97% of your cracks are `?l?d`; drop `?s` and your remaining space
  shrinks 40×"). Closes the loop between results and the coverage denominator.
- **Length distribution from cracks.** Plot recovered-password lengths; recommend which
  lengths to prioritise next (short tail cracks fast, long tail is where the misses
  hide). Feeds the recommender's length choice.
- **Overlap-aware import.** Paste a big list of masks (a `.hcmask` file, a colleague's
  playbook) → zebra dedupes, orders them by marginal-new-keyspace, and drops the
  redundant ones before you commit GPU time. Batch `evaluate_candidate`.
- **Mask families / rotations generator.** "One digit floating through the letter
  positions," case-toggle families, leet substitutions as first-class generators —
  expand a template into its concrete masks with exact coverage accounting.

## 2. The recommender grows a brain

- **Corpus-grounded hit probability.** Rank uncovered masks by real-world likelihood,
  learned from a mask corpus (Hashcat `masks/*.hcmask`, PACK maskgen, or the operator's
  own crack history), not just budget + novelty. The `recommend` engine already has the
  budget/overlap machinery; this swaps the ranking key.
- **Learn from *this* campaign.** As hashes crack, update per-class and per-position
  priors ("position 1 is uppercase 80% of the time here") and bias suggestions toward
  the observed structure. A tiny per-project Markov/positional model.
- **Cost-aware planning with real speeds.** Persist `Benchmark` rows per hashtype/device
  and let the recommender/autopilot say "this mask is 6 GPU-hours; this one is 40
  minutes and 90% as likely" — a genuine cost/benefit queue with cumulative hit
  probability (the queue page already computes cumulative ETA).
- **"Plan my night" wizard.** Give a time budget (8 hours) and a hardware profile → get
  an ordered, exact-coverage, non-overlapping playbook that maximises expected cracks,
  ready to load into the queue. Autopilot on rails.
- **Wordlist + rules recommender.** Extend suggestion beyond masks to `-a 0` (wordlist ×
  rules) and hybrids, ranked by novelty against the similarity engine — the biggest
  real-world crack source, currently only dedup-checked.

## 3. Cracking workflow & the launcher

- **Launch every attack mode, not just masks.** Wordlist/combinator/hybrid runs from the
  UI (validate `Wordlist.path`/`RuleSet.path` on disk first). The launcher, queue, and
  recovery all generalise; only the guard and argv differ.
- **Multi-GPU / multi-host farm.** Today it's one hashcat at a time. A real worker model
  (RQ/Celery, or a thin agent per box) that dispatches queued runs across GPUs/hosts,
  respecting per-device benchmarks — with zebra as the coverage-aware scheduler so two
  boxes never search the same keyspace.
- **Live keyspace checkpointing as coverage.** A run that's aborted at 60% has still
  searched a *contiguous* 60% of its keyspace — record that partial region as covered
  (from the `--restore` point / progress), so an interrupted campaign doesn't lose the
  work it actually did. Big robustness + honesty win; the restore file already has the
  position.
- **Chunked / resumable huge masks.** Split a monster mask into keyspace chunks (hashcat
  `-s`/`-l` skip/limit), queue them, and track coverage per chunk — so a 3-week mask is
  interruptible and shows real progress.
- **Speed/thermal telemetry.** Chart H/s over a run, flag thermal throttling or a
  slow-down that suggests a stuck run, estimate power/cost. `--status-json` already
  carries device speed.
- **Distributed-friendly potfile sync.** Watch a shared/remote potfile (S3, a teammate's
  box) and fold in cracks found elsewhere; zebra's one-at-a-time crack attribution
  becomes multi-source-aware.
- **"Attack templates."** Save a named sequence (NTLM: rockyou+best64 → ?u?l?l?l?l?d?d →
  8-char ?a fill) and stamp it onto any new project of that hashtype in one click.

## 4. Results, reporting, and the "so what"

- **Engagement report export.** One button → a shareable HTML/PDF/CSV: hashes,
  crack rate, coverage per length, time/cost spent, masks tried, top password patterns,
  policy findings ("47% of cracked passwords are ≤8 chars"). This is what a pentest
  client actually wants.
- **Password-policy analytics.** From the cracked set: length histogram, character-class
  usage, top base words, reuse across users, seasonal/keyboard-walk patterns, compliance
  against a target policy. zebra is sitting on this data and shows almost none of it.
- **Cracked-plaintext explorer.** Search/filter/sort recovered plaintexts, group by
  pattern, spot the "Summer2024!" clusters. Per-run drill-down exists; a project-wide
  explorer doesn't.
- **Case / superproject layer.** Group the per-hashtype projects of one engagement (an
  AD dump becomes NTLM + NetNTLMv2 + Kerberos as separate projects) into one case with a
  rolled-up report. Long-noted as the successor to the dropped `Hashlist` idea.
- **Reuse / credential-stuffing view.** Same plaintext across multiple users/hashes →
  the finding a client cares about most.

## 5. Robustness, ops, and trust

- **Deployability.** A `Dockerfile` + compose (zebra + optional Postgres + a hashcat
  worker image), production settings (real `SECRET_KEY`, `DEBUG=False`, `ALLOWED_HOSTS`,
  static handling), and a one-command bootstrap. Still dev-only today.
- **Postgres option.** SQLite is great single-operator; a Postgres backend unlocks
  concurrency, a team, and bigger campaigns. The engine is DB-agnostic; the launcher's
  cross-thread SQLite dance goes away.
- **Health & self-check page.** Is hashcat found and what version? GPU visible? Data dir
  writable? Any orphaned runs? Disk space for potfiles? One screen that answers "is
  zebra healthy right now."
- **Structured audit log.** Every launch/stop/resume/queue action with who/when/what —
  useful for a team and for after-action review.
- **Backup / export-import a project.** Serialise a project (masks, runs, coverage,
  cracks, settings) to a portable bundle; move a campaign between machines or archive it.
- **Coverage cache with invalidation.** Memoise per-length union math, invalidate on
  mask add, so huge projects stay snappy (the inclusion–exclusion is exact but not free).
- **Config validation & guardrails.** Warn before a mask whose keyspace × benchmark is
  "3 years," before an `-O` run that exceeds the optimized length cap, before a duplicate
  of a queued attack.

## 6. UX & quality-of-life

- **Live mask editor.** Type a mask and watch keyspace, per-length coverage, overlap %,
  and estimated runtime update *as you type* — the Evaluate step, but instant. The
  arithmetic is already fast.
- **Command palette / keyboard-first.** `Ctrl-K` to jump to a project, record an attack,
  toggle the queue — power-user speed for a tool you live in.
- **Copy-to-clipboard everywhere.** The generated hashcat command, a mask, a plaintext —
  currently you select-and-copy.
- **Pagination + search** for large hashlists and mask/attack lists (thousands of rows
  today render all at once).
- **Dark mode / theming**, denser tables, mobile-friendly run-monitoring so you can watch
  a crack from your phone.
- **Inline help / "why".** Hover a coverage number or an overlap warning to see the exact
  masks responsible (the decomposition already knows).
- **Notifications.** Desktop/webhook/email/Slack/ntfy on run finish, first crack, queue
  empty, or a rogue-run recovery — so autopilot can run unattended and still reach you.
- **Undo for destructive actions.** Soft-delete runs/projects with a grace period beside
  the strict-confirm delete.

## 7. Integrations & ecosystem

- **CherryTree/CME/BloodHound-adjacent importers.** Pull hashes straight from secretsdump
  output, `/etc/shadow`, KeePass/`*.kdbx`, NetNTLM captures, PCAP-extracted hashes — with
  hashtype auto-detection.
- **Hashtype auto-detection.** Guess `-m` from hash format/length on paste (a la
  `hashid`/`name-that-hash`), instead of the manual dropdown.
- **Hashcat brain integration.** hashcat's own `--brain` server dovetails with zebra's
  coverage model — could be a first-class "never re-test a candidate" backend.
- **Cloud-burst cracking.** Spin up a GPU instance (vast.ai / cloud), run a queued
  attack, tear it down, fold the potfile back — coverage tracked throughout.
- **REST/GraphQL API + CLI.** Everything the UI does, scriptable — so zebra becomes a
  component in a bigger automation, and CI can smoke-test a campaign.
- **Public API for the coverage engine.** `services/coverage.py` is a clean, dependency-
  light exact-set library; it could ship as a standalone pip package others build on.

## 8. Left-field / research-y

- **Provable exhaustion certificate.** Export a machine-checkable proof that "these N
  masks exhaust `?a`^8" — auditable evidence for a report that a space was fully searched.
- **Adaptive autopilot with a feedback loop.** Autopilot watches its own hit-rate and
  reallocates the budget toward the mask *shapes* that are cracking, mid-campaign — a
  bandit over mask families.
- **Multi-project keyspace dedup.** If two engagements share a hashtype and universe,
  reuse coverage/exhaustion knowledge across them (with care re: data separation).
- **Natural-language planning.** "Focus on 8–10 char passwords that start with a capital
  and end in digits" → the concrete non-overlapping masks. A thin LLM front-end over the
  existing mask/coverage primitives.
- **Rule/wordlist coverage math.** The hard open problem: some notion of "how much of the
  *likely* space" a wordlist+rules run covers, so non-mask attacks get a coverage story
  too — even a probabilistic one would be huge.
- **GPU-time market awareness.** Given live cloud GPU prices and per-mask cost estimates,
  suggest *when* and *where* to run the expensive tail of the campaign.
