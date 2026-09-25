import os
import shutil
import time
from decimal import Decimal

from django.conf import settings as dj_settings
from django.shortcuts import render, get_object_or_404, redirect
from django.urls import reverse
from django.http import JsonResponse

from .models import Project, Mask, HashType, Hash, Run, Wordlist, RuleSet, Settings
from . import coverage_helpers as ch
from . import run_helpers as rh
from .services import hashcat as hc
from .services import similarity as sim
from .services import coverage as cov
from .services import hashfile
from .services import launcher
from urllib.parse import quote


def index(request):
    launcher.recover_and_advance()  # sweep orphans + keep the queue/autopilot moving
    projects = Project.objects.all()
    return render(request, 'zebra/index.html',
                  {'projects': projects, 'deleted': request.GET.get('deleted')})


# Duration magnitudes offered by the recommender popup (label -> seconds).
RECO_DURATIONS = [
    ('5 minutes', 300),
    ('1 hour', 3600),
    ('1 day', 86400),
    ('1 week', 604800),
]
_RECO_SECONDS = {s for _, s in RECO_DURATIONS}


def _format_duration(seconds):
    """Human 'about N units' string for a (possibly fractional) second count."""
    seconds = float(seconds)
    for unit, size in (('week', 604800), ('day', 86400), ('hour', 3600),
                       ('minute', 60), ('second', 1)):
        if seconds >= size or unit == 'second':
            n = seconds / size
            return '%s %s%s' % (('%.1f' % n).rstrip('0').rstrip('.'),
                                unit, '' if 0.95 <= n < 1.05 else 's')


def _humanize_count(value):
    """Compact SI-suffixed magnitude for a big number, e.g. 12340000 -> '12.34 M'.

    Returns None for a falsy/None value so templates can branch on it.
    """
    if not value:
        return None
    n = float(value)
    for suffix in ('', 'K', 'M', 'G', 'T', 'P', 'E'):
        if abs(n) < 1000 or suffix == 'E':
            unit = (suffix + ' ') if suffix else ''
            return ('%.0f %s' % (n, unit) if suffix == '' or n >= 100
                    else '%.2f %s' % (n, unit)).strip()
        n /= 1000.0


def _format_hashrate(value):
    """Render an H/s integer as a compact human string, e.g. '12.34 M H/s'."""
    human = _humanize_count(value)
    return None if human is None else human + ' H/s'


# Predefined project universes (value -> hashcat charset spec stored on the project).
UNIVERSE_PRESETS = {'digits': '?d', 'alnum': '?l?u?d', 'all': '?a'}


def _resolve_universe(request):
    """Resolve the universe form fields to (spec_to_store, error).

    Presets store their shorthand; 'custom' stores the (validated) custom spec,
    which may use hashcat shorthands like ?l?u?d?s or literal characters.
    """
    choice = request.POST.get('universe') or ''
    if choice in UNIVERSE_PRESETS:
        return UNIVERSE_PRESETS[choice], None
    if choice == 'custom':
        text = (request.POST.get('universe_custom') or '').strip()
        if not text:
            return '', None
        try:
            if not cov.expand_charset(text):
                return None, 'The custom universe is empty.'
        except cov.MaskParseError as exc:
            return None, 'Invalid custom universe: %s' % exc
        return text, None
    return '', None  # none / per-position fallback


def project_new(request):
    hashtypes = HashType.objects.all()
    context = {'hashtypes': hashtypes}
    if request.method == 'POST':
        name = (request.POST.get('name') or '').strip()
        description = (request.POST.get('description') or '').strip()
        hashtype_id = request.POST.get('hashtype')
        hashlist_raw = request.POST.get('hashlist') or ''
        hash_source = request.POST.get('hash_source') or 'db'
        universe, universe_error = _resolve_universe(request)
        context.update({'name': name, 'description': description,
                        'hashtype_id': hashtype_id, 'hashlist': hashlist_raw,
                        'hash_source': hash_source,
                        'hashfile_path': request.POST.get('hashfile_path') or '',
                        'universe_choice': request.POST.get('universe') or '',
                        'universe_custom': request.POST.get('universe_custom') or ''})

        hashtype = hashtypes.filter(pk=hashtype_id).first() if hashtype_id else None
        if not name:
            context['error'] = 'Project name is required.'
        elif Project.objects.filter(name=name).exists():
            context['error'] = 'A project named "%s" already exists.' % name
        elif hashtype is None:
            context['error'] = 'Please choose a hashtype.'
        elif universe_error:
            context['error'] = universe_error
        else:
            project = Project.objects.create(
                name=name, description=description or None,
                hashtype=hashtype, universe=universe or None)
            if hash_source == 'file':
                ok, err = _apply_file_source(project, request)
                if not ok:
                    project.delete()  # roll back the just-created project
                    context['error'] = err
                    return render(request, 'zebra/project_new.html', context)
            else:
                _create_hashes(project, _hashlist_from_request(request))
            return redirect(reverse('project_detail', args=[project.pk]))
    return render(request, 'zebra/project_new.html', context)


def _coverage_total(coverage, rate):
    """Campaign-wide rollup across the per-length coverage rows.

    Candidate sets of different lengths are disjoint, so covered/total add across
    lengths. Returns None when nothing is covered yet. ``space`` / ``percent`` /
    ``remaining`` are filled only when every attacked length has a known total
    (i.e. a fixed project universe); ``remaining_eta`` also needs a benchmark.
    """
    if not coverage:
        return None
    covered = sum(r['covered'] for r in coverage)
    totals = [r['total'] for r in coverage]
    lengths = [r['length'] for r in coverage]
    known = all(t is not None for t in totals)
    space = sum(totals) if known else None
    remaining = max(space - covered, 0) if known else None
    percent = min(100.0 * covered / space, 100.0) if space else None
    eta = _format_duration(remaining / rate) if rate and remaining else None
    return {
        'covered': covered, 'space': space, 'remaining': remaining,
        'percent': percent, 'remaining_eta': eta,
        'min_length': min(lengths), 'max_length': max(lengths),
    }


def project_detail(request, pk):
    launcher.adopt_live_orphans()  # adopt live orphans lazily (non-mutating on GET)
    project = get_object_or_404(Project, pk=pk)
    hashes = project.hash_set.all()
    # Counts route through the project so a file-backed project reports its cached
    # line count / potfile-derived cracks instead of (absent) Hash rows. The cracked
    # count is live (hashcat's recovered while a run is in flight), so it's right on
    # first paint rather than 0 until the first poll.
    cracked = project.live_cracked_count()
    total_hashes = project.hash_count_value()
    coverage = ch.project_coverage(project)
    # Annotate each length's remaining keyspace with an approximate time to
    # exhaust it (remaining / benchmark), when a benchmark is set.
    rate = int(project.benchmark_hs) if project.benchmark_hs else 0
    for row in coverage:
        rem = row['remaining']
        row['remaining_eta'] = (_format_duration(rem / rate)
                                if rate and rem else None)
    context = {
        'coverage_total': _coverage_total(coverage, rate),
        'project': project,
        'hashes': hashes,
        'cracked': cracked,
        'total_hashes': total_hashes,
        'cracked_pct': (100.0 * cracked / total_hashes) if total_hashes else 0.0,
        'coverage': coverage,
        'universe_chars': ch.expand_universe(project.universe),
        'runs': (Run.objects.filter(project=project).select_related('mask', 'project')
                 .prefetch_related('cracks', 'hashes', 'wordlists', 'rules')[:50]),
        'benchmark_display': _format_hashrate(project.benchmark_hs),
        'hashcat_available': hc.configured_runner().available(),
        'bench_message': request.GET.get('bench_msg'),
        'bench_error': request.GET.get('bench_error'),
        'reco_durations': RECO_DURATIONS,
    }
    return render(request, 'zebra/project_detail.html', context)


def project_benchmark(request, pk):
    """Set the project's benchmark (H/s): save a manual value or run ``hashcat -b``.

    POST-only; both actions redirect back to the project page with a flash
    message or error in the query string.
    """
    project = get_object_or_404(Project, pk=pk)
    detail = reverse('project_detail', args=[pk])
    if request.method != 'POST':
        return redirect(detail)

    action = request.POST.get('action')
    if action == 'save':
        raw = (request.POST.get('benchmark_hs') or '').strip().replace(',', '')
        if not raw:
            project.benchmark_hs = None
            project.save(update_fields=['benchmark_hs'])
            return redirect(detail + '?bench_msg=' + quote('Benchmark cleared.'))
        try:
            value = int(Decimal(raw))
            if value < 0:
                raise ValueError
        except (ValueError, ArithmeticError):
            return redirect(detail + '?bench_error='
                            + quote('Enter a whole number of hashes per second.'))
        project.benchmark_hs = value
        project.save(update_fields=['benchmark_hs'])
        return redirect(detail + '?bench_msg='
                        + quote('Benchmark set to {:,} H/s.'.format(value)))

    if action == 'run':
        if project.hashtype is None:
            return redirect(detail + '?bench_error='
                            + quote('This project has no hash type to benchmark.'))
        runner = hc.configured_runner()
        if not runner.available():
            return redirect(detail + '?bench_error='
                            + quote('hashcat is not installed on this machine.'))
        try:
            speed, _raw = runner.benchmark(project.hashtype.hashcat_module,
                                           timeout=180)
        except hc.HashcatError as exc:
            return redirect(detail + '?bench_error='
                            + quote('Benchmark failed: %s' % exc))
        if not speed:
            return redirect(detail + '?bench_error='
                            + quote('hashcat produced no parseable speed.'))
        project.benchmark_hs = speed
        project.save(update_fields=['benchmark_hs'])
        return redirect(detail + '?bench_msg='
                        + quote('Benchmarked {} at {:,} H/s.'.format(
                            project.hashtype.name, speed)))

    return redirect(detail)


def run_detail(request, pk):
    """Detail page for one recorded attack: its specs and the exact command."""
    launcher.adopt_live_orphans()  # adopt live orphans lazily (non-mutating on GET)
    run = get_object_or_404(
        Run.objects.select_related('mask', 'project', 'project__hashtype'), pk=pk)
    p = run.params or {}
    wordlists = list(run.wordlists.all())
    rules = list(run.rules.all())

    def _charsets(cs):
        return ', '.join('-%s %s' % (k, cs[k]) for k in sorted(cs)) if cs else ''

    specs = []  # (label, value) rows, mode-specific
    m = run.attack_mode
    if m == 3 and run.mask:
        specs.append(('Mask', run.mask.pattern))
        if run.mask.is_incremental:
            specs.append(('Increment', '%d–%d (--increment)' % (
                run.mask.increment_min, run.mask.increment_max)))
        if run.mask.keyspace is not None:
            specs.append(('Keyspace', '{:,}'.format(int(run.mask.keyspace))))
        if run.mask.custom_charsets:
            specs.append(('Custom charsets', _charsets(run.mask.custom_charsets)))
    elif m == 0:
        specs.append(('Wordlist(s)', ', '.join(w.name for w in wordlists) or '—'))
        specs.append(('Rules', ', '.join(r.name for r in rules) or 'none'))
    elif m == 1:
        by_id = {w.id: w for w in wordlists}
        order = [by_id[i] for i in (p.get('order') or []) if i in by_id] or wordlists
        specs.append(('Left wordlist', order[0].name if len(order) > 0 else '—'))
        specs.append(('Right wordlist', order[1].name if len(order) > 1 else '—'))
        if p.get('left_rule'):
            specs.append(('-j (left rule)', p['left_rule']))
        if p.get('right_rule'):
            specs.append(('-k (right rule)', p['right_rule']))
    elif m in (6, 7):
        specs.append(('Wordlist', wordlists[0].name if wordlists else '—'))
        specs.append(('Mask', p.get('mask') or '—'))
        if p.get('custom_charsets'):
            specs.append(('Custom charsets', _charsets(p['custom_charsets'])))

    context = {
        'run': run,
        'project': run.project,
        'specs': specs,
        'cracks': run.cracks.select_related('hash').all(),
        'crack_count': run.crack_count(),
        # File-backed runs have no Crack rows; their recovered plaintexts come from
        # the project potfile, sliced to this run's row range (capped for display).
        'potfile_cracks': run.potfile_cracks(limit=500),
        'target_count': run.target_count(),
        'hashcat_available': hc.configured_runner().available(),
        # Recovery: whether a running row is being tracked by a potfile watcher
        # (contact lost, cracks live but progress frozen), and whether an ended run
        # has a checkpoint we can resume from.
        'adopted': (run.status == 'running' and run.pk not in launcher._active
                    and launcher._run_is_live(run)),
        'recovery_ready': run.recovery_ready(),
        'launch_error': request.GET.get('error'),
    }
    return render(request, 'zebra/run_detail.html', context)


def run_status_json(request, pk):
    """Live status of a run (polled by the detail page instead of full reloads).

    Returns the fields that change while a mask attack runs, so the page can
    update the progress bar / speed in place and only do a single full reload
    once ``running`` flips false (to render cracks, controls, final status).
    """
    run = get_object_or_404(Run, pk=pk)
    return JsonResponse({
        'status': run.status,
        'running': run.status == 'running',
        'progress': run.progress,
        'percent': 100.0 * (run.progress or 0.0),
        'speed_hs': str(run.speed_hs) if run.speed_hs else None,
        'speed_grouped': '{:,}'.format(int(run.speed_hs)) if run.speed_hs else None,
        'speed_h': _format_hashrate(run.speed_hs),
        'cracks': run.crack_count(),  # live recovered while running, else committed
        # --increment sweep position: 1-based current sub-run and the total.
        # increment_offset is already 1-based (hashcat's guess_base_offset).
        'run_index': run.increment_offset,
        'run_total': run.increment_count,
    })


def project_runs_status_json(request, pk):
    """Live status/progress/cracks of a project's runs (polled by the dashboard).

    Lets the Attacks table update the running row's progress and crack count in
    place and reload once any run's status changes (queue advancing, a run
    finishing), mirroring the detail page. Crack counts come from hashcat's live
    ``recovered_hashes`` while running (before the potfile is imported), else the
    committed Crack rows. Matches the dashboard's own set/order (newest 50)."""
    from django.db.models import Count
    project = get_object_or_404(Project, pk=pk)
    rows = (Run.objects.filter(project=project)
            .annotate(n_cracks=Count('cracks'))
            .values('pk', 'status', 'progress', 'recovered', 'crack_baseline',
                    'crack_range_end', 'n_cracks')[:50])
    active = any(r['status'] in ('running', 'queued') for r in rows)
    file_backed = project.is_file_backed
    live_recovered = None
    runs = []
    for r in rows:
        running = r['status'] == 'running'
        if file_backed:
            # Shared cumulative potfile: this run's own cracks are the block
            # [crack_baseline, end), where end is the recorded range end once
            # finished, else the live recovered count.
            end = r['crack_range_end'] if r['crack_range_end'] is not None else r['recovered']
            if end is not None and r['crack_baseline'] is not None:
                cracks = max(0, end - r['crack_baseline'])
            else:
                cracks = 0
        else:
            # DB-backed: live recovered while running, else committed Crack rows.
            cracks = r['recovered'] if (running and r['recovered'] is not None) else r['n_cracks']
        if running and r['recovered'] is not None:
            live_recovered = r['recovered']  # cumulative project total (either mode)
        runs.append({'pk': r['pk'], 'status': r['status'],
                     'percent': round(100.0 * (r['progress'] or 0.0)),
                     'cracks': cracks})
    # Project-level cracked count for the top card: live from the running run when
    # hashcat is reporting it, else the committed project total.
    cracked = live_recovered if live_recovered is not None else project.cracked_count()
    total = project.hash_count_value()
    return JsonResponse({
        'active': active,  # whether anything can still change on its own
        'cracked': cracked,
        'cracked_pct': round(100.0 * cracked / total, 1) if total else 0.0,
        'runs': runs,
    })


def run_start(request, pk):
    """Run a mask attack now, or queue it if a job is already in progress (POST)."""
    run = get_object_or_404(Run, pk=pk)
    detail = reverse('run_detail', args=[pk])
    if request.method != 'POST':
        return redirect(detail)
    _action, err = launcher.run_or_queue(run)
    return redirect(detail + ('?error=' + quote(err) if err else ''))


def run_stop(request, pk):
    """Signal a running attack to stop (POST-only)."""
    run = get_object_or_404(Run, pk=pk)
    detail = reverse('run_detail', args=[pk])
    if request.method != 'POST':
        return redirect(detail)
    err = launcher.stop_run(run)
    return redirect(detail + ('?error=' + quote(err) if err else ''))


def run_resume(request, pk):
    """Resume a dead attack from its hashcat checkpoint (POST-only)."""
    run = get_object_or_404(Run, pk=pk)
    detail = reverse('run_detail', args=[pk])
    if request.method != 'POST':
        return redirect(detail)
    err = launcher.resume_run(run)
    return redirect(detail + ('?error=' + quote(err) if err else ''))


def _queue_back(request, pk):
    """Where to return after a queue action: the form's 'next', else run detail."""
    return request.POST.get('next') or reverse('run_detail', args=[pk])


def run_enqueue(request, pk):
    """Add a planned mask run to the attack queue (POST-only)."""
    run = get_object_or_404(Run, pk=pk)
    if request.method != 'POST':
        return redirect(reverse('run_detail', args=[pk]))
    err = launcher.enqueue(run)
    if err:
        return redirect(reverse('run_detail', args=[pk]) + '?error=' + quote(err))
    return redirect(_queue_back(request, pk))


def run_dequeue(request, pk):
    """Remove a run from the queue, back to planned (POST-only)."""
    run = get_object_or_404(Run, pk=pk)
    if request.method != 'POST':
        return redirect(reverse('run_detail', args=[pk]))
    launcher.dequeue(run)
    return redirect(_queue_back(request, pk))


def run_move(request, pk):
    """Reorder a queued run up/down (POST-only, ?dir=up|down)."""
    run = get_object_or_404(Run, pk=pk)
    if request.method != 'POST':
        return redirect(reverse('queue'))
    launcher.move(run, -1 if request.POST.get('dir') == 'up' else 1)
    return redirect(_queue_back(request, pk))


def _safe_next(request):
    """A local redirect target from the POSTed ``next``, else None.

    Only same-site absolute paths (a single leading '/', not '//') are allowed, so
    the header switch can return to the page it was used from without being an open
    redirect."""
    nxt = request.POST.get('next') or ''
    if nxt.startswith('/') and not nxt.startswith('//'):
        return nxt
    return None


def queue_set_mode(request):
    """Set the queue master switch to off/on/auto (POST); return to the same page."""
    if request.method == 'POST':
        mode = request.POST.get('mode')
        if mode in ('off', 'on', 'auto'):
            launcher.set_queue_mode(mode)
            if mode in ('on', 'auto'):
                launcher._advance_queue()  # kick the queue (and auto-fill if empty)
    return redirect(_safe_next(request) or reverse('queue'))


def queue_pause(request):
    if request.method == 'POST':
        launcher.pause_queue()
    return redirect(reverse('queue'))


def queue_resume(request):
    if request.method == 'POST':
        launcher.resume_queue()
    return redirect(reverse('queue'))


def queue(request):
    """The machine-wide attack queue: what's running, what's next, ETA to clear it."""
    launcher.recover_and_advance()  # sweep orphans + keep the queue/autopilot moving
    running = (Run.objects.filter(status='running')
               .select_related('mask', 'project').first())
    queued = list(Run.objects.filter(status='queued')
                  .select_related('mask', 'project').order_by('queue_position', 'pk'))
    items, cumulative, all_have_eta = [], 0.0, True
    for r in queued:
        rate = int(r.project.benchmark_hs) if r.project and r.project.benchmark_hs else 0
        ks = int(r.mask.keyspace) if r.mask and r.mask.keyspace is not None else None
        if rate and ks is not None:
            est = ks / rate
            cumulative += est
            label = _format_duration(est)
        else:
            label, all_have_eta = None, False
        items.append({'run': r, 'est_label': label})
    recent = (Run.objects.filter(status__in=['exhausted', 'cracked', 'aborted', 'error'])
              .select_related('mask', 'project').order_by('-ended_at')[:8])
    return render(request, 'zebra/queue.html', {
        'running': running,
        'items': items,
        'queued_count': len(queued),
        'total_eta': _format_duration(cumulative) if items and all_have_eta else None,
        'paused': launcher.is_paused(),
        'auto_task_minutes': Settings.load().auto_task_seconds // 60,
        'recent': recent,
    })


def run_delete(request, pk):
    """Remove an attack (typo/error). POST-only; GET falls back to the detail page."""
    run = get_object_or_404(Run, pk=pk)
    if request.method != 'POST':
        return redirect(reverse('run_detail', args=[pk]))
    project_pk = run.project_id
    mask = run.mask
    # Remove this run's recovery files (its checkpoint, and per-run potfile for
    # DB-backed; never a file-backed project's shared potfile).
    with launcher.deleting_runs(Run.objects.filter(pk=pk)) as error:
        if error:
            return redirect(reverse('run_detail', args=[pk]) + '?error=' + quote(error))
        launcher._cleanup_run_files(
            run, drop_potfile=not (run.project and run.project.is_file_backed))
        run.delete()
        # Tidy up a mode-3 mask left with no runs (created for this attack alone).
        if mask and not mask.runs.exists():
            mask.delete()
    if project_pk:
        return redirect(reverse('project_detail', args=[project_pk]))
    return redirect(reverse('index'))


def _project_delete_phrase(project):
    """The exact sentence a user must type to confirm deleting this project."""
    return 'Permanently delete the project %s and all of its data' % project.name


def _cleanup_project_files(project):
    """Remove zebra-managed files for a project being deleted (best effort).

    Only files zebra owns: the per-project potfile, and an uploaded hashfile it
    stored (``hashfile_managed``). A server-side hashfile the operator supplied by
    path is left untouched."""
    paths = []
    if project.is_file_backed:
        paths.append(project.resolve_potfile_path())
        if project.hashfile_managed and project.hashfile_path:
            paths.append(project.hashfile_path)
    # Per-run recovery files (checkpoints + DB-backed per-run potfiles); the cascade
    # drops the rows but not these on-disk files.
    for run in project.runs.all():
        if run.restore_path:
            paths.append(run.restore_path)
        if not project.is_file_backed and run.potfile_path:
            paths.append(run.potfile_path)
    for p in paths:
        try:
            os.remove(p)
        except OSError:
            pass


def project_delete(request, pk):
    """Delete a whole project behind a strict typed confirmation.

    The user must type an exact, project-specific sentence and press the confirm
    button; anything else re-renders the page and deletes nothing. Cascades remove
    the project's hashes/masks/runs/cracks; zebra-managed files are cleaned up too.
    """
    project = get_object_or_404(Project, pk=pk)
    phrase = _project_delete_phrase(project)
    context = {'project': project, 'phrase': phrase,
               'run_count': project.runs.count()}
    if request.method == 'POST':
        typed = (request.POST.get('confirm_text') or '').strip()
        if typed != phrase:
            context['error'] = ('The confirmation sentence did not match — the '
                                'project was NOT deleted.')
            context['typed'] = typed
            return render(request, 'zebra/project_delete.html', context)
        name = project.name
        with launcher.deleting_runs(project.runs.all()) as error:
            if error:
                context['error'] = error
                context['typed'] = typed
                return render(request, 'zebra/project_delete.html', context)
            _cleanup_project_files(project)
            project.delete()
        return redirect(reverse('index') + '?deleted=' + quote(name))
    return render(request, 'zebra/project_delete.html', context)


def _hashlist_from_request(request):
    """Combined hashlist text: the pasted textarea plus any uploaded file.

    Either or both may be supplied; duplicates are dropped downstream in
    ``_create_hashes``. Uploaded bytes are decoded leniently.
    """
    parts = [request.POST.get('hashlist') or '']
    upload = request.FILES.get('hashfile')
    if upload:
        parts.append(upload.read().decode('utf-8', errors='ignore'))
    return '\n'.join(parts)


def _create_hashes(project, raw):
    """Create one Hash per unique, non-empty line of ``raw`` under ``project``.

    The project fixes the hash type, so hashes carry none of their own. Skips
    lines already in the project and duplicates within the submission. Returns
    (added, skipped).
    """
    existing = set(project.hash_set.values_list('hashstring', flat=True))
    seen, rows, skipped = set(), [], 0
    for line in (raw or '').splitlines():
        line = line.strip()
        if not line:
            continue
        if line in seen or line in existing:
            skipped += 1
            continue
        seen.add(line)
        rows.append(Hash(hashstring=line, project=project, cracked=False))
    if rows:
        Hash.objects.bulk_create(rows)
    return len(rows), skipped


def _store_uploaded_hashfile(project, upload):
    """Stream an uploaded hash file into the managed dir; return its abs path.

    Uses ``upload.chunks()`` (never ``.read()``) so a multi-gigabyte list is never
    held in memory -- the whole point of file-backed projects."""
    dest_dir = os.path.join(dj_settings.ZEBRA_DATA_DIR, 'hashfiles')
    os.makedirs(dest_dir, exist_ok=True)
    dest = os.path.join(dest_dir, 'project-%d-%d.txt' % (project.pk, int(time.time())))
    with open(dest, 'wb') as f:
        for chunk in upload.chunks():
            f.write(chunk)
    return dest


def _apply_file_source(project, request):
    """Point ``project`` at an external hash file from the form. Returns (ok, error).

    Accepts either an uploaded file (saved into the managed dir, marked managed) or
    a server-side absolute path (referenced zero-copy). Caches the line count."""
    path = (request.POST.get('hashfile_path') or '').strip()
    upload = request.FILES.get('hashfile_upload')
    if upload:
        project.hashfile_path = _store_uploaded_hashfile(project, upload)
        project.hashfile_managed = True
    elif path:
        ok, err = hashfile.validate_path(path)
        if not ok:
            return False, err
        project.hashfile_path = path
        project.hashfile_managed = False
    else:
        return False, 'Provide a server-side path or upload a hash file.'
    project.save(update_fields=['hashfile_path', 'hashfile_managed'])
    project.refresh_hash_count()
    return True, None


def hashes_add(request, pk):
    project = get_object_or_404(Project, pk=pk)
    context = {'project': project}
    if request.method == 'POST':
        if project.is_file_backed:
            # File-backed: "add hashes" = point at a new file (path or upload) and
            # re-count. We never mutate an operator's server-side file, so this
            # replaces the reference rather than appending.
            ok, err = _apply_file_source(project, request)
            if ok:
                context['message'] = ('Hash file set to %s (%s hashes).'
                                      % (project.hashfile_path,
                                         project.hash_count if project.hash_count is not None else '?'))
            else:
                context['error'] = err
        elif project.hashtype is None:
            context['error'] = ('This project has no hash type set. Set one in the '
                                'admin before adding hashes.')
        else:
            hashlist_raw = request.POST.get('hashlist') or ''
            context['hashlist'] = hashlist_raw
            added, skipped = _create_hashes(project, _hashlist_from_request(request))
            context['message'] = (
                'Added %d hash(es) as %s%s.'
                % (added, project.hashtype.name,
                   ' (%d duplicate(s) skipped)' % skipped if skipped else ''))
            context['hashlist'] = ''  # clear the textarea after a successful add
    return render(request, 'zebra/hashes_add.html', context)


def _parse_custom_charsets(raw):
    """Parse 'key=def' lines (one per line) into a {key: def} dict."""
    cs = {}
    for line in (raw or '').splitlines():
        line = line.strip()
        if not line or '=' not in line:
            continue
        k, _, v = line.partition('=')
        cs[k.strip()] = v.strip()
    return cs


def mask_new(request, pk):
    """Record an attack of any supported mode (mask / straight / combinator / hybrid)."""
    project = get_object_or_404(Project, pk=pk)
    context = {
        'project': project,
        'statuses': Run.STATUS_CHOICES,
        'attack_modes': Run.ATTACK_MODES,
        'attack_mode': 3,  # default; overwritten on POST (0 is a valid, falsy value)
        'default_status': 'planned',
        'wordlist_names': list(Wordlist.objects.values_list('name', flat=True)),
        'rule_names': list(RuleSet.objects.values_list('name', flat=True)),
        'hashcat_available': hc.configured_runner().available(),
    }
    if request.method != 'POST' or project.hashtype is None:
        # Prefill the mask from query params (e.g. the recommender's "Record"
        # link) so the form opens ready to evaluate/record.
        context['pattern'] = (request.GET.get('pattern') or '').strip()
        context['increment'] = bool(request.GET.get('increment'))
        context['increment_max'] = (request.GET.get('increment_max') or '').strip()
        # Custom charsets ride along as newline-joined "key=def" lines (the format
        # the POST handler parses) so a complement/suggested mask keeps its -1..-4.
        context['custom_charsets_raw'] = request.GET.get('custom_charsets') or ''
        context['optimized'] = True  # optimized kernels (-O) on by default
        return render(request, 'zebra/mask_new.html', context)

    # --- common inputs (echoed back for re-render) ---
    try:
        attack_mode = int(request.POST.get('attack_mode') or 3)
    except ValueError:
        attack_mode = 3
    status = request.POST.get('status') or 'planned'
    device = (request.POST.get('device') or '').strip()
    optimized = bool(request.POST.get('optimized'))  # -O; absent (unchecked) -> off
    action = request.POST.get('action')

    pattern = (request.POST.get('pattern') or '').strip()
    custom_raw = request.POST.get('custom_charsets', '')
    custom = _parse_custom_charsets(custom_raw)
    # --increment (mask mode only): a checkbox + optional max; min defaults to 1.
    increment_on = bool(request.POST.get('increment'))
    increment_max_raw = (request.POST.get('increment_max') or '').strip()
    try:
        inc_max_in = int(increment_max_raw) if increment_max_raw else None
    except ValueError:
        inc_max_in = None
    inc_min = 1 if increment_on else None
    wordlist = (request.POST.get('wordlist') or '').strip()
    left_wl = (request.POST.get('left_wordlist') or '').strip()
    right_wl = (request.POST.get('right_wordlist') or '').strip()
    left_rule = (request.POST.get('left_rule') or '').strip()
    right_rule = (request.POST.get('right_rule') or '').strip()
    rules_raw = request.POST.get('rules', '')
    rule_names = [ln.strip() for ln in rules_raw.splitlines() if ln.strip()]

    context.update({
        'attack_mode': attack_mode, 'status': status, 'device': device,
        'pattern': pattern, 'custom_charsets_raw': custom_raw,
        'wordlist': wordlist, 'left_wordlist': left_wl, 'right_wordlist': right_wl,
        'left_rule': left_rule, 'right_rule': right_rule, 'rules_raw': rules_raw,
        'increment': increment_on, 'increment_max': increment_max_raw,
        'optimized': optimized,
    })

    module = project.hashtype.hashcat_module
    runner = hc.configured_runner()
    hashfile = '%s.hashes' % project.name

    # --- Mask (attack mode 3): exact coverage path ---
    if attack_mode == 3:
        evaluation = ch.evaluate_candidate(project, pattern, custom,
                                           increment_min=inc_min, increment_max=inc_max_in)
        context['evaluation'] = evaluation
        if evaluation.get('error'):
            return render(request, 'zebra/mask_new.html', context)
        # Effective increment bounds: evaluate defaults a blank max to the mask
        # length and auto-raises the min past leading fully-covered lengths.
        inc_max = evaluation.get('increment_max')
        inc_min_eff = evaluation.get('increment_min')
        redundant_inc = evaluation.get('redundant_increment')
        mask_params = {'mask': pattern, 'custom_charsets': custom,
                       'increment_min': inc_min_eff, 'increment_max': inc_max}
        # Expected runtime = keyspace / benchmark (for an incremental run, keyspace is
        # the sum over swept lengths). Only when a benchmark is set for the project.
        if project.benchmark_hs and evaluation.get('keyspace'):
            rate = int(project.benchmark_hs)
            seconds = evaluation['keyspace'] / rate
            context['duration'] = {
                'seconds': seconds,
                'label': _format_duration(seconds),
                'benchmark_h': _humanize_count(rate),
            }
        context['command'] = runner.plan_run(
            3, module, hashfile=hashfile, params=mask_params, optimized=optimized)
        # A fully-covered incremental sweep has no lengths left to run.
        context['can_record'] = not redundant_inc
        if not redundant_inc and action in ('record', 'record_run'):
            mask, _ = Mask.objects.get_or_create(
                project=project, pattern=pattern, custom_charsets=custom,
                increment_min=inc_min_eff, increment_max=inc_max)
            ch.compute_and_cache_keyspace(mask)
            mask.save()
            sig_spec = {'attack_mode': 3, 'mask': pattern}
            if inc_min_eff is not None:
                sig_spec['increment'] = [inc_min_eff, inc_max]
            run = Run.objects.create(
                mask=mask, project=project, attack_mode=3, optimized=optimized,
                device=device or None, status=status, command=context['command'],
                signature=sim.signature(sig_spec))
            # Snapshot targeted hashes for DB-backed projects only; a file-backed
            # project would create millions of M2M rows (target_count falls back to
            # the project's hash count instead).
            if not project.is_file_backed:
                run.hashes.set(project.hash_set.all())
            # "Record & run": launch straight away and land on the live run page,
            # collapsing record -> find in list -> open -> Run into one click. A
            # launch guard failure (no hashcat, one already running, ...) is shown
            # as a banner on the run page, where the run can still be queued.
            if action == 'record_run':
                _act, err = launcher.run_or_queue(run)  # runs now, or queues if busy
                dest = reverse('run_detail', args=[run.pk])
                return redirect(dest + ('?error=' + quote(err) if err else ''))
            return redirect(reverse('project_detail', args=[project.pk]))
        return render(request, 'zebra/mask_new.html', context)

    # --- Non-mask modes: similarity path ---
    if attack_mode == 0:
        wl_names, params, missing = ([wordlist] if wordlist else []), {}, not wordlist
    elif attack_mode == 1:
        wl_names = [x for x in (left_wl, right_wl) if x]
        params = {'left_rule': left_rule, 'right_rule': right_rule}
        rule_names = []  # combinator uses inline -j/-k, not -r files
        missing = len(wl_names) < 2
    elif attack_mode in (6, 7):
        wl_names = [wordlist] if wordlist else []
        params = {'mask': pattern, 'custom_charsets': custom}
        missing = not wordlist or not pattern
    else:
        context['error'] = 'Unsupported attack mode.'
        return render(request, 'zebra/mask_new.html', context)

    candidate_spec = {
        'attack_mode': attack_mode, 'wordlists': wl_names, 'rules': rule_names,
        'left_rule': params.get('left_rule', ''), 'right_rule': params.get('right_rule', ''),
        'mask': params.get('mask', ''), 'custom_charsets': params.get('custom_charsets', {}),
    }
    context['similar'] = rh.evaluate_run(project, candidate_spec)
    context['ran_similarity'] = True
    context['command'] = runner.plan_run(
        attack_mode, module, hashfile=hashfile, wordlists=wl_names,
        rules=rule_names, params=params, optimized=optimized)
    context['can_record'] = not missing
    if missing:
        context['error'] = ('This attack needs %s.' %
                            ('two wordlists' if attack_mode == 1
                             else 'a wordlist and a mask' if attack_mode in (6, 7)
                             else 'a wordlist'))
        return render(request, 'zebra/mask_new.html', context)

    # Non-mask modes can't be launched yet (launcher is mask-only), so
    # "record_run" degrades to a plain record here.
    if action in ('record', 'record_run'):
        wl_objs = rh.resolve_wordlists(wl_names)
        rule_objs = rh.resolve_rules(rule_names)
        if attack_mode == 1:
            params['order'] = [w.id for w in wl_objs]
        run = Run.objects.create(
            project=project, attack_mode=attack_mode, optimized=optimized,
            device=device or None, status=status, command=context['command'],
            params=params, signature=sim.signature(candidate_spec))
        run.wordlists.set(wl_objs)
        run.rules.set(rule_objs)
        if not project.is_file_backed:  # see the mask path -- skip the huge M2M
            run.hashes.set(project.hash_set.all())
        return redirect(reverse('project_detail', args=[project.pk]))
    return render(request, 'zebra/mask_new.html', context)


def import_results(request, pk):
    project = get_object_or_404(Project, pk=pk)
    context = {'project': project}
    if request.method == 'POST':
        kind = request.POST.get('kind')
        text = request.POST.get('text') or ''
        try:
            if kind == 'potfile':
                pairs = hc.parse_potfile(text)
                if project.is_file_backed:
                    # No Hash rows to match against -- the persistent potfile is the
                    # source of truth, so append the parsed cracks to it.
                    pot = project.resolve_potfile_path()
                    os.makedirs(os.path.dirname(pot), exist_ok=True)
                    with open(pot, 'a', encoding='utf-8') as f:
                        for h, plain in pairs:
                            f.write('%s:%s\n' % (h, plain))
                    context['message'] = ('Appended %d crack(s) to the project '
                                          'potfile.' % len(pairs))
                else:
                    matched = hc.ingest_cracks(project, pairs)
                    context['message'] = ('Imported %d potfile line(s); %d hash(es) '
                                          'newly cracked.' % (len(pairs), matched))
            elif kind == 'status':
                summary = hc.parse_status_json(text)
                context['message'] = 'Parsed status: %r' % summary
            else:
                context['error'] = 'Choose an import type.'
        except Exception as exc:  # surface parse errors to the user
            context['error'] = '%s: %s' % (type(exc).__name__, exc)
    return render(request, 'zebra/import_results.html', context)


def recommend_json(request, pk):
    """Mask suggestions for a time budget (JSON; feeds the recommender popup).

    Query param ``seconds`` = the chosen duration magnitude. Needs the project's
    benchmark (target keyspace = benchmark_hs * seconds) and hash type. Keyspace
    counts are sent as strings (JS loses integer precision past 2**53); durations
    ride along both as raw seconds and a preformatted label.
    """
    project = get_object_or_404(Project, pk=pk)
    try:
        seconds = int(request.GET.get('seconds') or 0)
    except ValueError:
        seconds = 0
    if seconds <= 0:
        return JsonResponse({'ok': False, 'error': 'Choose a duration.'})
    if project.benchmark_hs is None:
        return JsonResponse({'ok': False, 'error': 'no-benchmark'})

    rate = int(project.benchmark_hs)
    target = rate * seconds
    recs = ch.project_recommendations(project, target)
    items = []
    for r in recs:
        est = r['keyspace'] / rate if rate else 0
        overlap = r['overlap']
        record_url = reverse('mask_new', args=[project.pk]) + '?pattern=' + quote(r['pattern'])
        if r.get('incremental'):
            record_url += '&increment=1&increment_max=%d' % r['increment_max']
        items.append({
            'pattern': r['pattern'],
            'length': r['length'],
            'keyspace': str(r['keyspace']),
            'keyspace_h': _humanize_count(r['keyspace']) or '0',
            'overlap': str(overlap),
            'overlap_pct': (100.0 * overlap / r['keyspace']) if r['keyspace'] else 0.0,
            'zero_overlap': overlap == 0,
            'incremental': bool(r.get('incremental')),
            'increment_max': r['increment_max'] if r.get('incremental') else None,
            'covers': r.get('covers', str(r['length'])),
            'est_seconds': est,
            'est_label': _format_duration(est),
            'record_url': record_url,
        })
    return JsonResponse({
        'ok': True,
        'seconds': seconds,
        'budget_label': _format_duration(seconds),
        'benchmark_hs': str(rate),
        'benchmark_h': _humanize_count(rate),
        'target': str(target),
        'target_h': _humanize_count(target),
        'recommendations': items,
    })


def settings_view(request):
    """Global (project-independent) program settings.

    Currently one knob: an override path to the hashcat binary. On POST we save
    the singleton, then always report whether the (now-effective) binary resolves,
    so the user gets immediate feedback that their path actually works.
    """
    config = Settings.load()
    saved = False
    if request.method == 'POST':
        config.hashcat_binary = request.POST.get('hashcat_binary', '').strip()
        # Auto-pilot task length, entered in minutes (min 1); stored as seconds.
        try:
            minutes = max(1, int(request.POST.get('auto_task_minutes') or 60))
        except ValueError:
            minutes = 60
        config.auto_task_seconds = minutes * 60
        config.save()
        saved = True
    binary = hc.configured_binary()
    resolved = shutil.which(binary)
    context = {
        'settings': config,
        'saved': saved,
        'auto_task_minutes': config.auto_task_seconds // 60,
        'default_binary': hc.DEFAULT_BINARY,
        'effective_binary': binary,
        'is_override': bool((config.hashcat_binary or '').strip()),
        'hashcat_available': resolved is not None,
        'resolved_path': resolved,
    }
    return render(request, 'zebra/settings.html', context)


def coverage_decomposition_json(request, pk, length):
    """Disjoint-cell decomposition for one password length (search-space viz).

    Fetched lazily by the dashboard when a coverage row is expanded, so
    project_detail itself stays cheap for large campaigns.
    """
    project = get_object_or_404(Project, pk=pk)
    return JsonResponse(ch.project_length_decomposition(project, length))


def _custom_charsets_raw(custom):
    """Encode a {"1":def,...} dict as the newline "key=def" form the form parses."""
    return '\n'.join('%s=%s' % (k, custom[k]) for k in sorted(custom))


def complement_json(request, pk, length):
    """Masks covering the untried region of ``length`` (feeds the Fill-gaps modal).

    ``?style=compact|builtins``. Keyspaces are strings (JS precision). Each mask
    carries a ``record_url`` and ``custom_charsets_raw`` so the modal's Record link
    and Record&run POST preserve its -1..-4 definitions through the record flow.
    """
    project = get_object_or_404(Project, pk=pk)
    style = request.GET.get('style')
    style = style if style in ('compact', 'builtins') else 'compact'
    res = ch.project_complement_masks(project, length, style)
    if res.get('error') == 'no-universe':
        return JsonResponse({'ok': False, 'error': 'no-universe'})
    rate = int(project.benchmark_hs) if project.benchmark_hs else 0
    masks = []
    for it in res['items']:
        cc = it['custom_charsets']
        cc_raw = _custom_charsets_raw(cc)
        record_url = reverse('mask_new', args=[project.pk]) + '?pattern=' + quote(it['pattern'])
        if cc:
            record_url += '&custom_charsets=' + quote(cc_raw)
        masks.append({
            'pattern': it['pattern'],
            'custom_charsets': cc,
            'custom_charsets_raw': cc_raw,
            'keyspace': str(it['keyspace']),
            'keyspace_h': _humanize_count(it['keyspace']) or '0',
            'covers': it['covers'],
            'est_label': _format_duration(it['keyspace'] / rate) if rate else None,
            'record_url': record_url,
        })
    s = res['summary']
    return JsonResponse({
        'ok': True, 'length': res['length'], 'style': res['style'], 'masks': masks,
        'summary': {
            'total': str(s['total']), 'untried': str(s['untried']),
            'untried_h': _humanize_count(s['untried']) or '0',
            'shown': str(s['shown']),
            'omitted_gaps': s['omitted_gaps'],
            'omitted_keyspace': str(s['omitted_keyspace']),
            'omitted_h': _humanize_count(s['omitted_keyspace']) or '0',
            'truncated': s['truncated'],
        },
    })


def complement_queue(request, pk, length):
    """Record every untried-region mask for ``length`` and enqueue it (POST).

    Recomputes the set server-side (never trusts the client), skips masks already
    recorded/queued, and enqueues the rest (which runs the first immediately when
    the queue is idle). Returns {queued, skipped}.
    """
    project = get_object_or_404(Project, pk=pk)
    if request.method != 'POST':
        return redirect(reverse('project_detail', args=[pk]))
    style = request.POST.get('style')
    style = style if style in ('compact', 'builtins') else 'compact'
    res = ch.project_complement_masks(project, length, style)
    if res.get('error') == 'no-universe':
        return JsonResponse({'ok': False, 'error': 'no-universe'})
    module = project.hashtype.hashcat_module if project.hashtype else 0
    runner = hc.configured_runner()
    hashfile = '%s.hashes' % project.name
    queued = skipped = 0
    for it in res['items']:
        pattern, custom = it['pattern'], it['custom_charsets']
        signature = sim.signature({'attack_mode': 3, 'mask': pattern})
        # Skip if this exact mask is already recorded/queued/running/done.
        if Run.objects.filter(project=project, attack_mode=3,
                              signature=signature).exclude(
                              status__in=('aborted', 'error')).exists():
            skipped += 1
            continue
        mask, _ = Mask.objects.get_or_create(
            project=project, pattern=pattern, custom_charsets=custom,
            increment_min=None, increment_max=None)
        ch.compute_and_cache_keyspace(mask)
        mask.save()
        command = runner.plan_run(3, module, hashfile=hashfile,
                                  params={'mask': pattern, 'custom_charsets': custom},
                                  optimized=True)
        run = Run.objects.create(mask=mask, project=project, attack_mode=3,
                                 optimized=True, status='planned', command=command,
                                 signature=signature)
        if not project.is_file_backed:
            run.hashes.set(project.hash_set.all())
        launcher.enqueue(run)
        queued += 1
    return JsonResponse({'ok': True, 'queued': queued, 'skipped': skipped})
