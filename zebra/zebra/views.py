import shutil
from decimal import Decimal

from django.shortcuts import render, get_object_or_404, redirect
from django.urls import reverse
from django.http import JsonResponse

from .models import Project, Mask, HashType, Hash, Run, Wordlist, RuleSet, Settings
from . import coverage_helpers as ch
from . import run_helpers as rh
from .services import hashcat as hc
from .services import similarity as sim
from .services import coverage as cov
from .services import launcher
from urllib.parse import quote


def index(request):
    projects = Project.objects.all()
    return render(request, 'zebra/index.html', {'projects': projects})


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
        universe, universe_error = _resolve_universe(request)
        context.update({'name': name, 'description': description,
                        'hashtype_id': hashtype_id, 'hashlist': hashlist_raw,
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
    project = get_object_or_404(Project, pk=pk)
    hashes = project.hash_set.all()
    cracked = hashes.filter(cracked=True).count()
    total_hashes = hashes.count()
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
        'runs': (Run.objects.filter(project=project).select_related('mask')
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
        'target_count': run.hashes.count(),
        'hashcat_available': hc.configured_runner().available(),
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
        'cracks': run.cracks.count(),
        # --increment sweep position: 1-based current sub-run and the total.
        # increment_offset is already 1-based (hashcat's guess_base_offset).
        'run_index': run.increment_offset,
        'run_total': run.increment_count,
    })


def run_start(request, pk):
    """Launch a mask attack with hashcat (POST-only)."""
    run = get_object_or_404(Run, pk=pk)
    detail = reverse('run_detail', args=[pk])
    if request.method != 'POST':
        return redirect(detail)
    err = launcher.start_run(run)
    return redirect(detail + ('?error=' + quote(err) if err else ''))


def run_stop(request, pk):
    """Signal a running attack to stop (POST-only)."""
    run = get_object_or_404(Run, pk=pk)
    detail = reverse('run_detail', args=[pk])
    if request.method != 'POST':
        return redirect(detail)
    err = launcher.stop_run(run)
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
        'recent': recent,
    })


def run_delete(request, pk):
    """Remove an attack (typo/error). POST-only; GET falls back to the detail page."""
    run = get_object_or_404(Run, pk=pk)
    if request.method != 'POST':
        return redirect(reverse('run_detail', args=[pk]))
    project_pk = run.project_id
    mask = run.mask
    run.delete()
    # Tidy up a mode-3 mask left with no runs (created for this attack alone).
    if mask and not mask.runs.exists():
        mask.delete()
    if project_pk:
        return redirect(reverse('project_detail', args=[project_pk]))
    return redirect(reverse('index'))


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


def hashes_add(request, pk):
    project = get_object_or_404(Project, pk=pk)
    context = {'project': project}
    if request.method == 'POST':
        hashlist_raw = request.POST.get('hashlist') or ''
        context['hashlist'] = hashlist_raw
        if project.hashtype is None:
            context['error'] = ('This project has no hash type set. Set one in the '
                                'admin before adding hashes.')
        else:
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
    }
    if request.method != 'POST' or project.hashtype is None:
        # Prefill the mask from query params (e.g. the recommender's "Record"
        # link) so the form opens ready to evaluate/record.
        context['pattern'] = (request.GET.get('pattern') or '').strip()
        context['increment'] = bool(request.GET.get('increment'))
        context['increment_max'] = (request.GET.get('increment_max') or '').strip()
        return render(request, 'zebra/mask_new.html', context)

    # --- common inputs (echoed back for re-render) ---
    try:
        attack_mode = int(request.POST.get('attack_mode') or 3)
    except ValueError:
        attack_mode = 3
    status = request.POST.get('status') or 'planned'
    device = (request.POST.get('device') or '').strip()
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
        # Concrete max (evaluate defaults a blank increment-max to the mask length).
        inc_max = evaluation.get('increment_max')
        mask_params = {'mask': pattern, 'custom_charsets': custom,
                       'increment_min': inc_min, 'increment_max': inc_max}
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
            3, module, hashfile=hashfile, params=mask_params)
        context['can_record'] = True
        if action == 'record':
            mask, _ = Mask.objects.get_or_create(
                project=project, pattern=pattern, custom_charsets=custom,
                increment_min=inc_min, increment_max=inc_max)
            ch.compute_and_cache_keyspace(mask)
            mask.save()
            sig_spec = {'attack_mode': 3, 'mask': pattern}
            if inc_min is not None:
                sig_spec['increment'] = [inc_min, inc_max]
            run = Run.objects.create(
                mask=mask, project=project, attack_mode=3,
                device=device or None, status=status, command=context['command'],
                signature=sim.signature(sig_spec))
            run.hashes.set(project.hash_set.all())
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
        rules=rule_names, params=params)
    context['can_record'] = not missing
    if missing:
        context['error'] = ('This attack needs %s.' %
                            ('two wordlists' if attack_mode == 1
                             else 'a wordlist and a mask' if attack_mode in (6, 7)
                             else 'a wordlist'))
        return render(request, 'zebra/mask_new.html', context)

    if action == 'record':
        wl_objs = rh.resolve_wordlists(wl_names)
        rule_objs = rh.resolve_rules(rule_names)
        if attack_mode == 1:
            params['order'] = [w.id for w in wl_objs]
        run = Run.objects.create(
            project=project, attack_mode=attack_mode,
            device=device or None, status=status, command=context['command'],
            params=params, signature=sim.signature(candidate_spec))
        run.wordlists.set(wl_objs)
        run.rules.set(rule_objs)
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
        config.save()
        saved = True
    binary = hc.configured_binary()
    resolved = shutil.which(binary)
    context = {
        'settings': config,
        'saved': saved,
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
