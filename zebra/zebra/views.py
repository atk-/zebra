from decimal import Decimal

from django.shortcuts import render, get_object_or_404, redirect
from django.urls import reverse
from django.http import JsonResponse

from .models import Project, Mask, HashType, Hash, Run, Wordlist, RuleSet
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


def project_detail(request, pk):
    project = get_object_or_404(Project, pk=pk)
    hashes = project.hash_set.all()
    cracked = hashes.filter(cracked=True).count()
    total_hashes = hashes.count()
    context = {
        'project': project,
        'hashes': hashes,
        'cracked': cracked,
        'total_hashes': total_hashes,
        'cracked_pct': (100.0 * cracked / total_hashes) if total_hashes else 0.0,
        'coverage': ch.project_coverage(project),
        'universe_chars': ch.expand_universe(project.universe),
        'runs': (Run.objects.filter(project=project).select_related('mask')
                 .prefetch_related('cracks', 'hashes', 'wordlists', 'rules')[:50]),
    }
    return render(request, 'zebra/project_detail.html', context)


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
        if run.mask.keyspace is not None:
            specs.append(('Keyspace', run.mask.keyspace))
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
        'hashcat_available': hc.HashcatRunner().available(),
        'launch_error': request.GET.get('error'),
    }
    return render(request, 'zebra/run_detail.html', context)


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
    })

    module = project.hashtype.hashcat_module
    runner = hc.HashcatRunner()
    hashfile = '%s.hashes' % project.name

    # --- Mask (attack mode 3): exact coverage path (unchanged behaviour) ---
    if attack_mode == 3:
        evaluation = ch.evaluate_candidate(project, pattern, custom)
        context['evaluation'] = evaluation
        if evaluation.get('error'):
            return render(request, 'zebra/mask_new.html', context)
        context['command'] = runner.plan_run(
            3, module, hashfile=hashfile,
            params={'mask': pattern, 'custom_charsets': custom})
        context['can_record'] = True
        if action == 'record':
            mask, _ = Mask.objects.get_or_create(
                project=project, pattern=pattern, custom_charsets=custom)
            ch.compute_and_cache_keyspace(mask)
            mask.save()
            run = Run.objects.create(
                mask=mask, project=project, attack_mode=3,
                device=device or None, status=status, command=context['command'],
                signature=sim.signature({'attack_mode': 3, 'mask': pattern}))
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


def coverage_decomposition_json(request, pk, length):
    """Disjoint-cell decomposition for one password length (search-space viz).

    Fetched lazily by the dashboard when a coverage row is expanded, so
    project_detail itself stays cheap for large campaigns.
    """
    project = get_object_or_404(Project, pk=pk)
    return JsonResponse(ch.project_length_decomposition(project, length))
