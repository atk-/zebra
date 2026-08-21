from decimal import Decimal

from django.shortcuts import render, get_object_or_404, redirect
from django.urls import reverse

from .models import Project, Mask, HashType, Hash, Run
from . import coverage_helpers as ch
from .services import hashcat as hc


def index(request):
    projects = Project.objects.all()
    return render(request, 'zebra/index.html', {'projects': projects})


def project_new(request):
    hashtypes = HashType.objects.all()
    context = {'hashtypes': hashtypes}
    if request.method == 'POST':
        name = (request.POST.get('name') or '').strip()
        description = (request.POST.get('description') or '').strip()
        universe = (request.POST.get('universe') or '').strip()
        hashtype_id = request.POST.get('hashtype')
        hashlist_raw = request.POST.get('hashlist') or ''
        context.update({'name': name, 'description': description,
                        'universe': universe, 'hashtype_id': hashtype_id,
                        'hashlist': hashlist_raw})

        hashtype = hashtypes.filter(pk=hashtype_id).first() if hashtype_id else None
        if not name:
            context['error'] = 'Project name is required.'
        elif Project.objects.filter(name=name).exists():
            context['error'] = 'A project named "%s" already exists.' % name
        elif hashtype is None:
            context['error'] = 'Please choose a hashtype.'
        else:
            project = Project.objects.create(
                name=name, description=description or None,
                universe=universe or None)
            _create_hashes(project, hashtype, hashlist_raw)
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
        'runs': (Run.objects.filter(mask__project=project)
                 .select_related('mask', 'hashtype').prefetch_related('cracks', 'hashes')[:50]),
    }
    return render(request, 'zebra/project_detail.html', context)


def _create_hashes(project, hashtype, raw):
    """Create one Hash per unique, non-empty line of ``raw``.

    Skips lines already present for this (project, hashtype) and duplicates
    within the submission. Returns (added, skipped).
    """
    existing = set(project.hash_set.filter(hashtype=hashtype)
                   .values_list('hashstring', flat=True))
    seen, rows, skipped = set(), [], 0
    for line in (raw or '').splitlines():
        line = line.strip()
        if not line:
            continue
        if line in seen or line in existing:
            skipped += 1
            continue
        seen.add(line)
        rows.append(Hash(hashstring=line, hashtype=hashtype,
                         project=project, cracked=False))
    if rows:
        Hash.objects.bulk_create(rows)
    return len(rows), skipped


def hashes_add(request, pk):
    project = get_object_or_404(Project, pk=pk)
    hashtypes = HashType.objects.all()
    context = {'project': project, 'hashtypes': hashtypes}
    if request.method == 'POST':
        hashtype_id = request.POST.get('hashtype')
        hashtype = hashtypes.filter(pk=hashtype_id).first() if hashtype_id else None
        hashlist_raw = request.POST.get('hashlist') or ''
        context.update({'hashtype_id': hashtype_id, 'hashlist': hashlist_raw})
        if hashtype is None:
            context['error'] = 'Please choose a hashtype.'
        else:
            added, skipped = _create_hashes(project, hashtype, hashlist_raw)
            context['message'] = (
                'Added %d hash(es) as %s%s.'
                % (added, hashtype.name,
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
    project = get_object_or_404(Project, pk=pk)
    # Hashtypes actually present in this project (a mask attack targets one module).
    hashtypes = HashType.objects.filter(hash__project=project).distinct()
    context = {
        'project': project,
        'hashtypes': hashtypes,
        'statuses': Run.STATUS_CHOICES,
        'default_status': 'exhausted',
    }
    if request.method == 'POST':
        pattern = (request.POST.get('pattern') or '').strip()
        custom = _parse_custom_charsets(request.POST.get('custom_charsets'))
        hashtype_id = request.POST.get('hashtype')
        hashtype = hashtypes.filter(pk=hashtype_id).first() if hashtype_id else None
        status = request.POST.get('status') or 'exhausted'
        device = (request.POST.get('device') or '').strip()
        context.update({'pattern': pattern,
                        'custom_charsets_raw': request.POST.get('custom_charsets', ''),
                        'hashtype_id': request.POST.get('hashtype'),
                        'status': status, 'device': device})

        evaluation = ch.evaluate_candidate(project, pattern, custom)
        context['evaluation'] = evaluation

        if not evaluation.get('error'):
            module = hashtype.hashcat_module if hashtype else 0
            runner = hc.HashcatRunner()
            command = runner.plan(module, pattern,
                                  hashfile='%s.hashes' % project.name,
                                  custom_charsets=custom)
            context['command'] = command

            if request.POST.get('action') == 'record':
                if hashtype is None:
                    context['error'] = 'Please choose a hashtype for this attack.'
                    return render(request, 'zebra/mask_new.html', context)
                mask, _ = Mask.objects.get_or_create(
                    project=project, pattern=pattern, custom_charsets=custom)
                ch.compute_and_cache_keyspace(mask)
                mask.save()
                run = Run.objects.create(
                    mask=mask, attack_mode=3, hashtype=hashtype,
                    device=device or None, status=status, command=command)
                run.hashes.set(project.hash_set.filter(hashtype=hashtype))
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
