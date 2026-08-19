from decimal import Decimal

from django.shortcuts import render, get_object_or_404, redirect
from django.urls import reverse

from .models import Project, Mask, HashType, Run
from . import coverage_helpers as ch
from .services import hashcat as hc


def index(request):
    projects = Project.objects.all()
    return render(request, 'zebra/index.html', {'projects': projects})


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
        'runs': Run.objects.filter(mask__project=project)[:50],
    }
    return render(request, 'zebra/project_detail.html', context)


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
    context = {
        'project': project,
        'hashtypes': HashType.objects.all(),
    }
    if request.method == 'POST':
        pattern = (request.POST.get('pattern') or '').strip()
        custom = _parse_custom_charsets(request.POST.get('custom_charsets'))
        module = request.POST.get('module') or '0'
        context.update({'pattern': pattern,
                        'custom_charsets_raw': request.POST.get('custom_charsets', ''),
                        'module': module})
        evaluation = ch.evaluate_candidate(project, pattern, custom)
        context['evaluation'] = evaluation

        if not evaluation.get('error'):
            runner = hc.HashcatRunner()
            context['command'] = runner.plan(module, pattern,
                                             hashfile='%s.hashes' % project.name,
                                             custom_charsets=custom)
            if request.POST.get('action') == 'save':
                mask = Mask(project=project, pattern=pattern, custom_charsets=custom)
                ch.compute_and_cache_keyspace(mask)
                mask.save()
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
