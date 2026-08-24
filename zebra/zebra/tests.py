from django.test import SimpleTestCase

from .services import coverage as cov


def P(pattern, **kw):
    return cov.parse_mask(pattern, **kw)


class MaskKeyspaceTests(SimpleTestCase):
    def test_single_mask_products(self):
        self.assertEqual(cov.mask_keyspace(P('?d?d')), 100)
        self.assertEqual(cov.mask_keyspace(P('?l?l')), 26 * 26)
        self.assertEqual(cov.mask_keyspace(P('?a')), 95)
        self.assertEqual(cov.mask_keyspace(P('?b')), 256)
        self.assertEqual(cov.mask_keyspace(P('?u?l?l?l?d?d')),
                         26 * 26 * 26 * 26 * 10 * 10)

    def test_literals_and_escaped_question_mark(self):
        self.assertEqual(cov.mask_keyspace(P('abc?d')), 10)
        self.assertEqual(cov.mask_keyspace(P('?u??')), 26)  # ?? is literal '?'

    def test_custom_charsets_and_wildcards(self):
        self.assertEqual(
            cov.mask_keyspace(P('?1?1', custom_charsets={'1': '?l?d'})), 36 * 36)
        self.assertEqual(
            cov.mask_keyspace(P('?c?c', wildcard_map={'c': 'abcABC'})), 36)

    def test_bad_masks_raise(self):
        with self.assertRaises(cov.MaskParseError):
            P('?l?')            # dangling ?
        with self.assertRaises(cov.MaskParseError):
            P('?z')             # unknown token


class SubsumptionTests(SimpleTestCase):
    def test_subsumed(self):
        self.assertTrue(cov.is_subsumed(P('?l?l'), [P('?a?a')]))
        self.assertTrue(cov.is_subsumed(P('?d'), [P('?a')]))

    def test_not_subsumed_when_disjoint(self):
        self.assertFalse(cov.is_subsumed(P('?d'), [P('?l')]))

    def test_overlap_accounting(self):
        self.assertEqual(cov.overlap_keyspace(P('?l?l'), [P('?a?a')]), 26 * 26)
        self.assertEqual(cov.overlap_keyspace(P('?d'), [P('?l')]), 0)


class UnionTests(SimpleTestCase):
    def test_disjoint_union_is_sum(self):
        self.assertEqual(cov.union_keyspace([P('?u?u'), P('?l?l')]),
                         26 * 26 + 26 * 26)

    def test_overlapping_union_inclusion_exclusion(self):
        # ?a?l U ?l?a : subtract the ?l?l overlap once
        self.assertEqual(cov.union_keyspace([P('?a?l'), P('?l?a')]),
                         95 * 26 + 26 * 95 - 26 * 26)

    def test_three_way_covered_by_superset(self):
        self.assertEqual(
            cov.union_keyspace([P('?a?a'), P('?l?l'), P('?u?u')]), 95 * 95)

    def test_different_length_masks_rejected(self):
        with self.assertRaises(ValueError):
            cov.union_keyspace([P('?d'), P('?d?d')])


class CoverageByLengthTests(SimpleTestCase):
    def test_explicit_universe(self):
        c = cov.coverage_by_length([P('?d?d'), P('?d?d?d')],
                                   universe='0123456789')
        self.assertEqual(c[2], {'covered': 100, 'total': 100, 'masks': 1})
        self.assertEqual(c[3], {'covered': 1000, 'total': 1000, 'masks': 1})

    def test_fallback_universe(self):
        c = cov.coverage_by_length([P('?l?l'), P('?u?l')], universe=None)
        self.assertEqual(c[2]['covered'], 26 * 26 + 26 * 26)
        self.assertEqual(c[2]['total'], 52 * 26)  # pos0=l|u, pos1=l
        self.assertEqual(c[2]['masks'], 2)


from django.test import TestCase

from .models import Project, HashType, Hash, Mask, Run
from . import coverage_helpers as ch


class RunCoverageTests(TestCase):
    """Runs are first-class: only exhausted runs count as covered keyspace."""

    def setUp(self):
        self.ht = HashType.objects.create(name='T-MD5', hashcat_module=0)
        self.project = Project.objects.create(name='RUNTEST', hashtype=self.ht,
                                              universe='0123456789')
        self.h1 = Hash.objects.create(hashstring='h1', project=self.project, cracked=False)
        self.h2 = Hash.objects.create(hashstring='h2', project=self.project, cracked=False)

    def _record(self, pattern, status):
        mask = Mask.objects.create(project=self.project, pattern=pattern)
        ch.compute_and_cache_keyspace(mask); mask.save()
        run = Run.objects.create(mask=mask, project=self.project, attack_mode=3,
                                 status=status)
        run.hashes.set(self.project.hash_set.all())
        return mask, run

    def test_exhausted_run_counts_as_covered(self):
        self._record('?d?d', 'exhausted')
        self.assertEqual(list(ch.covered_masks(self.project).values_list(
            'pattern', flat=True)), ['?d?d'])
        cov = ch.project_coverage(self.project)
        row = next(r for r in cov if r['length'] == 2)
        self.assertEqual(row['covered'], 100)

    def test_planned_run_does_not_count(self):
        self._record('?d?d', 'planned')
        self.assertFalse(ch.covered_masks(self.project).exists())
        self.assertEqual(ch.project_coverage(self.project), [])

    def test_redundancy_only_after_exhausted(self):
        # Saved-but-planned mask must not make an identical candidate redundant.
        self._record('?d?d', 'planned')
        self.assertFalse(ch.evaluate_candidate(self.project, '?d?d')['subsumed'])
        # Once exhausted, the same candidate is redundant.
        self._record('?d?d', 'exhausted')
        self.assertTrue(ch.evaluate_candidate(self.project, '?d?d')['subsumed'])

    def test_run_targets_all_project_hashes(self):
        _, run = self._record('?d?d', 'exhausted')
        self.assertEqual(set(run.hashes.values_list('hashstring', flat=True)),
                         {'h1', 'h2'})  # the project's single hash type = all hashes


class RecordAttackViewTests(TestCase):
    def setUp(self):
        self.ht = HashType.objects.create(name='V-MD5', hashcat_module=0)
        self.project = Project.objects.create(name='VIEWTEST', hashtype=self.ht,
                                              universe='0123456789')
        Hash.objects.create(hashstring='vh1', project=self.project, cracked=False)

    def test_record_attack_creates_run_and_counts_coverage(self):
        url = '/zebra/project/%d/mask/new/' % self.project.pk
        r = self.client.post(url, {'pattern': '?d?d', 'custom_charsets': '',
                                   'status': 'exhausted', 'action': 'record'})
        self.assertEqual(r.status_code, 302)
        run = Run.objects.get(mask__project=self.project)
        self.assertEqual(run.status, 'exhausted')
        self.assertEqual(run.hashes.count(), 1)  # inherits the project's hashes
        # dashboard shows the attack + non-zero coverage
        d = self.client.get('/zebra/project/%d/' % self.project.pk)
        self.assertContains(d, 'Attacks (1)')
        self.assertContains(d, '?d?d')

    def test_planned_attack_contributes_zero_coverage(self):
        url = '/zebra/project/%d/mask/new/' % self.project.pk
        self.client.post(url, {'pattern': '?d?d?d', 'custom_charsets': '',
                               'status': 'planned', 'action': 'record'})
        self.assertTrue(Run.objects.filter(status='planned').exists())
        self.assertEqual(ch.project_coverage(self.project), [])


class AddHashesViewTests(TestCase):
    def setUp(self):
        self.ht = HashType.objects.create(name='A-MD5', hashcat_module=0)
        self.project = Project.objects.create(name='ADDTEST', hashtype=self.ht)
        Hash.objects.create(hashstring='dup', project=self.project, cracked=False)

    def test_add_hashes_dedups_and_skips_existing(self):
        url = '/zebra/project/%d/hashes/add/' % self.project.pk
        r = self.client.post(url, {'hashlist': 'a\nb\na\n dup \n\n'})  # dup + repeat + blank
        self.assertEqual(r.status_code, 200)
        self.assertContains(r, 'Added 2 hash(es)')
        self.assertContains(r, '2 duplicate(s) skipped')  # repeated 'a' + existing 'dup'
        self.assertContains(r, 'A-MD5')  # the project's fixed type is shown
        got = set(self.project.hash_set.values_list('hashstring', flat=True))
        self.assertEqual(got, {'dup', 'a', 'b'})

    def test_add_form_shows_fixed_type_and_no_picker(self):
        d = self.client.get('/zebra/project/%d/hashes/add/' % self.project.pk)
        self.assertContains(d, 'Adding hashes as')
        self.assertContains(d, 'A-MD5')
        self.assertNotContains(d, 'name="hashtype"')  # no per-add type picker

    def test_add_without_project_hashtype_shows_notice(self):
        typeless = Project.objects.create(name='NOTYPE')  # hashtype null
        d = self.client.get('/zebra/project/%d/hashes/add/' % typeless.pk)
        self.assertContains(d, 'no hash type set')
        r = self.client.post('/zebra/project/%d/hashes/add/' % typeless.pk,
                             {'hashlist': 'x'})
        self.assertFalse(typeless.hash_set.exists())


from .services import similarity as sim


def _spec(mode, wl=None, rules=None, **kw):
    return dict(attack_mode=mode, wordlists=wl or [], rules=rules or [], **kw)


class SimilarityEngineTests(SimpleTestCase):
    def test_basename_normalization(self):
        self.assertEqual(sim.normalize_ref('/usr/share/wordlists/rockyou.txt'),
                         'rockyou.txt')
        r = sim.similarity(_spec(0, ['/x/rockyou.txt'], ['BEST64.rule']),
                           _spec(0, ['rockyou.txt'], ['/r/best64.rule']))
        self.assertTrue(r['exact'])

    def test_straight_subset_rules_is_near_redundant(self):
        r = sim.similarity(_spec(0, ['rockyou.txt'], ['best64.rule']),
                           _spec(0, ['rockyou.txt'], ['best64.rule', 'd3ad0ne.rule']))
        self.assertFalse(r['exact'])
        self.assertIn('subset', r['reasons'][0])
        self.assertGreaterEqual(r['score'], 0.5)

    def test_straight_same_wordlist_different_rules(self):
        r = sim.similarity(_spec(0, ['rockyou.txt'], ['best64.rule']),
                           _spec(0, ['rockyou.txt'], ['toggle5.rule']))
        self.assertAlmostEqual(r['score'], 0.5)
        self.assertIn('different rules', r['reasons'][0])

    def test_combinator_reversed_pair(self):
        r = sim.similarity(_spec(1, ['a.txt', 'b.txt']), _spec(1, ['b.txt', 'a.txt']))
        self.assertIn('reversed', r['reasons'][0])

    def test_hybrid_direction_swap(self):
        r = sim.similarity(dict(attack_mode=6, wordlists=['rockyou.txt'], rules=[], mask='?d?d'),
                           dict(attack_mode=7, wordlists=['rockyou.txt'], rules=[], mask='?d?d'))
        self.assertIn('direction swapped', r['reasons'][0])

    def test_incompatible_modes_not_comparable(self):
        self.assertIsNone(sim.similarity(_spec(0, ['a']), _spec(1, ['a', 'b'])))

    def test_find_similar_orders_exact_first(self):
        cand = _spec(0, ['rockyou.txt'], ['best64.rule'])
        existing = [
            ('near', _spec(0, ['rockyou.txt'], ['toggle5.rule'])),
            ('exact', _spec(0, ['rockyou.txt'], ['best64.rule'])),
            ('unrelated', _spec(1, ['a.txt', 'b.txt'])),
        ]
        self.assertEqual([ref for ref, _ in sim.find_similar(cand, existing)],
                         ['exact', 'near'])


from .models import Wordlist, RuleSet


class RecordNonMaskViewTests(TestCase):
    def setUp(self):
        self.ht = HashType.objects.create(name='N-MD5', hashcat_module=0)
        self.project = Project.objects.create(name='NONMASK', hashtype=self.ht)
        Hash.objects.create(hashstring='nh1', project=self.project, cracked=False)
        self.url = '/zebra/project/%d/mask/new/' % self.project.pk

    def _record_straight(self, wordlist, rules):
        return self.client.post(self.url, {
            'attack_mode': '0', 'status': 'exhausted',
            'wordlist': wordlist, 'rules': rules, 'action': 'record'})

    def test_record_straight_creates_run_with_refs_and_project(self):
        r = self._record_straight('/usr/share/wordlists/rockyou.txt', 'best64.rule')
        self.assertEqual(r.status_code, 302)
        run = Run.objects.get(project=self.project)
        self.assertEqual(run.attack_mode, 0)
        self.assertEqual(run.project_id, self.project.pk)
        self.assertEqual([w.name for w in run.wordlists.all()], ['rockyou.txt'])
        self.assertEqual([x.name for x in run.rules.all()], ['best64.rule'])
        self.assertEqual(run.hashes.count(), 1)  # targeted the hashtype's hashes
        # dashboard shows it with the spec + type
        d = self.client.get('/zebra/project/%d/' % self.project.pk)
        self.assertContains(d, 'Straight')
        self.assertContains(d, 'rockyou.txt')

    def test_exact_duplicate_is_flagged_on_preview(self):
        self._record_straight('rockyou.txt', 'best64.rule')
        r = self.client.post(self.url, {
            'attack_mode': '0', 'status': 'exhausted',
            'wordlist': 'rockyou.txt', 'rules': 'best64.rule', 'action': 'preview'})
        self.assertContains(r, 'Duplicate')

    def test_superset_rules_flagged_near_duplicate(self):
        self._record_straight('rockyou.txt', 'best64.rule')
        r = self.client.post(self.url, {
            'attack_mode': '0', 'status': 'planned',
            'wordlist': 'rockyou.txt', 'rules': 'best64.rule\nd3ad0ne.rule',
            'action': 'preview'})
        self.assertContains(r, 'Near-duplicate')
        self.assertContains(r, 'subset')

    def test_combinator_records_ordered_pair(self):
        r = self.client.post(self.url, {
            'attack_mode': '1', 'status': 'exhausted',
            'left_wordlist': 'left.txt', 'right_wordlist': 'right.txt', 'action': 'record'})
        self.assertEqual(r.status_code, 302)
        run = Run.objects.get(project=self.project, attack_mode=1)
        order_names = [Wordlist.objects.get(pk=i).name for i in run.params['order']]
        self.assertEqual(order_names, ['left.txt', 'right.txt'])
        self.assertEqual(run.describe(), 'left.txt × right.txt')

    def test_hybrid_records_wordlist_and_mask(self):
        r = self.client.post(self.url, {
            'attack_mode': '6', 'status': 'exhausted',
            'wordlist': 'rockyou.txt', 'pattern': '?d?d?d', 'action': 'record'})
        self.assertEqual(r.status_code, 302)
        run = Run.objects.get(project=self.project, attack_mode=6)
        self.assertEqual(run.params.get('mask'), '?d?d?d')
        self.assertEqual(run.describe(), 'rockyou.txt + ?d?d?d')
        # hybrid mask must NOT pollute exact mask coverage
        self.assertEqual(ch.covered_masks(self.project).count(), 0)

    def test_missing_wordlist_rejected(self):
        r = self.client.post(self.url, {
            'attack_mode': '0', 'status': 'exhausted',
            'wordlist': '', 'rules': '', 'action': 'record'})
        self.assertContains(r, 'needs a wordlist')
        self.assertFalse(Run.objects.filter(project=self.project).exists())

    def test_mask_mode_still_gets_exact_coverage(self):
        # regression: mode 3 unchanged
        r = self.client.post(self.url, {
            'attack_mode': '3', 'status': 'exhausted',
            'pattern': '?d?d', 'custom_charsets': '', 'action': 'record'})
        self.assertEqual(r.status_code, 302)
        run = Run.objects.get(project=self.project, attack_mode=3)
        self.assertIsNotNone(run.mask)
        self.assertEqual(ch.covered_masks(self.project).count(), 1)


class AttackModeSelectRegressionTests(TestCase):
    """Regression: -a 0 (a falsy value) must stay selected after a preview
    re-render, instead of the select snapping back to the -a 3 default."""

    def setUp(self):
        self.ht = HashType.objects.create(name='S-MD5', hashcat_module=0)
        self.project = Project.objects.create(name='SELREG', hashtype=self.ht)
        Hash.objects.create(hashstring='s1', project=self.project, cracked=False)
        self.url = '/zebra/project/%d/mask/new/' % self.project.pk

    def test_preview_keeps_mode_zero_selected(self):
        r = self.client.post(self.url, {
            'attack_mode': '0', 'status': 'exhausted',
            'wordlist': 'rockyou.txt', 'rules': 'best64.rule', 'action': 'preview'})
        self.assertContains(r, '<option value="0" selected>')
        self.assertNotContains(r, '<option value="3" selected>')

    def test_get_defaults_to_mask_mode(self):
        r = self.client.get(self.url)
        self.assertContains(r, '<option value="3" selected>')
        self.assertNotContains(r, '<option value="0" selected>')


class RunDetailViewTests(TestCase):
    def setUp(self):
        self.ht = HashType.objects.create(name='D-MD5', hashcat_module=0)
        self.project = Project.objects.create(name='DETAIL', hashtype=self.ht,
                                              universe='0123456789')
        Hash.objects.create(hashstring='dh1', project=self.project, cracked=False)
        self.url = '/zebra/project/%d/mask/new/' % self.project.pk

    def _last_run(self):
        return Run.objects.filter(project=self.project).latest('pk')

    def test_project_page_links_to_attack_detail(self):
        self.client.post(self.url, {'attack_mode': '0', 'status': 'exhausted',
                                    'wordlist': 'rockyou.txt', 'rules': 'best64.rule',
                                    'action': 'record'})
        run = self._last_run()
        d = self.client.get('/zebra/project/%d/' % self.project.pk)
        self.assertContains(d, '/zebra/run/%d/' % run.pk)

    def test_straight_detail_shows_specs_and_command(self):
        self.client.post(self.url, {'attack_mode': '0', 'status': 'exhausted',
                                    'wordlist': '/wl/rockyou.txt', 'rules': 'best64.rule',
                                    'action': 'record'})
        run = self._last_run()
        r = self.client.get('/zebra/run/%d/' % run.pk)
        self.assertEqual(r.status_code, 200)
        self.assertContains(r, 'Exact hashcat command')
        self.assertContains(r, 'hashcat -m 0 -a 0')       # the recorded command
        self.assertContains(r, 'Wordlist(s)')
        self.assertContains(r, 'rockyou.txt')
        self.assertContains(r, 'best64.rule')
        self.assertContains(r, 'D-MD5')                    # project hash type shown

    def test_combinator_detail_shows_ordered_pair(self):
        self.client.post(self.url, {'attack_mode': '1', 'status': 'exhausted',
                                    'left_wordlist': 'a.txt', 'right_wordlist': 'b.txt',
                                    'left_rule': 'c', 'action': 'record'})
        run = self._last_run()
        r = self.client.get('/zebra/run/%d/' % run.pk)
        self.assertContains(r, 'Left wordlist')
        self.assertContains(r, 'a.txt')
        self.assertContains(r, 'Right wordlist')
        self.assertContains(r, '-j (left rule)')

    def test_mask_detail_shows_keyspace(self):
        self.client.post(self.url, {'attack_mode': '3', 'pattern': '?d?d',
                                    'custom_charsets': '', 'status': 'exhausted',
                                    'action': 'record'})
        run = self._last_run()
        r = self.client.get('/zebra/run/%d/' % run.pk)
        self.assertContains(r, 'Keyspace')
        self.assertContains(r, '100')


class RunDeleteViewTests(TestCase):
    def setUp(self):
        self.ht = HashType.objects.create(name='X-MD5', hashcat_module=0)
        self.project = Project.objects.create(name='DELPROJ', hashtype=self.ht,
                                              universe='0123456789')
        Hash.objects.create(hashstring='xh1', project=self.project, cracked=False)
        self.url = '/zebra/project/%d/mask/new/' % self.project.pk

    def _record(self, **extra):
        data = {'status': 'exhausted', 'action': 'record'}
        data.update(extra)
        self.client.post(self.url, data)
        return Run.objects.filter(project=self.project).latest('pk')

    def test_post_deletes_run_and_redirects_to_project(self):
        run = self._record(attack_mode='0', wordlist='rockyou.txt', rules='best64.rule')
        r = self.client.post('/zebra/run/%d/delete/' % run.pk)
        self.assertRedirects(r, '/zebra/project/%d/' % self.project.pk)
        self.assertFalse(Run.objects.filter(pk=run.pk).exists())

    def test_get_does_not_delete(self):
        run = self._record(attack_mode='0', wordlist='rockyou.txt', rules='')
        r = self.client.get('/zebra/run/%d/delete/' % run.pk)
        self.assertRedirects(r, '/zebra/run/%d/' % run.pk)
        self.assertTrue(Run.objects.filter(pk=run.pk).exists())

    def test_deleting_mask_run_drops_coverage_and_orphan_mask(self):
        run = self._record(attack_mode='3', pattern='?d?d', custom_charsets='')
        self.assertEqual(ch.covered_masks(self.project).count(), 1)
        mask_pk = run.mask_id
        self.client.post('/zebra/run/%d/delete/' % run.pk)
        self.assertEqual(ch.covered_masks(self.project).count(), 0)
        self.assertFalse(Mask.objects.filter(pk=mask_pk).exists())  # orphan cleaned up

    def test_shared_mask_kept_when_another_run_uses_it(self):
        r1 = self._record(attack_mode='3', pattern='?d?d', custom_charsets='')
        r2 = self._record(attack_mode='3', pattern='?d?d', custom_charsets='')
        self.assertEqual(r1.mask_id, r2.mask_id)  # get_or_create reuses the mask
        self.client.post('/zebra/run/%d/delete/' % r1.pk)
        self.assertTrue(Mask.objects.filter(pk=r1.mask_id).exists())  # r2 still uses it

    def test_delete_button_on_detail_page(self):
        run = self._record(attack_mode='0', wordlist='rockyou.txt', rules='')
        d = self.client.get('/zebra/run/%d/' % run.pk)
        self.assertContains(d, '/zebra/run/%d/delete/' % run.pk)
        self.assertContains(d, 'Delete attack')


import os
import stat
import subprocess
import tempfile
from unittest import mock

from django.test import TransactionTestCase

from .services import hashcat as hc
from .services import launcher


def _write_stub(dirpath, body):
    """Write an executable stub 'hashcat' script and return its path."""
    path = os.path.join(dirpath, 'hashcat_stub.sh')
    with open(path, 'w') as f:
        f.write('#!/bin/sh\n' + body)
    os.chmod(path, os.stat(path).st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
    return path


class LauncherUnitTests(TestCase):
    def setUp(self):
        self.ht = HashType.objects.create(name='L-MD5', hashcat_module=0)
        self.project = Project.objects.create(name='LAUNCH', hashtype=self.ht)
        self.h = Hash.objects.create(hashstring='5f4dcc3b', project=self.project,
                                     cracked=False)

    def _mask_run(self, pattern='?d?d', status='planned'):
        mask = Mask.objects.create(project=self.project, pattern=pattern)
        run = Run.objects.create(mask=mask, project=self.project, attack_mode=3,
                                 status=status)
        run.hashes.set(self.project.hash_set.all())
        return run

    def test_final_status_mapping(self):
        self.assertEqual(launcher._final_status(0), 'cracked')
        self.assertEqual(launcher._final_status(1), 'exhausted')
        for code in (2, 3, 4):
            self.assertEqual(launcher._final_status(code), 'aborted')
        import signal
        self.assertEqual(launcher._final_status(-signal.SIGINT), 'aborted')  # Stop
        self.assertEqual(launcher._final_status(255), 'error')

    def test_materialize_hashfile_writes_project_hashes(self):
        Hash.objects.create(hashstring='deadbeef', project=self.project, cracked=False)
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, 'h.txt')
            launcher._materialize_hashfile(self.project, path)
            self.assertEqual(sorted(open(path).read().split()),
                             ['5f4dcc3b', 'deadbeef'])

    def test_start_refused_without_hashcat(self):
        run = self._mask_run()
        runner = hc.HashcatRunner(binary='zzz-not-a-real-binary')
        self.assertIn('not installed', launcher.start_run(run, runner=runner))

    def test_start_refused_for_non_mask(self):
        with tempfile.TemporaryDirectory() as d:
            runner = hc.HashcatRunner(binary=_write_stub(d, 'exit 0\n'))
            run = Run.objects.create(project=self.project, attack_mode=0,
                                     status='planned')
            self.assertIn('Only mask attacks', launcher.start_run(run, runner=runner))

    def test_start_refused_when_another_running(self):
        self._mask_run(status='running')          # occupies the GPU
        run = self._mask_run(pattern='?d?d?d')
        with tempfile.TemporaryDirectory() as d:
            runner = hc.HashcatRunner(binary=_write_stub(d, 'exit 1\n'))
            self.assertIn('already running', launcher.start_run(run, runner=runner))


class LauncherExecuteTests(TransactionTestCase):
    """Drive the spawn->stream->finalise->ingest path with a stub binary,
    synchronously (TransactionTestCase so the launcher's connection.close is safe)."""

    def setUp(self):
        self.ht = HashType.objects.create(name='E-MD5', hashcat_module=0)
        self.project = Project.objects.create(name='EXECPROJ', hashtype=self.ht)
        self.h = Hash.objects.create(hashstring='aaa', project=self.project,
                                     cracked=False)
        self.mask = Mask.objects.create(project=self.project, pattern='?d?d')
        self.run = Run.objects.create(mask=self.mask, project=self.project,
                                      attack_mode=3, status='running')
        self.run.hashes.set(self.project.hash_set.all())

    def test_execute_finalises_exhausted_and_ingests_cracks(self):
        d = tempfile.mkdtemp()
        pot = os.path.join(d, 'zebra.pot')
        open(pot, 'w').write('aaa:secret\n')  # hashcat would write this potfile
        # stub emits one status line (progress 1.0, speed 1234) then exits 1 = exhausted
        stub = _write_stub(
            d, "echo '{\"progress\":[100,100],\"devices\":[{\"speed\":1234}],\"status\":3}'\nexit 1\n")
        proc = subprocess.Popen([stub], stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT)
        launcher._execute(self.run, proc, proc.stdout.fileno(), d, pot)

        self.run.refresh_from_db()
        self.assertEqual(self.run.status, 'exhausted')
        self.assertEqual(self.run.progress, 1.0)
        self.assertEqual(int(self.run.speed_hs), 1234)
        self.assertIsNotNone(self.run.ended_at)
        self.assertIsNone(self.run.pid)
        self.h.refresh_from_db()
        self.assertTrue(self.h.cracked)
        self.assertTrue(self.h.cracks.filter(plaintext='secret').exists())

    def test_execute_maps_cracked_returncode(self):
        d = tempfile.mkdtemp()
        pot = os.path.join(d, 'zebra.pot')
        stub = _write_stub(d, "exit 0\n")  # all cracked
        proc = subprocess.Popen([stub], stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT)
        launcher._execute(self.run, proc, proc.stdout.fileno(), d, pot)
        self.run.refresh_from_db()
        self.assertEqual(self.run.status, 'cracked')


class RunLaunchTemplateTests(TestCase):
    def setUp(self):
        self.ht = HashType.objects.create(name='TL-MD5', hashcat_module=0)
        self.project = Project.objects.create(name='TMPL', hashtype=self.ht)
        Hash.objects.create(hashstring='th', project=self.project, cracked=False)

    def _run(self, mode, **kw):
        return Run.objects.create(project=self.project, attack_mode=mode, **kw)

    @mock.patch('zebra.services.hashcat.HashcatRunner.available', return_value=True)
    def test_mask_run_shows_run_button(self, _avail):
        mask = Mask.objects.create(project=self.project, pattern='?d?d')
        run = self._run(3, mask=mask, status='planned')
        d = self.client.get('/zebra/run/%d/' % run.pk)
        self.assertContains(d, 'Run attack')
        self.assertContains(d, '/zebra/run/%d/start/' % run.pk)

    def test_non_mask_run_shows_not_supported_note(self):
        run = self._run(0, status='planned')
        d = self.client.get('/zebra/run/%d/' % run.pk)
        self.assertContains(d, "isn't supported yet")

    @mock.patch('zebra.services.hashcat.HashcatRunner.available', return_value=True)
    def test_running_shows_stop_and_progress(self, _avail):
        mask = Mask.objects.create(project=self.project, pattern='?d?d')
        run = self._run(3, mask=mask, status='running', progress=0.5)
        d = self.client.get('/zebra/run/%d/' % run.pk)
        self.assertContains(d, 'Running')
        self.assertContains(d, '/zebra/run/%d/stop/' % run.pk)


from io import BytesIO


class HashlistUploadTests(TestCase):
    def setUp(self):
        self.ht = HashType.objects.create(name='U-MD5', hashcat_module=0)
        self.project = Project.objects.create(name='UPLOAD', hashtype=self.ht)

    def _file(self, text, name='hashes.txt'):
        f = BytesIO(text.encode())
        f.name = name
        return f

    def test_add_hashes_from_uploaded_file(self):
        url = '/zebra/project/%d/hashes/add/' % self.project.pk
        r = self.client.post(url, {'hashlist': '', 'hashfile': self._file('a\nb\nc\n')})
        self.assertContains(r, 'Added 3 hash(es)')
        self.assertEqual(set(self.project.hash_set.values_list('hashstring', flat=True)),
                         {'a', 'b', 'c'})

    def test_textarea_and_file_combine_and_dedup(self):
        url = '/zebra/project/%d/hashes/add/' % self.project.pk
        r = self.client.post(url, {'hashlist': 'a\nb', 'hashfile': self._file('b\nc\n')})
        self.assertContains(r, 'Added 3 hash(es)')  # a,b,c ; the duplicate b skipped
        self.assertEqual(set(self.project.hash_set.values_list('hashstring', flat=True)),
                         {'a', 'b', 'c'})

    def test_new_project_accepts_uploaded_hashlist(self):
        Project.objects.filter(name='UPFROMNEW').delete()
        r = self.client.post('/zebra/project/new/', {
            'name': 'UPFROMNEW', 'hashtype': str(self.ht.pk), 'hashlist': '',
            'hashfile': self._file('h1\nh2\n')})
        self.assertEqual(r.status_code, 302)
        p = Project.objects.get(name='UPFROMNEW')
        self.assertEqual(p.hash_set.count(), 2)

    def test_add_form_is_multipart(self):
        d = self.client.get('/zebra/project/%d/hashes/add/' % self.project.pk)
        self.assertContains(d, 'enctype="multipart/form-data"')
        self.assertContains(d, 'name="hashfile"')


class ExpandCharsetTests(SimpleTestCase):
    def test_shorthands(self):
        self.assertEqual(len(cov.expand_charset('?d')), 10)
        self.assertEqual(len(cov.expand_charset('?l?u?d')), 62)
        self.assertEqual(len(cov.expand_charset('?a')), 95)

    def test_literals_and_mix(self):
        self.assertEqual(cov.expand_charset('abc012'), set('abc012'))
        self.assertEqual(cov.expand_charset('?dxy'), set('0123456789xy'))

    def test_unknown_token_raises(self):
        with self.assertRaises(cov.MaskParseError):
            cov.expand_charset('?z')


class UniverseCoverageTests(TestCase):
    def setUp(self):
        self.ht = HashType.objects.create(name='UNI-MD5', hashcat_module=0)

    def _covered(self, universe):
        p = Project.objects.create(name='U-' + str(universe), hashtype=self.ht,
                                   universe=universe)
        Hash.objects.create(hashstring='u', project=p, cracked=False)
        mask = Mask.objects.create(project=p, pattern='?d?d')
        run = Run.objects.create(mask=mask, project=p, attack_mode=3, status='exhausted')
        run.hashes.set(p.hash_set.all())
        return ch.project_coverage(p)

    def test_shorthand_universe_matches_literal(self):
        # '?d' should give the same length-2 total (10**2) as the literal digits
        row_short = next(r for r in self._covered('?d') if r['length'] == 2)
        row_lit = next(r for r in self._covered('0123456789') if r['length'] == 2)
        self.assertEqual(row_short['total'], 100)
        self.assertEqual(row_lit['total'], 100)


class UniverseFormTests(TestCase):
    def setUp(self):
        self.ht = HashType.objects.create(name='UF-MD5', hashcat_module=0)

    def _create(self, name, **extra):
        data = {'name': name, 'hashtype': str(self.ht.pk), 'hashlist': ''}
        data.update(extra)
        return self.client.post('/zebra/project/new/', data)

    def test_preset_digits_stored_as_shorthand(self):
        self._create('UP1', universe='digits')
        self.assertEqual(Project.objects.get(name='UP1').universe, '?d')

    def test_preset_all(self):
        self._create('UP2', universe='all')
        self.assertEqual(Project.objects.get(name='UP2').universe, '?a')

    def test_custom_universe_with_shorthands(self):
        self._create('UP3', universe='custom', universe_custom='?l?d')
        self.assertEqual(Project.objects.get(name='UP3').universe, '?l?d')

    def test_invalid_custom_universe_rejected(self):
        r = self._create('UP4', universe='custom', universe_custom='?z')
        self.assertContains(r, 'Invalid custom universe')
        self.assertFalse(Project.objects.filter(name='UP4').exists())

    def test_none_stores_null(self):
        self._create('UP5', universe='')
        self.assertIsNone(Project.objects.get(name='UP5').universe)

    def test_form_lists_presets(self):
        d = self.client.get('/zebra/project/new/')
        self.assertContains(d, 'Only digits (?d)')
        self.assertContains(d, 'Alphanumeric (?l?u?d)')
        self.assertContains(d, 'All printable (?a)')
        self.assertContains(d, 'name="universe_custom"')
