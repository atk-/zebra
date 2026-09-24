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
        # 'w' is not a builtin, so a project wildcard defines it (unlike 'c', which
        # is now the builtin ?a-complement and takes precedence over any wildcard).
        self.assertEqual(
            cov.mask_keyspace(P('?w?w', wildcard_map={'w': 'abcABC'})), 36)

    def test_b_and_c_builtins(self):
        self.assertEqual(cov.mask_keyspace(P('?b')), 256)          # any byte
        self.assertEqual(cov.mask_keyspace(P('?c')), 256 - 95)     # complement of ?a
        # ?a and ?c partition the byte space with no overlap and full cover.
        a, c = set(cov.BUILTIN_CHARSETS['a']), set(cov.BUILTIN_CHARSETS['c'])
        self.assertEqual(a & c, set())
        self.assertEqual(a | c, set(cov.BUILTIN_CHARSETS['b']))

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

    def test_exhausted_mask_detail_hides_run_controls(self):
        from unittest import mock
        self.client.post(self.url, {'attack_mode': '3', 'pattern': '?d?d',
                                    'custom_charsets': '', 'status': 'exhausted',
                                    'action': 'record'})
        run = self._last_run()
        with mock.patch('zebra.services.hashcat.HashcatRunner.available',
                        return_value=True):
            r = self.client.get('/zebra/run/%d/' % run.pk)
        self.assertNotContains(r, 'Run attack')
        self.assertNotContains(r, 'Add to queue')
        self.assertContains(r, 'nothing left to run')

    def test_planned_mask_detail_shows_single_run_button(self):
        # One unconditional label -- the action runs when idle and queues when busy,
        # so there's no separate "Add to queue" button to reason about.
        from unittest import mock
        self.client.post(self.url, {'attack_mode': '3', 'pattern': '?d?d',
                                    'custom_charsets': '', 'status': 'planned',
                                    'action': 'record'})
        run = self._last_run()
        with mock.patch('zebra.services.hashcat.HashcatRunner.available',
                        return_value=True):
            r = self.client.get('/zebra/run/%d/' % run.pk)
        self.assertContains(r, 'Run attack')
        self.assertNotContains(r, 'Add to queue')


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

    def test_launch_hashfile_materializes_db_project_hashes(self):
        Hash.objects.create(hashstring='deadbeef', project=self.project, cracked=False)
        with tempfile.TemporaryDirectory() as d:
            path = self.project.launch_hashfile(d)  # DB-backed: writes workdir/hashes.txt
            self.assertEqual(path, os.path.join(d, 'hashes.txt'))
            self.assertEqual(sorted(open(path).read().split()),
                             ['5f4dcc3b', 'deadbeef'])

    def test_launch_hashfile_returns_external_path_for_file_backed(self):
        with tempfile.TemporaryDirectory() as d:
            ext = os.path.join(d, 'big.txt')
            open(ext, 'w').write('aaaa\nbbbb\n')
            self.project.hashfile_path = ext
            self.project.save(update_fields=['hashfile_path'])
            # Zero-copy: returns the external path itself, writes nothing new.
            self.assertEqual(self.project.launch_hashfile(d), ext)

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
        # A *genuinely live* attack (this process is tracking its proc) blocks.
        busy = self._mask_run(status='running')

        class _FakeProc:
            pid = 4242
        with launcher._lock:
            launcher._active[busy.pk] = _FakeProc()
        try:
            run = self._mask_run(pattern='?d?d?d')
            with tempfile.TemporaryDirectory() as d:
                runner = hc.HashcatRunner(binary=_write_stub(d, 'exit 1\n'))
                self.assertIn('already running', launcher.start_run(run, runner=runner))
        finally:
            with launcher._lock:
                launcher._active.pop(busy.pk, None)

    def test_start_refused_when_exhausted(self):
        run = self._mask_run(status='exhausted')
        with tempfile.TemporaryDirectory() as d:
            runner = hc.HashcatRunner(binary=_write_stub(d, 'exit 0\n'))  # available
            self.assertIn('already exhausted', launcher.start_run(run, runner=runner))
        run.refresh_from_db()
        self.assertEqual(run.status, 'exhausted')  # not relaunched

    def test_enqueue_refused_when_exhausted(self):
        run = self._mask_run(status='exhausted')
        self.assertIn('already exhausted', launcher.enqueue(run))
        run.refresh_from_db()
        self.assertEqual(run.status, 'exhausted')  # not queued

    def test_stop_recovers_orphaned_run(self):
        # A run left 'running' after a server restart: no thread, no live pid.
        run = self._mask_run(status='running')
        run.pid = 999999  # not a hashcat process (recovery must not signal it)
        run.save(update_fields=['pid'])
        self.assertIsNone(launcher.stop_run(run))
        run.refresh_from_db()
        self.assertEqual(run.status, 'aborted')
        self.assertIsNone(run.pid)
        self.assertIsNotNone(run.ended_at)
        # No longer blocks new launches.
        self.assertFalse(Run.objects.filter(status='running').exists())

    def test_stop_live_run_signals_and_leaves_status_to_thread(self):
        import signal
        run = self._mask_run(status='running')

        class _FakeProc:
            def __init__(self): self.signals = []
            def send_signal(self, sig): self.signals.append(sig)

        proc = _FakeProc()
        with launcher._lock:
            launcher._active[run.pk] = proc
        try:
            self.assertIsNone(launcher.stop_run(run))
        finally:
            with launcher._lock:
                launcher._active.pop(run.pk, None)
        self.assertEqual(proc.signals, [signal.SIGINT])
        run.refresh_from_db()
        self.assertEqual(run.status, 'running')  # the worker thread finalises it

    def test_pid_is_hashcat_false_for_bogus_pid(self):
        self.assertFalse(launcher._pid_is_hashcat(999999))

    def test_reconcile_aborts_orphan_without_pid(self):
        # The reported deadlock: a 'running' row that was never really launched
        # (no pid, no tracking thread) must be swept, not left to block forever.
        run = self._mask_run(status='running')  # pid=None, not in _active
        self.assertEqual(launcher.reconcile_stale_runs(), 1)
        run.refresh_from_db()
        self.assertEqual(run.status, 'aborted')
        self.assertIsNone(run.pid)
        self.assertIsNotNone(run.ended_at)

    def test_reconcile_aborts_orphan_with_dead_pid(self):
        run = self._mask_run(status='running')
        run.pid = 999999  # a pid that is not a live hashcat process
        run.save(update_fields=['pid'])
        self.assertEqual(launcher.reconcile_stale_runs(), 1)
        run.refresh_from_db()
        self.assertEqual(run.status, 'aborted')

    def test_reconcile_keeps_live_run(self):
        run = self._mask_run(status='running')

        class _FakeProc:
            pid = 4242
        with launcher._lock:
            launcher._active[run.pk] = _FakeProc()
        try:
            self.assertEqual(launcher.reconcile_stale_runs(), 0)
        finally:
            with launcher._lock:
                launcher._active.pop(run.pk, None)
        run.refresh_from_db()
        self.assertEqual(run.status, 'running')  # untouched -- it's really running

    def test_orphan_no_longer_blocks_the_one_at_a_time_guard(self):
        self._mask_run(status='running')  # stale orphan
        self.assertTrue(Run.objects.filter(status='running').exists())
        launcher.reconcile_stale_runs()
        # Guard set is now clear, so a new launch is no longer refused.
        self.assertFalse(Run.objects.filter(status='running').exists())


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

    def test_execute_file_backed_skips_crack_ingest(self):
        # File-backed: the persistent potfile is the source of truth, so _execute
        # must NOT create Crack rows / flip the cracked flag, and must not delete
        # the potfile (it lives outside the workdir that gets rmtree'd).
        from zebra.models import Crack
        work = tempfile.mkdtemp()
        keep = tempfile.mkdtemp()  # stands in for the external/persistent locations
        ext = os.path.join(keep, 'hashes.txt'); open(ext, 'w').write('aaa\n')
        pot = os.path.join(keep, 'project.pot'); open(pot, 'w').write('aaa:secret\n')
        self.project.hashfile_path = ext
        self.project.save(update_fields=['hashfile_path'])
        stub = _write_stub(work, "exit 1\n")
        proc = subprocess.Popen([stub], stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT)
        launcher._execute(self.run, proc, proc.stdout.fileno(), work, pot)
        self.run.refresh_from_db()
        self.assertEqual(self.run.status, 'exhausted')
        self.assertFalse(Crack.objects.filter(run=self.run).exists())
        self.h.refresh_from_db()
        self.assertFalse(self.h.cracked)          # DB hash untouched
        self.assertTrue(os.path.exists(pot))      # persistent potfile survives

    def test_execute_file_backed_pins_recovered_to_final_potfile(self):
        # Per-run attribution: at finalise, recovered is pinned to the final potfile
        # count so this run's tally (recovered - crack_baseline) is exact.
        work = tempfile.mkdtemp(); keep = tempfile.mkdtemp()
        ext = os.path.join(keep, 'h.txt'); open(ext, 'w').write('a\n')
        pot = os.path.join(keep, 'p.pot'); open(pot, 'w').write('a:x\nb:y\n')  # 2 cracks
        self.project.hashfile_path = ext
        self.project.save(update_fields=['hashfile_path'])
        self.run.crack_baseline = 1  # 1 crack pre-existed this run
        self.run.recovered = None
        self.run.save(update_fields=['crack_baseline', 'recovered'])
        stub = _write_stub(work, "exit 1\n")
        proc = subprocess.Popen([stub], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        launcher._execute(self.run, proc, proc.stdout.fileno(), work, pot)
        self.run.refresh_from_db()
        self.assertEqual(self.run.recovered, 2)        # pinned to final potfile count
        self.assertEqual(self.run.crack_range_end, 2)  # end of this run's row range
        self.assertEqual(self.run.crack_count(), 1)    # rows [1, 2) = this run


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


class CoverageDecompositionTests(SimpleTestCase):
    def _sizes(self, dec):
        return sum(c['size'] for c in dec['cells'])

    def test_cells_sum_to_union_keyspace(self):
        for pats in (['?u?l?l?d?d?d', '?a?a?a?a?a?a'],
                     ['?a?d?d?d', '?u?l?l?s'],
                     ['?l?l?l?l', 'abcd', 'ab?d?d']):
            masks = [P(p) for p in pats]
            dec = cov.coverage_decomposition(masks)
            self.assertFalse(dec['truncated'])
            self.assertEqual(self._sizes(dec), cov.union_keyspace(masks))
            self.assertEqual(dec['covered'], cov.union_keyspace(masks))

    def test_cells_are_disjoint(self):
        dec = cov.coverage_decomposition([P('?a?d?d?d'), P('?u?l?l?s')])
        tuples = [tuple(c['atoms']) for c in dec['cells']]
        self.assertEqual(len(tuples), len(set(tuples)))

    def test_dependency_is_visible_in_cells(self):
        # Same covered count, but the covered *cells* differ: anti-diagonal vs
        # diagonal. A per-position marginal alone could not tell these apart.
        uni = cov.expand_charset('?l?u')
        anti = cov.coverage_decomposition([P('?u?l'), P('?l?u')], universe=uni)
        diag = cov.coverage_decomposition([P('?u?u'), P('?l?l')], universe=uni)
        self.assertEqual(anti['covered'], diag['covered'])
        anti_cells = {tuple(c['atoms']) for c in anti['cells']}
        diag_cells = {tuple(c['atoms']) for c in diag['cells']}
        self.assertNotEqual(anti_cells, diag_cells)
        self.assertEqual(anti['total'], 2 * 26 * (2 * 26))  # |Sigma|=52, L=2

    def test_marginals_sum_to_covered_at_every_position(self):
        dec = cov.coverage_decomposition([P('?a?d?d?d'), P('?u?l?l?s')])
        for mp in dec['marginals']:
            self.assertEqual(sum(mp.values()), dec['covered'])

    def test_truncation_keeps_marginals_exact(self):
        masks = [P('?a?a?a?a'), P('?l?l?l?l')]
        dec = cov.coverage_decomposition(masks, universe=cov.expand_charset('?a'),
                                         cell_cap=3)
        self.assertTrue(dec['truncated'])
        self.assertIsNone(dec['cells'])
        self.assertEqual(dec['covered'], cov.union_keyspace(masks))
        for mp in dec['marginals']:
            self.assertEqual(sum(mp.values()), dec['covered'])

    def test_single_mask_is_one_cell(self):
        dec = cov.coverage_decomposition([P('?u?l?l?d')])
        self.assertEqual(len(dec['cells']), 1)
        self.assertEqual(dec['cells'][0]['size'], cov.mask_keyspace(P('?u?l?l?d')))

    def test_empty_masks_return_none(self):
        self.assertIsNone(cov.coverage_decomposition([]))


from .services import recommend as rec


class RecommendEngineTests(SimpleTestCase):
    """Pure recommender: fit a keyspace budget, prefer zero overlap."""

    SIZES = {'l': 26, 'u': 26, 'd': 10, 's': 33}

    def test_canonical_pattern_orders_classes(self):
        # u, l, d, s regardless of input order; keyspace is order-independent.
        self.assertEqual(rec.canonical_pattern(['d', 'l', 'u']), '?u?l?d')
        self.assertEqual(rec.canonical_pattern(['s', 'd', 'l', 'u']), '?u?l?d?s')

    def test_picks_mask_near_target(self):
        target = 26 ** 4 * 10 ** 2  # exactly ?u?l?l?l?d?d-sized (6 positions)
        out = rec.recommend(target, [], self.SIZES, top_n=8)
        # the length-6 single is the exact-fit multiset (4 letters + 2 digits)
        six = [r for r in out if not r['incremental'] and r['length'] == 6]
        self.assertTrue(six)
        self.assertEqual(six[0]['keyspace'], target)
        self.assertAlmostEqual(six[0]['log_dist'], 0.0, places=9)

    def test_prefers_zero_overlap_over_covered(self):
        # Cover ?u?l?l?l?d?d exactly; a same-size suggestion must avoid it.
        covered = [P('?u?l?l?l?d?d')]
        target = cov.mask_keyspace(P('?u?l?l?l?d?d'))
        out = rec.recommend(target, covered, self.SIZES, top_n=5)
        self.assertTrue(out)
        self.assertEqual(out[0]['overlap'], 0)  # top suggestion is fully new
        self.assertNotEqual(out[0]['pattern'], '?u?l?l?l?d?d')

    def test_excludes_fully_covered_masks(self):
        # Cover ?u?l?l?l?d?d and aim right at its keyspace: the identical (100%
        # overlapping) mask must be filtered out, not suggested.
        covered = [P('?u?l?l?l?d?d')]
        target = cov.mask_keyspace(P('?u?l?l?l?d?d'))
        out = rec.recommend(target, covered, self.SIZES, top_n=20)
        self.assertTrue(out)  # still returns useful alternatives
        self.assertFalse(any(r['pattern'] == '?u?l?l?l?d?d' for r in out))
        self.assertTrue(all(r['overlap'] < r['keyspace'] for r in out))  # none 100%

    def test_spans_distinct_lengths(self):
        # reachable across several lengths (band M..N); the single-mask suggestions
        # should cover distinct lengths, not cluster on the single closest one.
        target = 26 ** 6 * 10 ** 4
        out = rec.recommend(target, [], self.SIZES, top_n=6)
        singles = [r for r in out if not r['incremental']]
        lengths = [r['length'] for r in singles]
        self.assertGreaterEqual(len(set(lengths)), 4)
        self.assertEqual(len(set(lengths)), len(singles))  # each single a distinct length
        self.assertEqual(lengths, sorted(lengths))         # presented short-to-long
        for r in singles:
            self.assertLess(r['log_dist'], 1.0)            # each fits the budget
        # at most one incremental "sweep" suggestion, flagged and covering 1..N
        incr = [r for r in out if r['incremental']]
        self.assertLessEqual(len(incr), 1)
        if incr:
            self.assertEqual(incr[0]['increment_min'], 1)
            self.assertTrue(incr[0]['covers'].startswith('1-'))

    def test_empty_when_no_budget_or_tokens(self):
        self.assertEqual(rec.recommend(0, [], self.SIZES), [])
        self.assertEqual(rec.recommend(1000, [], {}), [])


class RecommendViewTests(TestCase):
    """The recommend.json endpoint and its benchmark/hashtype guards."""

    def setUp(self):
        self.ht = HashType.objects.create(name='reco-ht', hashcat_module=987654)
        self.project = Project.objects.create(
            name='reco-view', hashtype=self.ht, universe='?l?u?d',
            benchmark_hs=10_000_000_000)
        Hash.objects.create(hashstring='a' * 32, project=self.project)

    def _get(self, seconds):
        return self.client.get(
            '/zebra/project/%d/recommend.json?seconds=%s' % (self.project.pk, seconds))

    def test_recommendations_fit_budget_and_are_new(self):
        d = self._get(300).json()
        self.assertTrue(d['ok'])
        self.assertEqual(d['seconds'], 300)
        self.assertTrue(d['recommendations'])
        top = d['recommendations'][0]
        self.assertTrue(top['zero_overlap'])
        # est. runtime within an order of magnitude of the 5-minute budget
        self.assertLess(top['est_seconds'], 3000)
        self.assertGreater(top['est_seconds'], 30)
        # keyspace is a string (JS precision) and parses as a big int
        self.assertIsInstance(top['keyspace'], str)
        int(top['keyspace'])

    def test_missing_benchmark_flagged(self):
        self.project.benchmark_hs = None
        self.project.save()
        self.assertEqual(self._get(300).json()['error'], 'no-benchmark')

    def test_bad_duration_rejected(self):
        self.assertFalse(self._get(0).json()['ok'])
        self.assertFalse(self._get('abc').json()['ok'])

    def test_record_link_prefills_mask_form(self):
        top = self._get(3600).json()['recommendations'][0]
        r = self.client.get(top['record_url'])
        self.assertEqual(r.status_code, 200)
        self.assertContains(r, 'value="%s"' % top['pattern'])


from .services import hashcat as hcsvc


class ParseBenchmarkTests(SimpleTestCase):
    """Speed parsing from --machine-readable benchmark output (hashcat v6)."""

    def test_single_device_takes_last_field_not_sentinel(self):
        # Real MD5 line: last field is the ~375 MH/s speed; the 4294967295
        # (0xFFFFFFFF) fields are placeholders and must be ignored.
        line = '1:0:4294967295:4294967295:62.19:375777106'
        self.assertEqual(hcsvc.parse_benchmark(line), 375777106)

    def test_slow_hash_below_sentinel_is_not_clamped(self):
        # ~95 MH/s < 0xFFFFFFFF: the old max() heuristic returned the sentinel.
        line = '1:1400:4294967295:4294967295:79.74:95000000'
        self.assertEqual(hcsvc.parse_benchmark(line), 95000000)

    def test_multiple_devices_sum(self):
        text = ('1:0:4294967295:4294967295:62.19:200000000\n'
                '2:0:4294967295:4294967295:60.01:150000000\n')
        self.assertEqual(hcsvc.parse_benchmark(text), 350000000)

    def test_ignores_non_device_lines(self):
        text = 'hashcat (v6.2.6) starting in benchmark mode\n\n1:0:0:0:1.0:12345\n'
        self.assertEqual(hcsvc.parse_benchmark(text), 12345)

    def test_empty_output(self):
        self.assertEqual(hcsvc.parse_benchmark(''), 0)


class RecommendTokenSizesTests(SimpleTestCase):
    """Which character classes the recommender offers for a given universe."""

    def test_all_class_offered_when_no_universe(self):
        sizes = ch.project_token_sizes(None)
        self.assertEqual(sizes.get("a"), 95)
        self.assertEqual(set(sizes), {'l', 'u', 'd', 's', 'a'})

    def test_all_class_dropped_when_universe_excludes_symbols(self):
        # ?l?u?d universe: ?a (which needs symbols) is out of scope.
        alnum = cov.expand_charset('?l?u?d')
        sizes = ch.project_token_sizes(alnum)
        self.assertNotIn('a', sizes)
        self.assertNotIn('s', sizes)
        self.assertEqual(set(sizes), {'l', 'u', 'd'})

    def test_all_class_offered_for_full_ascii_universe(self):
        sizes = ch.project_token_sizes(cov.expand_charset('?a'))
        self.assertEqual(sizes.get("a"), 95)

    def test_recommender_can_propose_an_all_mask(self):
        sizes = ch.project_token_sizes(None)
        target = 94 ** 5  # exactly ?a?a?a?a?a
        out = rec.recommend(target, [], sizes, top_n=5)
        self.assertTrue(any('?a' in r['pattern'] for r in out))


class RunStatusJsonTests(TestCase):
    """The live-status endpoint the running detail page polls (AJAX)."""

    def setUp(self):
        self.ht = HashType.objects.create(name='S-MD5', hashcat_module=0)
        self.project = Project.objects.create(name='STATUS', hashtype=self.ht)
        self.mask = Mask.objects.create(project=self.project, pattern='?d?d?d')

    def _run(self, **kw):
        return Run.objects.create(project=self.project, mask=self.mask,
                                  attack_mode=3, **kw)

    def test_running_payload(self):
        from decimal import Decimal
        run = self._run(status='running', progress=0.25, speed_hs=Decimal('395000000'))
        d = self.client.get('/zebra/run/%d/status.json' % run.pk).json()
        self.assertTrue(d['running'])
        self.assertEqual(d['percent'], 25.0)
        self.assertEqual(d['speed_hs'], '395000000')
        self.assertIn('H/s', d['speed_h'])

    def test_finished_run_reports_not_running(self):
        run = self._run(status='exhausted', progress=1.0)
        d = self.client.get('/zebra/run/%d/status.json' % run.pk).json()
        self.assertFalse(d['running'])
        self.assertEqual(d['status'], 'exhausted')

    def test_running_page_polls_instead_of_reloading(self):
        run = self._run(status='running', progress=0.1)
        body = self.client.get('/zebra/run/%d/' % run.pk).content.decode()
        self.assertIn('status.json', body)
        self.assertIn('id="run-bar"', body)
        self.assertNotIn('location.reload(); }, 3000', body)  # no blind full reload


class EvaluateDurationTests(TestCase):
    """The Evaluate button estimates a mask attack's runtime when a benchmark is set."""

    def setUp(self):
        self.ht = HashType.objects.create(name='D-MD5', hashcat_module=0)
        self.project = Project.objects.create(name='DURTEST', hashtype=self.ht)
        Hash.objects.create(hashstring='dh1', project=self.project, cracked=False)

    def _evaluate(self, pattern):
        return self.client.post('/zebra/project/%d/mask/new/' % self.project.pk,
                                {'pattern': pattern, 'custom_charsets': '',
                                 'status': 'planned', 'action': 'preview'})

    def test_duration_shown_when_benchmark_set(self):
        from decimal import Decimal
        self.project.benchmark_hs = Decimal('1000000000')  # 1 GH/s
        self.project.save()
        # 10**13 candidates / 1e9 = 10000 s ≈ 2.8 hours
        r = self._evaluate('?d?d?d?d?d?d?d?d?d?d?d?d?d')
        self.assertContains(r, 'Expected runtime')
        self.assertContains(r, '2.8 hours')

    def test_hint_shown_when_no_benchmark(self):
        r = self._evaluate('?d?d?d')
        self.assertNotContains(r, 'Expected runtime')
        self.assertContains(r, 'to estimate this attack')


class NumberFormattingTests(TestCase):
    """Big numbers get thousands separators; overlap shows a percentage."""

    def setUp(self):
        self.ht = HashType.objects.create(name='N-MD5', hashcat_module=0)
        self.project = Project.objects.create(name='NUMTEST', hashtype=self.ht,
                                              universe='0123456789')
        Hash.objects.create(hashstring='nh1', project=self.project, cracked=False)
        # Cover ?d?d?d?d?d?d (1,000,000) as exhausted.
        m = Mask.objects.create(project=self.project, pattern='?d?d?d?d?d?d')
        ch.compute_and_cache_keyspace(m); m.save()
        run = Run.objects.create(mask=m, project=self.project, attack_mode=3,
                                 status='exhausted')
        run.hashes.set(self.project.hash_set.all())

    def test_evaluate_candidate_reports_overlap_pct(self):
        # Re-evaluating the exhausted mask: fully overlapping (100%).
        ev = ch.evaluate_candidate(self.project, '?d?d?d?d?d?d')
        self.assertEqual(ev['overlap'], 1_000_000)
        self.assertAlmostEqual(ev['overlap_pct'], 100.0)

    def test_evaluate_page_shows_x_of_y_percent(self):
        r = self.client.post('/zebra/project/%d/mask/new/' % self.project.pk,
                             {'pattern': '?d?d?d?d?d?d', 'custom_charsets': '',
                              'status': 'planned', 'action': 'preview'})
        self.assertContains(r, '1,000,000 of 1,000,000')
        self.assertContains(r, '100.00%')

    def test_coverage_numbers_have_thousands_separators(self):
        d = self.client.get('/zebra/project/%d/' % self.project.pk)
        self.assertContains(d, '1,000,000')  # covered / total grouped


class CComplementCommandTests(SimpleTestCase):
    """?c has no native hashcat token; runs bind it to the complement charset file."""

    def test_c_bound_to_free_custom_slot(self):
        r = hcsvc.HashcatRunner()
        argv = r.build_run_args(3, 0, hashfile='H', params={'mask': '?u?c?d'})
        self.assertIn('-1', argv)
        self.assertTrue(any(a.endswith('b_complement.hcchr') for a in argv))
        self.assertIn('?u?1?d', argv)          # ?c -> the bound slot
        self.assertNotIn('?c', ' '.join(argv))  # no raw ?c reaches hashcat

    def test_c_avoids_a_taken_slot(self):
        r = hcsvc.HashcatRunner()
        argv = r.build_run_args(3, 0, hashfile='H',
                                params={'mask': '?1?c', 'custom_charsets': {'1': '?l?d'}})
        self.assertIn('?1?2', argv)             # slot 1 taken -> ?c goes to slot 2

    def test_literal_c_is_not_translated(self):
        r = hcsvc.HashcatRunner()
        argv = r.build_run_args(3, 0, hashfile='H', params={'mask': 'abc?d'})
        self.assertNotIn('-1', argv)            # literal 'c' must not add a charset
        self.assertIn('abc?d', argv)

    def test_b_is_native_and_unchanged(self):
        r = hcsvc.HashcatRunner()
        argv = r.build_run_args(3, 0, hashfile='H', params={'mask': '?b?b'})
        self.assertIn('?b?b', argv)
        self.assertNotIn('-1', argv)

    def test_substitute_c_is_noop_without_c(self):
        self.assertEqual(hcsvc.substitute_c('?u?l?d', {}, '/x'), ('?u?l?d', {}))


class IncrementEngineTests(SimpleTestCase):
    """Pure engine: --increment covers the union of a mask's length-prefixes."""

    def test_mask_prefixes(self):
        pos = P('?u?l?d')
        pref = cov.mask_prefixes(pos, 1, 3)
        self.assertEqual([len(p) for p in pref], [1, 2, 3])
        # bounds clamp to [1, len]
        self.assertEqual(len(cov.mask_prefixes(pos, 2, 99)), 2)  # lengths 2,3

    def test_incremental_keyspace_is_sum_of_prefixes(self):
        # ?d?d?d incremental 1..3 = 10 + 100 + 1000
        self.assertEqual(cov.incremental_keyspace(P('?d?d?d'), 1, 3), 1110)
        # 2..3 = 100 + 1000
        self.assertEqual(cov.incremental_keyspace(P('?d?d?d'), 2, 3), 1100)


class IncrementCoverageTests(TestCase):
    """One exhausted incremental run covers every swept length."""

    def setUp(self):
        self.ht = HashType.objects.create(name='I-MD5', hashcat_module=0)
        self.project = Project.objects.create(name='INC', hashtype=self.ht,
                                              universe='0123456789')
        Hash.objects.create(hashstring='ih1', project=self.project, cracked=False)

    def _record_incremental(self, pattern, inc_min, inc_max, status='exhausted'):
        mask = Mask.objects.create(project=self.project, pattern=pattern,
                                   increment_min=inc_min, increment_max=inc_max)
        ch.compute_and_cache_keyspace(mask); mask.save()
        run = Run.objects.create(mask=mask, project=self.project, attack_mode=3,
                                 status=status)
        run.hashes.set(self.project.hash_set.all())
        return mask, run

    def test_cached_keyspace_is_incremental_sum(self):
        mask, _ = self._record_incremental('?d?d?d', 1, 3)
        self.assertEqual(int(mask.keyspace), 1110)  # 10+100+1000
        self.assertTrue(mask.is_incremental)

    def test_coverage_rows_for_every_swept_length(self):
        self._record_incremental('?d?d?d', 1, 3)
        rows = {r['length']: r for r in ch.project_coverage(self.project)}
        self.assertEqual(set(rows), {1, 2, 3})
        self.assertEqual(rows[1]['covered'], 10)
        self.assertEqual(rows[2]['covered'], 100)
        self.assertEqual(rows[3]['covered'], 1000)

    def test_evaluate_incremental_candidate(self):
        ev = ch.evaluate_candidate(self.project, '?d?d?d',
                                   increment_min=1, increment_max=3)
        self.assertTrue(ev['incremental'])
        self.assertEqual(ev['keyspace'], 1110)
        self.assertEqual(ev['increment_max'], 3)

    def test_recommender_discounts_incremental_coverage(self):
        # Sweep ?d 1..4 exhausted -> lengths 1..4 of digits fully covered. A digit
        # mask at those lengths must be reported redundant, not suggested.
        self._record_incremental('?d?d?d?d', 1, 4)
        ev = ch.evaluate_candidate(self.project, '?d?d')  # length 2, all digits
        self.assertTrue(ev['subsumed'])                    # already swept
        self.assertEqual(ev['marginal'], 0)


class IncrementCommandTests(SimpleTestCase):
    """--increment flags are emitted for incremental mask runs only."""

    def test_increment_flags_present(self):
        argv = hcsvc.HashcatRunner().build_run_args(
            3, 0, hashfile='H',
            params={'mask': '?a?a?a', 'increment_min': 1, 'increment_max': 3})
        self.assertIn('-i', argv)
        self.assertIn('--increment-min', argv)
        self.assertIn('--increment-max', argv)
        self.assertEqual(argv[argv.index('--increment-max') + 1], '3')

    def test_no_increment_flags_for_plain_mask(self):
        argv = hcsvc.HashcatRunner().build_run_args(
            3, 0, hashfile='H', params={'mask': '?a?a?a'})
        self.assertNotIn('-i', argv)
        self.assertNotIn('--increment-min', argv)


class IncrementViewTests(TestCase):
    """Recording, prefill, and the recommender JSON for incremental masks."""

    def setUp(self):
        self.ht = HashType.objects.create(name='IV-MD5', hashcat_module=0)
        self.project = Project.objects.create(name='IVIEW', hashtype=self.ht,
                                              universe='?l?u?d', benchmark_hs=10_000_000_000)
        Hash.objects.create(hashstring='ivh1', project=self.project, cracked=False)

    def test_record_incremental_mask_sets_fields_and_command(self):
        url = '/zebra/project/%d/mask/new/' % self.project.pk
        r = self.client.post(url, {'pattern': '?l?l?l', 'custom_charsets': '',
                                   'increment': '1', 'increment_max': '3',
                                   'status': 'planned', 'action': 'record'})
        self.assertEqual(r.status_code, 302)
        mask = Mask.objects.get(project=self.project)
        self.assertEqual((mask.increment_min, mask.increment_max), (1, 3))
        run = Run.objects.get(mask=mask)
        self.assertIn('--increment-min', run.command)
        self.assertIn('--increment-max 3', run.command)

    def test_mask_new_prefills_increment_from_query(self):
        r = self.client.get('/zebra/project/%d/mask/new/?pattern=%%3Fl%%3Fl&increment=1&increment_max=5'
                            % self.project.pk)
        self.assertContains(r, 'name="increment"')
        self.assertContains(r, 'checked')
        self.assertContains(r, 'value="5"')

    def test_recommend_json_includes_incremental_entry(self):
        d = self.client.get('/zebra/project/%d/recommend.json?seconds=300' % self.project.pk).json()
        self.assertTrue(d['ok'])
        incr = [r for r in d['recommendations'] if r['incremental']]
        self.assertTrue(incr)                              # a sweep suggestion is offered
        self.assertIn('increment=1', incr[0]['record_url'])
        self.assertIn('increment_max=', incr[0]['record_url'])


class CoverageDisplayClampTests(TestCase):
    """?b/?c can exceed the universe; the dashboard clamps remaining >=0, %<=100."""

    def setUp(self):
        self.ht = HashType.objects.create(name='CLAMP-MD5', hashcat_module=0)
        # Universe is digits only, but we search ?b (256 bytes) -> covered > total.
        self.project = Project.objects.create(name='CLAMP', hashtype=self.ht,
                                              universe='0123456789')
        Hash.objects.create(hashstring='ch1', project=self.project, cracked=False)

    def test_remaining_and_percent_are_clamped(self):
        mask = Mask.objects.create(project=self.project, pattern='?b?b')  # 256*256
        ch.compute_and_cache_keyspace(mask); mask.save()
        run = Run.objects.create(mask=mask, project=self.project, attack_mode=3,
                                 status='exhausted')
        run.hashes.set(self.project.hash_set.all())
        row = next(r for r in ch.project_coverage(self.project) if r['length'] == 2)
        self.assertGreater(row['covered'], row['total'])  # genuinely over-covered
        self.assertEqual(row['remaining'], 0)             # not negative
        self.assertEqual(row['percent'], 100.0)           # not >100


class IncrementProgressTests(TestCase):
    """The (X/Y runs) counter for an incremental sweep."""

    def setUp(self):
        self.ht = HashType.objects.create(name='IP-MD5', hashcat_module=0)
        self.project = Project.objects.create(name='IPROG', hashtype=self.ht)
        Hash.objects.create(hashstring='ip1', project=self.project, cracked=False)

    def test_parse_status_json_extracts_increment_position(self):
        line = ('{"status":3,"guess":{"guess_base":"?a?a?a?a?a?a",'
                '"guess_base_offset":1,"guess_base_count":3},'
                '"progress":[133693440,735091890625]}')
        s = hcsvc.parse_status_json(line)
        self.assertEqual(s['base_offset'], 1)
        self.assertEqual(s['base_count'], 3)

    def test_ingest_status_stores_position_on_run(self):
        mask = Mask.objects.create(project=self.project, pattern='?d?d?d',
                                   increment_min=1, increment_max=3)
        run = Run.objects.create(mask=mask, project=self.project, attack_mode=3,
                                 status='running')
        hcsvc.ingest_status(run, {'base_offset': 2, 'base_count': 3, 'progress': 0.5})
        run.refresh_from_db()
        self.assertEqual(run.increment_offset, 2)
        self.assertEqual(run.increment_count, 3)

    def test_ingest_status_stores_recovered(self):
        mask = Mask.objects.create(project=self.project, pattern='?d?d?d')
        run = Run.objects.create(mask=mask, project=self.project, attack_mode=3,
                                 status='running')
        # hashcat status-json: recovered_hashes: [3, 100]
        summary = hcsvc.parse_status_json(
            '{"status":3,"progress":[5,100],"recovered_hashes":[3,100]}')
        self.assertEqual(summary['recovered'], 3)
        hcsvc.ingest_status(run, summary)
        run.refresh_from_db()
        self.assertEqual(run.recovered, 3)

    def test_status_json_view_reports_1based_counter(self):
        mask = Mask.objects.create(project=self.project, pattern='?d?d?d',
                                   increment_min=1, increment_max=3)
        run = Run.objects.create(mask=mask, project=self.project, attack_mode=3,
                                 status='running', increment_offset=2, increment_count=3)
        d = self.client.get('/zebra/run/%d/status.json' % run.pk).json()
        # increment_offset is hashcat's 1-based guess_base_offset -> shown as-is.
        self.assertEqual(d['run_index'], 2)   # offset 2 -> "2/3"
        self.assertEqual(d['run_total'], 3)

    def test_final_subrun_does_not_overflow_counter(self):
        # Regression: a 6-length sweep's last sub-run is guess_base_offset 6 of 6.
        # It must read "6/6", not "7/6" (an earlier off-by-one added 1 to hashcat's
        # already-1-based offset).
        mask = Mask.objects.create(project=self.project, pattern='?a?a?a?a?a?a',
                                   increment_min=1, increment_max=6)
        run = Run.objects.create(mask=mask, project=self.project, attack_mode=3,
                                 status='running')
        hcsvc.ingest_status(run, {'base_offset': 6, 'base_count': 6, 'progress': 0.26})
        run.refresh_from_db()
        d = self.client.get('/zebra/run/%d/status.json' % run.pk).json()
        self.assertEqual((d['run_index'], d['run_total']), (6, 6))

    def test_non_incremental_run_has_no_counter(self):
        mask = Mask.objects.create(project=self.project, pattern='?d?d?d')
        run = Run.objects.create(mask=mask, project=self.project, attack_mode=3,
                                 status='running')
        d = self.client.get('/zebra/run/%d/status.json' % run.pk).json()
        self.assertIsNone(d['run_index'])
        self.assertIsNone(d['run_total'])


from .templatetags.zebra_extras import bignum


class BignumFilterTests(SimpleTestCase):
    def test_commas_up_to_12_digits(self):
        self.assertEqual(bignum(1000), '1,000')
        self.assertEqual(bignum(999_999_999_999), '999,999,999,999')  # 12 digits

    def test_scientific_past_12_digits(self):
        self.assertEqual(bignum(1_000_000_000_000), '1.00 × 10¹²')    # 13 digits
        self.assertEqual(bignum(68_987_765_456_789), '6.90 × 10¹³')
        self.assertEqual(bignum(95 ** 12), '5.40 × 10²³')

    def test_passthrough_non_numeric(self):
        self.assertIsNone(bignum(None))
        self.assertEqual(bignum('—'), '—')


class RemainingEtaTests(TestCase):
    """The Remaining column shows an approximate time-to-exhaust when benchmarked."""

    def setUp(self):
        self.ht = HashType.objects.create(name='ETA-MD5', hashcat_module=0)
        # alnum universe (62), so a digits-only exhausted mask leaves lots remaining
        self.project = Project.objects.create(name='ETA', hashtype=self.ht,
                                              universe='?l?u?d',
                                              benchmark_hs=10_000_000_000)  # 10 GH/s
        Hash.objects.create(hashstring='eh1', project=self.project, cracked=False)

    def _cover(self, pattern, custom_charsets=None):
        mask = Mask.objects.create(project=self.project, pattern=pattern,
                                   custom_charsets=custom_charsets or {})
        ch.compute_and_cache_keyspace(mask); mask.save()
        run = Run.objects.create(mask=mask, project=self.project, attack_mode=3,
                                 status='exhausted')
        run.hashes.set(self.project.hash_set.all())

    def test_eta_present_when_remaining_positive(self):
        self._cover('?d?d?d?d?d?d?d?d')          # 10^8 covered; total 62^8, big remainder
        resp = self.client.get('/zebra/project/%d/' % self.project.pk)
        row = next(r for r in resp.context['coverage'] if r['length'] == 8)
        self.assertGreater(row['remaining'], 0)
        self.assertIsNotNone(row['remaining_eta'])
        # remaining ~2.18e14 / 1e10 ~ 6 hours
        self.assertIn('hour', row['remaining_eta'])
        self.assertContains(resp, '(~' + row['remaining_eta'] + ')')
        self.assertContains(resp, '× 10')           # remaining shown as n × 10ᵏ

    def test_no_eta_when_fully_covered(self):
        # ?1?1?1 with 1=?l?u?d == 62^3, the whole length-3 universe -> remaining 0
        self._cover('?1?1?1', custom_charsets={'1': '?l?u?d'})
        resp = self.client.get('/zebra/project/%d/' % self.project.pk)
        row = next(r for r in resp.context['coverage'] if r['length'] == 3)
        self.assertEqual(row['remaining'], 0)
        self.assertIsNone(row['remaining_eta'])

    def test_no_eta_without_benchmark(self):
        self.project.benchmark_hs = None
        self.project.save()
        self._cover('?d?d?d?d?d?d?d?d')
        resp = self.client.get('/zebra/project/%d/' % self.project.pk)
        row = next(r for r in resp.context['coverage'] if r['length'] == 8)
        self.assertIsNone(row['remaining_eta'])


class CoverageTotalTests(TestCase):
    """Grand-total (cross-length) coverage rollup on the dashboard."""

    def setUp(self):
        self.ht = HashType.objects.create(name='GT-MD5', hashcat_module=0)
        self.project = Project.objects.create(name='GT', hashtype=self.ht,
                                              universe='0123456789',  # digits
                                              benchmark_hs=1_000_000)  # 1 MH/s
        Hash.objects.create(hashstring='gh1', project=self.project, cracked=False)

    def _cover(self, pattern):
        mask = Mask.objects.create(project=self.project, pattern=pattern)
        ch.compute_and_cache_keyspace(mask); mask.save()
        run = Run.objects.create(mask=mask, project=self.project, attack_mode=3,
                                 status='exhausted')
        run.hashes.set(self.project.hash_set.all())

    def test_rollup_sums_across_lengths(self):
        self._cover('?d?d')     # len 2: covered 100, total 100
        self._cover('?d?d?d')   # len 3: covered 1000, total 1000
        resp = self.client.get('/zebra/project/%d/' % self.project.pk)
        tot = resp.context['coverage_total']
        self.assertEqual(tot['covered'], 1100)          # 100 + 1000
        self.assertEqual(tot['space'], 1100)            # digits universe, fully covered
        self.assertEqual(tot['percent'], 100.0)
        self.assertEqual(tot['remaining'], 0)
        self.assertEqual((tot['min_length'], tot['max_length']), (2, 3))
        self.assertContains(resp, 'Candidates covered')

    def test_rollup_none_without_coverage(self):
        resp = self.client.get('/zebra/project/%d/' % self.project.pk)
        self.assertIsNone(resp.context['coverage_total'])
        self.assertNotContains(resp, 'Candidates covered')

    def test_rollup_percent_clamped_when_over_universe(self):
        # ?b?b (65536) exhausted but universe is digits: covered > total per length,
        # so the rollup percent must clamp to 100 and remaining to 0.
        self._cover('?b?b')
        tot = self.client.get('/zebra/project/%d/' % self.project.pk).context['coverage_total']
        self.assertEqual(tot['percent'], 100.0)
        self.assertEqual(tot['remaining'], 0)


class SessionNameTests(TestCase):
    """hashcat --session names identify the project and attack."""

    def test_session_name_has_zebra_project_and_attack(self):
        ht = HashType.objects.create(name='SN-MD5', hashcat_module=0)
        project = Project.objects.create(name='AD Dump 2024!', hashtype=ht)
        mask = Mask.objects.create(project=project, pattern='?d?d')
        run = Run.objects.create(mask=mask, project=project, attack_mode=3, status='planned')
        name = launcher._session_name(run)
        self.assertTrue(name.startswith('zebra-'))
        self.assertIn('p%d' % project.pk, name)         # project number
        self.assertIn('a%d' % run.pk, name)             # attack number
        self.assertIn('ad-dump-2024', name)             # slugified project name
        # filesystem-safe: only lowercase alnum and dashes
        self.assertRegex(name, r'^[a-z0-9-]+$')

    def test_session_name_without_project_name(self):
        ht = HashType.objects.create(name='SN2-MD5', hashcat_module=0)
        project = Project.objects.create(name='X', hashtype=ht)
        run = Run.objects.create(project=project, attack_mode=3, status='planned')
        self.assertRegex(launcher._session_name(run), r'^zebra-p\d+-x-a\d+$')


class QueueTests(TestCase):
    """Attack-queue logic: enqueue/dequeue/reorder and auto-advance selection."""

    def setUp(self):
        self.ht = HashType.objects.create(name='Q-MD5', hashcat_module=0)
        self.project = Project.objects.create(name='QUEUE', hashtype=self.ht)
        Hash.objects.create(hashstring='q1', project=self.project, cracked=False)

    def tearDown(self):
        launcher.set_queue_paused(False)
        with launcher._lock:
            launcher._active.clear()

    def _run(self, pattern='?d?d', status='planned'):
        mask = Mask.objects.create(project=self.project, pattern=pattern)
        r = Run.objects.create(mask=mask, project=self.project, attack_mode=3, status=status)
        r.hashes.set(self.project.hash_set.all())
        return r

    @mock.patch.object(launcher, 'start_run', return_value=None)
    def test_enqueue_assigns_incrementing_positions(self, _start):
        a, b = self._run('?d?d'), self._run('?d?d?d')
        launcher.enqueue(a); launcher.enqueue(b)
        a.refresh_from_db(); b.refresh_from_db()
        self.assertEqual((a.status, b.status), ('queued', 'queued'))
        self.assertEqual([a.queue_position, b.queue_position], [1, 2])

    def test_enqueue_rejects_non_mask(self):
        r = Run.objects.create(project=self.project, attack_mode=0, status='planned')
        self.assertIn('mask', launcher.enqueue(r))

    @mock.patch.object(launcher, 'start_run', return_value=None)
    def test_dequeue_restores_planned(self, _s):
        launcher.set_queue_paused(True)
        a = self._run(); launcher.enqueue(a)
        launcher.dequeue(a); a.refresh_from_db()
        self.assertEqual(a.status, 'planned')
        self.assertIsNone(a.queue_position)

    @mock.patch.object(launcher, 'start_run', return_value=None)
    def test_move_reorders(self, _s):
        launcher.set_queue_paused(True)
        a, b, c = self._run(), self._run('?d?d?d'), self._run('?d?d?d?d')
        for r in (a, b, c):
            launcher.enqueue(r)
        launcher.move(c, -1)  # move last up one
        order = list(Run.objects.filter(status='queued')
                     .order_by('queue_position', 'pk').values_list('pk', flat=True))
        self.assertEqual(order, [a.pk, c.pk, b.pk])

    def test_next_queued_is_lowest_position(self):
        launcher.set_queue_paused(True)
        a, b = self._run(), self._run('?d?d?d')
        with mock.patch.object(launcher, 'start_run', return_value=None):
            launcher.enqueue(a); launcher.enqueue(b)
        self.assertEqual(launcher._next_queued().pk, a.pk)

    def test_advance_starts_next_when_idle(self):
        launcher.set_queue_paused(True)
        with mock.patch.object(launcher, 'start_run', return_value=None):
            a = self._run(); launcher.enqueue(a)   # queued but not started (paused)
        with mock.patch.object(launcher, 'start_run', return_value=None) as m:
            launcher.set_queue_paused(False)
            started = launcher._advance_queue()
        self.assertEqual(started.pk, a.pk)
        m.assert_called_once()

    def test_advance_noop_when_paused(self):
        launcher.set_queue_paused(True)
        with mock.patch.object(launcher, 'start_run', return_value=None) as m:
            launcher.enqueue(self._run())
            self.assertIsNone(launcher._advance_queue())
            m.assert_not_called()

    def test_advance_noop_when_running(self):
        busy = self._run(status='running')     # occupies the GPU
        with launcher._lock:                   # ...and is genuinely live (tracked)
            launcher._active[busy.pk] = type('P', (), {'pid': 4242})()
        with mock.patch.object(launcher, 'start_run', return_value=None) as m:
            a = self._run(); launcher.enqueue(a)   # enqueue -> advance sees running
            m.assert_not_called()
        a.refresh_from_db()
        self.assertEqual(a.status, 'queued')


class QueueChainTests(TransactionTestCase):
    """Finishing a run advances the queue (the _execute finally hook)."""

    def setUp(self):
        self.ht = HashType.objects.create(name='QC-MD5', hashcat_module=0)
        self.project = Project.objects.create(name='QCHAIN', hashtype=self.ht)
        Hash.objects.create(hashstring='qc', project=self.project, cracked=False)
        self.mask = Mask.objects.create(project=self.project, pattern='?d?d')
        self.run = Run.objects.create(mask=self.mask, project=self.project,
                                      attack_mode=3, status='running')
        self.run.hashes.set(self.project.hash_set.all())

    def tearDown(self):
        launcher.set_queue_paused(False)
        with launcher._lock:
            launcher._active.clear()

    def test_execute_finally_advances_queue(self):
        d = tempfile.mkdtemp()
        pot = os.path.join(d, 'zebra.pot')
        stub = _write_stub(d, "exit 1\n")  # exhausted
        proc = subprocess.Popen([stub], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        with mock.patch.object(launcher, '_advance_queue', return_value=None) as adv:
            launcher._execute(self.run, proc, proc.stdout.fileno(), d, pot)
        adv.assert_called_once()


class QueueViewTests(TestCase):
    """Queue page + enqueue/dequeue/pause endpoints."""

    def setUp(self):
        self.ht = HashType.objects.create(name='QV-MD5', hashcat_module=0)
        self.project = Project.objects.create(name='QV', hashtype=self.ht,
                                              benchmark_hs=1_000_000_000)  # 1 GH/s
        Hash.objects.create(hashstring='qv1', project=self.project, cracked=False)

    def tearDown(self):
        launcher.set_queue_paused(False)
        with launcher._lock:
            launcher._active.clear()

    def _queued(self, pattern='?d?d', pos=1):
        mask = Mask.objects.create(project=self.project, pattern=pattern)
        ch.compute_and_cache_keyspace(mask); mask.save()
        r = Run.objects.create(mask=mask, project=self.project, attack_mode=3,
                               status='queued', queue_position=pos)
        r.hashes.set(self.project.hash_set.all())
        return r

    def test_queue_page_lists_and_totals(self):
        self._queued('?d' * 12, pos=1)   # 10^12 / 1e9 = 1000s ~ 16.7 minutes
        resp = self.client.get('/zebra/queue/')
        self.assertEqual(resp.status_code, 200)
        self.assertContains(resp, 'queued')
        self.assertContains(resp, '× 10')       # keyspace scientific
        self.assertContains(resp, 'to clear')   # cumulative ETA header

    def test_enqueue_endpoint(self):
        mask = Mask.objects.create(project=self.project, pattern='?d?d')
        run = Run.objects.create(mask=mask, project=self.project, attack_mode=3,
                                 status='planned')
        run.hashes.set(self.project.hash_set.all())
        with mock.patch.object(launcher, 'start_run', return_value=None):
            self.client.post('/zebra/run/%d/enqueue/' % run.pk)
        run.refresh_from_db()
        self.assertEqual(run.status, 'queued')

    def test_dequeue_endpoint(self):
        run = self._queued()
        self.client.post('/zebra/run/%d/dequeue/' % run.pk)
        run.refresh_from_db()
        self.assertEqual(run.status, 'planned')

    def test_pause_resume_endpoints(self):
        with mock.patch.object(launcher, '_advance_queue', return_value=None):
            self.client.post('/zebra/queue/pause/')
            self.assertTrue(launcher.is_paused())
            self.client.post('/zebra/queue/resume/')
            self.assertFalse(launcher.is_paused())


class SettingsViewTests(TestCase):
    """The global Settings page and the hashcat-binary override it controls."""

    def test_get_renders_page(self):
        r = self.client.get('/zebra/settings/')
        self.assertEqual(r.status_code, 200)
        self.assertContains(r, 'Settings')

    def test_post_saves_override_and_feeds_runner(self):
        from .models import Settings
        from .services import hashcat as hc
        r = self.client.post('/zebra/settings/',
                             {'hashcat_binary': '/opt/hashcat/hashcat.bin'})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(Settings.load().hashcat_binary, '/opt/hashcat/hashcat.bin')
        # The override is what the DB-aware runner factory now uses.
        self.assertEqual(hc.configured_binary(), '/opt/hashcat/hashcat.bin')
        self.assertEqual(hc.configured_runner().binary, '/opt/hashcat/hashcat.bin')

    def test_blank_override_falls_back_to_path_default(self):
        from .models import Settings
        from .services import hashcat as hc
        self.client.post('/zebra/settings/', {'hashcat_binary': 'x'})
        self.client.post('/zebra/settings/', {'hashcat_binary': '   '})  # whitespace -> blank
        self.assertEqual(Settings.load().hashcat_binary, '')
        self.assertEqual(hc.configured_binary(), hc.DEFAULT_BINARY)

    def test_settings_is_a_singleton(self):
        from .models import Settings
        Settings.load()
        Settings.load()
        s = Settings(hashcat_binary='second')
        s.save()
        self.assertEqual(Settings.objects.count(), 1)
        self.assertEqual(s.pk, 1)


class RecordAndRunViewTests(TestCase):
    """The streamlined 'Record & run' action: record a mask then launch it."""

    def setUp(self):
        self.ht = HashType.objects.create(name='RR-MD5', hashcat_module=0)
        self.project = Project.objects.create(name='RRTEST', hashtype=self.ht,
                                              universe='0123456789')
        Hash.objects.create(hashstring='rr1', project=self.project, cracked=False)
        self.url = '/zebra/project/%d/mask/new/' % self.project.pk

    def test_record_run_creates_run_launches_and_lands_on_run_page(self):
        from unittest import mock
        with mock.patch('zebra.views.launcher.start_run', return_value=None) as start:
            r = self.client.post(self.url, {'pattern': '?d?d', 'custom_charsets': '',
                                            'status': 'planned', 'action': 'record_run'})
        run = Run.objects.get(mask__project=self.project)
        start.assert_called_once_with(run)
        # Lands on the live run page, not the project dashboard.
        self.assertRedirects(r, '/zebra/run/%d/' % run.pk,
                             fetch_redirect_response=False)

    def test_record_run_surfaces_launch_error_on_run_page(self):
        from unittest import mock
        with mock.patch('zebra.views.launcher.start_run',
                        return_value='hashcat is not installed on this machine.'):
            r = self.client.post(self.url, {'pattern': '?d?d', 'custom_charsets': '',
                                            'status': 'planned', 'action': 'record_run'})
        run = Run.objects.get(mask__project=self.project)
        self.assertIn('/zebra/run/%d/?error=' % run.pk, r['Location'])
        self.assertIn('not%20installed', r['Location'])

    def test_record_run_is_noop_launch_for_non_mask_mode(self):
        # Non-mask modes can't launch yet: record_run must still record, and must
        # NOT call the mask launcher.
        from unittest import mock
        Wordlist.objects.create(name='rockyou.txt')
        with mock.patch('zebra.views.launcher.start_run') as start:
            r = self.client.post(self.url, {'attack_mode': '0', 'wordlist': 'rockyou.txt',
                                            'status': 'planned', 'action': 'record_run'})
        start.assert_not_called()
        self.assertRedirects(r, '/zebra/project/%d/' % self.project.pk,
                             fetch_redirect_response=False)
        self.assertTrue(Run.objects.filter(project=self.project, attack_mode=0).exists())


class HashfileServiceTests(SimpleTestCase):
    """Pure file-side helpers for file-backed projects (no DB)."""

    def _tmp(self, content, mode='w'):
        import tempfile as _tf
        fd, path = _tf.mkstemp()
        os.close(fd)
        with open(path, mode) as f:
            f.write(content)
        return path

    def test_count_lines_basic_and_trailing(self):
        from .services import hashfile
        self.assertEqual(hashfile.count_lines(self._tmp('a\nb\nc\n')), 3)
        self.assertEqual(hashfile.count_lines(self._tmp('a\nb\nc')), 3)  # no trailing nl

    def test_count_lines_skips_blanks_and_empty(self):
        from .services import hashfile
        self.assertEqual(hashfile.count_lines(self._tmp('a\n\n  \nb\n')), 2)
        self.assertEqual(hashfile.count_lines(self._tmp('')), 0)

    def test_count_lines_spanning_chunk_boundary(self):
        from .services import hashfile
        n = 5000
        path = self._tmp(''.join('h%d\n' % i for i in range(n)))
        # Force a tiny chunk so lines straddle read boundaries.
        orig = hashfile._CHUNK
        hashfile._CHUNK = 7
        try:
            self.assertEqual(hashfile.count_lines(path), n)
        finally:
            hashfile._CHUNK = orig

    def test_validate_path(self):
        from .services import hashfile
        ok, _ = hashfile.validate_path(self._tmp('x\n'))
        self.assertTrue(ok)
        self.assertFalse(hashfile.validate_path('relative/path')[0])
        self.assertFalse(hashfile.validate_path('/no/such/file/here')[0])
        import tempfile as _tf
        self.assertFalse(hashfile.validate_path(_tf.mkdtemp())[0])  # a directory

    def test_potfile_cracked_count_and_missing(self):
        from .services import hashfile
        self.assertEqual(hashfile.potfile_cracked_count('/no/such.pot'), 0)
        p = self._tmp('h1:pw\nh2:pw2\n')
        self.assertEqual(hashfile.potfile_cracked_count(p), 2)
        # Cache invalidates when the file grows.
        with open(p, 'a') as f:
            f.write('h3:pw3\n')
        self.assertEqual(hashfile.potfile_cracked_count(p), 3)


class ProjectHashSourceTests(TestCase):
    """Project methods route counts/paths through the DB-vs-file abstraction."""

    def setUp(self):
        self.ht = HashType.objects.create(name='HS-MD5', hashcat_module=0)

    def test_db_backed_counts(self):
        p = Project.objects.create(name='DBP', hashtype=self.ht)
        Hash.objects.create(hashstring='a', project=p, cracked=True)
        Hash.objects.create(hashstring='b', project=p, cracked=False)
        self.assertFalse(p.is_file_backed)
        self.assertEqual(p.hash_count_value(), 2)
        self.assertEqual(p.cracked_count(), 1)
        self.assertTrue(p.has_hashes())

    def test_file_backed_counts_and_paths(self):
        import tempfile as _tf
        d = _tf.mkdtemp()
        ext = os.path.join(d, 'h.txt'); open(ext, 'w').write('a\nb\nc\n')
        p = Project.objects.create(name='FP', hashtype=self.ht, hashfile_path=ext)
        self.assertTrue(p.is_file_backed)
        self.assertTrue(p.has_hashes())
        self.assertEqual(p.refresh_hash_count(), 3)
        self.assertEqual(p.hash_count_value(), 3)         # cached
        self.assertEqual(p.cracked_count(), 0)            # no potfile yet
        # Write the resolved potfile -> cracked count reflects it.
        pot = p.resolve_potfile_path()
        os.makedirs(os.path.dirname(pot), exist_ok=True)
        open(pot, 'w').write('a:pw\n')
        self.assertEqual(p.cracked_count(), 1)
        os.remove(pot)

    def test_file_backed_missing_file_has_no_hashes(self):
        p = Project.objects.create(name='MISS', hashtype=self.ht,
                                   hashfile_path='/no/such/file.txt')
        self.assertFalse(p.has_hashes())


class FileBackedViewTests(TestCase):
    """Creating/using a file-backed project through the views."""

    def setUp(self):
        self.ht = HashType.objects.create(name='FV-MD5', hashcat_module=0)
        import tempfile as _tf
        self.d = _tf.mkdtemp()
        self.ext = os.path.join(self.d, 'big.txt')
        open(self.ext, 'w').write('h1\nh2\nh3\nh4\n')

    def test_create_file_backed_project_by_path(self):
        r = self.client.post('/zebra/project/new/', {
            'name': 'FILEPROJ', 'hashtype': str(self.ht.pk),
            'hash_source': 'file', 'hashfile_path': self.ext})
        self.assertEqual(r.status_code, 302)
        p = Project.objects.get(name='FILEPROJ')
        self.assertEqual(p.hashfile_path, self.ext)
        self.assertFalse(p.hashfile_managed)
        self.assertEqual(p.hash_count, 4)
        self.assertEqual(p.hash_set.count(), 0)   # NOT ingested

    def test_create_file_backed_rejects_bad_path(self):
        r = self.client.post('/zebra/project/new/', {
            'name': 'BADPROJ', 'hashtype': str(self.ht.pk),
            'hash_source': 'file', 'hashfile_path': '/no/such/file'})
        self.assertEqual(r.status_code, 200)      # re-render with error
        self.assertFalse(Project.objects.filter(name='BADPROJ').exists())  # rolled back

    def test_create_file_backed_by_upload_is_stored(self):
        from io import BytesIO
        up = BytesIO(b'x1\nx2\n'); up.name = 'list.txt'
        r = self.client.post('/zebra/project/new/', {
            'name': 'UPPROJ', 'hashtype': str(self.ht.pk),
            'hash_source': 'file', 'hashfile_upload': up})
        self.assertEqual(r.status_code, 302)
        p = Project.objects.get(name='UPPROJ')
        self.assertTrue(p.hashfile_managed)
        self.assertTrue(os.path.exists(p.hashfile_path))
        self.assertEqual(p.hash_count, 2)
        self.assertEqual(p.hash_set.count(), 0)

    def test_hashes_add_replaces_path_for_file_backed(self):
        p = Project.objects.create(name='RP', hashtype=self.ht,
                                   hashfile_path=self.ext, hash_count=4)
        other = os.path.join(self.d, 'other.txt'); open(other, 'w').write('a\nb\n')
        r = self.client.post('/zebra/project/%d/hashes/add/' % p.pk,
                             {'hashfile_path': other})
        self.assertEqual(r.status_code, 200)
        p.refresh_from_db()
        self.assertEqual(p.hashfile_path, other)
        self.assertEqual(p.hash_count, 2)

    def test_import_results_appends_to_project_potfile(self):
        p = Project.objects.create(name='IMP', hashtype=self.ht,
                                   hashfile_path=self.ext, hash_count=4)
        pot = p.resolve_potfile_path()
        try:
            r = self.client.post('/zebra/project/%d/import/' % p.pk,
                                 {'kind': 'potfile', 'text': 'h1:secret\nh2:hunter2\n'})
            self.assertEqual(r.status_code, 200)
            self.assertTrue(os.path.exists(pot))
            self.assertEqual(p.cracked_count(), 2)
            from .models import Crack
            self.assertEqual(Crack.objects.count(), 0)  # no Crack rows for file-backed
        finally:
            if os.path.exists(pot):
                os.remove(pot)


class ProjectRunsStatusTests(TestCase):
    """The dashboard's live runs-status endpoint + Progress column."""

    def setUp(self):
        self.ht = HashType.objects.create(name='PR-MD5', hashcat_module=0)
        self.project = Project.objects.create(name='PRUNS', hashtype=self.ht)
        Hash.objects.create(hashstring='h', project=self.project, cracked=False)
        self.mask = Mask.objects.create(project=self.project, pattern='?d?d')

    def _run(self, status, progress=0.0):
        return Run.objects.create(mask=self.mask, project=self.project,
                                  attack_mode=3, status=status, progress=progress)

    def test_status_json_reports_percent_and_active(self):
        self._run('running', 0.42)
        self._run('exhausted', 1.0)
        d = self.client.get('/zebra/project/%d/runs.json' % self.project.pk).json()
        by_pk = {r['pk']: r for r in d['runs']}
        pcts = sorted(r['percent'] for r in d['runs'])
        self.assertEqual(pcts, [42, 100])
        self.assertTrue(d['active'])  # a running run can still change

    def test_status_json_inactive_when_all_terminal(self):
        self._run('exhausted', 1.0)
        self._run('aborted', 0.3)
        d = self.client.get('/zebra/project/%d/runs.json' % self.project.pk).json()
        self.assertFalse(d['active'])

    def test_live_cracks_from_recovered_while_running(self):
        Hash.objects.create(hashstring='h2', project=self.project, cracked=False)  # 2 total
        run = self._run('running', 0.5)
        run.recovered = 1  # hashcat reports 1 recovered so far (no Crack rows yet)
        run.save(update_fields=['recovered'])
        d = self.client.get('/zebra/project/%d/runs.json' % self.project.pk).json()
        row = next(r for r in d['runs'] if r['pk'] == run.pk)
        self.assertEqual(row['cracks'], 1)     # live from recovered
        self.assertEqual(d['cracked'], 1)      # project-level live count
        self.assertEqual(d['cracked_pct'], 50.0)

    def test_finished_run_reports_committed_crack_count(self):
        from .models import Crack
        h = Hash.objects.get(hashstring='h', project=self.project)
        run = self._run('exhausted', 1.0)
        Crack.objects.create(hash=h, plaintext='pw', run=run)
        d = self.client.get('/zebra/project/%d/runs.json' % self.project.pk).json()
        row = next(r for r in d['runs'] if r['pk'] == run.pk)
        self.assertEqual(row['cracks'], 1)     # committed Crack rows, not recovered

    def test_dashboard_shows_progress_only_for_running_and_polls(self):
        self._run('running', 0.5)
        self._run('exhausted', 1.0)
        html = self.client.get('/zebra/project/%d/' % self.project.pk).content.decode()
        self.assertNotIn('<th>Progress</th>', html)   # merged into Status
        self.assertIn('data-runs-url', html)
        self.assertIn('data-run-status="running"', html)
        self.assertIn('50%', html)                    # running run's progress
        # Only the running run gets a progress badge (not the exhausted one).
        self.assertEqual(html.count('class="run-progress'), 1)


class LiveCrackCountHarmonizationTests(TestCase):
    """Live crack counts show on first paint (not 0 until a poll), everywhere."""

    def setUp(self):
        self.ht = HashType.objects.create(name='LH-MD5', hashcat_module=0)
        self.project = Project.objects.create(name='LHP', hashtype=self.ht)
        for s in ('a', 'b', 'c', 'd'):
            Hash.objects.create(hashstring=s, project=self.project, cracked=False)
        self.mask = Mask.objects.create(project=self.project, pattern='?d?d')

    def _running(self, recovered=None):
        return Run.objects.create(mask=self.mask, project=self.project, attack_mode=3,
                                  status='running', progress=0.5, recovered=recovered)

    def test_run_crack_count_uses_recovered_while_running(self):
        run = self._running(recovered=2)
        self.assertEqual(run.crack_count(), 2)          # live, before any Crack rows
        run.status = 'exhausted'
        self.assertEqual(run.crack_count(), 0)          # committed rows once finished

    def test_project_live_cracked_count(self):
        self._running(recovered=3)
        self.assertEqual(self.project.live_cracked_count(), 3)

    def test_dashboard_initial_render_shows_live_cracks(self):
        self._running(recovered=2)
        html = self.client.get('/zebra/project/%d/' % self.project.pk).content.decode()
        # Top card cracked count and the run's Cracks cell reflect recovered at paint.
        self.assertIn('id="proj-cracked">2<', html)
        self.assertIn('class="run-cracks">2<', html)

    def test_run_detail_and_status_json_show_live_cracks(self):
        run = self._running(recovered=2)
        html = self.client.get('/zebra/run/%d/' % run.pk).content.decode()
        self.assertIn('id="run-cracks">2<', html)       # Specification table, first paint
        d = self.client.get('/zebra/run/%d/status.json' % run.pk).json()
        self.assertEqual(d['cracks'], 2)                # endpoint agrees


class OptimizedKernelTests(TestCase):
    """The -O (optimized kernels) option: default on, wired into the command."""

    def setUp(self):
        self.ht = HashType.objects.create(name='OPT-MD5', hashcat_module=0)
        self.project = Project.objects.create(name='OPTP', hashtype=self.ht,
                                              universe='0123456789')
        Hash.objects.create(hashstring='oh1', project=self.project, cracked=False)
        self.url = '/zebra/project/%d/mask/new/' % self.project.pk

    def test_build_run_args_adds_O_when_optimized(self):
        from .services import hashcat as hc
        argv = hc.HashcatRunner().build_run_args(3, 0, hashfile='H',
                                                 params={'mask': '?d?d'}, optimized=True)
        self.assertIn('-O', argv)
        argv = hc.HashcatRunner().build_run_args(3, 0, hashfile='H',
                                                 params={'mask': '?d?d'}, optimized=False)
        self.assertNotIn('-O', argv)

    def test_new_attack_form_checks_optimized_by_default(self):
        html = self.client.get(self.url).content.decode()
        self.assertIn('name="optimized"', html)
        self.assertIn('checked', html)  # on by default

    def test_recommender_record_run_form_enables_optimized(self):
        # The one-click "Record & run" from the suggestion popup must default -O ON,
        # matching the form (a missing field would read as unchecked -> off).
        from unittest import mock
        with mock.patch('zebra.services.hashcat.HashcatRunner.available',
                        return_value=True):
            html = self.client.get('/zebra/project/%d/' % self.project.pk).content.decode()
        self.assertIn('name="optimized" value="1"', html)

    def test_record_optimized_stores_flag_and_command(self):
        self.client.post(self.url, {'pattern': '?d?d', 'custom_charsets': '',
                                    'status': 'planned', 'optimized': '1',
                                    'action': 'record'})
        run = Run.objects.get(mask__project=self.project)
        self.assertTrue(run.optimized)
        self.assertIn(' -O ', run.command)

    def test_record_without_optimized_uses_pure_kernels(self):
        # Checkbox unchecked -> field absent from POST -> optimized False, no -O.
        self.client.post(self.url, {'pattern': '?d?d', 'custom_charsets': '',
                                    'status': 'planned', 'action': 'record'})
        run = Run.objects.get(mask__project=self.project)
        self.assertFalse(run.optimized)
        self.assertNotIn('-O', run.command)


class PerRunCrackAttributionTests(TestCase):
    """File-backed per-run crack attribution: each run is credited only its own
    finds, not the cumulative shared-potfile total."""

    def setUp(self):
        import tempfile as _tf
        self.ht = HashType.objects.create(name='AT-MD5', hashcat_module=0)
        d = _tf.mkdtemp()
        ext = os.path.join(d, 'h.txt'); open(ext, 'w').write('a\nb\nc\nd\n')
        self.project = Project.objects.create(name='ATP', hashtype=self.ht,
                                              hashfile_path=ext, hash_count=4)
        self.mask = Mask.objects.create(project=self.project, pattern='?d?d')

    def _run(self, status, recovered=None, baseline=None):
        return Run.objects.create(mask=self.mask, project=self.project, attack_mode=3,
                                  status=status, recovered=recovered, crack_baseline=baseline)

    def test_run_credited_only_its_delta(self):
        # run1: potfile 0 -> 2 (found 2). run2: potfile 2 -> 3 (found 1).
        r1 = self._run('exhausted', recovered=2, baseline=0)
        r2 = self._run('exhausted', recovered=3, baseline=2)
        self.assertEqual(r1.crack_count(), 2)
        self.assertEqual(r2.crack_count(), 1)   # NOT 3 (the old cumulative bug)

    def test_missing_baseline_reports_zero(self):
        r = self._run('exhausted', recovered=5, baseline=None)  # legacy run
        self.assertEqual(r.crack_count(), 0)

    def test_endpoint_attributes_per_run_and_keeps_project_total(self):
        r1 = self._run('exhausted', recovered=2, baseline=0)
        r2 = self._run('running', recovered=3, baseline=2)
        d = self.client.get('/zebra/project/%d/runs.json' % self.project.pk).json()
        by = {x['pk']: x['cracks'] for x in d['runs']}
        self.assertEqual(by[r1.pk], 2)
        self.assertEqual(by[r2.pk], 1)          # per-run delta, not 3
        self.assertEqual(d['cracked'], 3)       # project total stays cumulative


class ProjectDeleteViewTests(TestCase):
    """Strict typed-confirmation project deletion."""

    def setUp(self):
        self.ht = HashType.objects.create(name='DEL-MD5', hashcat_module=0)
        self.project = Project.objects.create(name='DELPROJ', hashtype=self.ht)
        Hash.objects.create(hashstring='dh', project=self.project, cracked=False)
        self.mask = Mask.objects.create(project=self.project, pattern='?d?d')
        Run.objects.create(mask=self.mask, project=self.project, attack_mode=3,
                           status='planned')
        self.url = '/zebra/project/%d/delete/' % self.project.pk
        self.phrase = 'Permanently delete the project DELPROJ and all of its data'

    def test_confirm_page_shows_the_required_sentence(self):
        r = self.client.get(self.url)
        self.assertEqual(r.status_code, 200)
        self.assertContains(r, self.phrase)
        self.assertContains(r, "Yes, I'm sure")

    def test_wrong_sentence_does_not_delete(self):
        r = self.client.post(self.url, {'confirm_text': 'delete it'})
        self.assertEqual(r.status_code, 200)
        self.assertContains(r, 'did not match')
        self.assertTrue(Project.objects.filter(pk=self.project.pk).exists())

    def test_empty_confirmation_does_not_delete(self):
        self.client.post(self.url, {'confirm_text': ''})
        self.assertTrue(Project.objects.filter(pk=self.project.pk).exists())

    def test_exact_sentence_deletes_and_cascades(self):
        pk = self.project.pk
        r = self.client.post(self.url, {'confirm_text': self.phrase})
        self.assertEqual(r.status_code, 302)
        self.assertIn('/zebra/?deleted=', r['Location'])
        self.assertFalse(Project.objects.filter(pk=pk).exists())
        self.assertFalse(Run.objects.filter(project_id=pk).exists())  # cascaded
        self.assertFalse(Hash.objects.filter(project_id=pk).exists())

    def test_sentence_match_is_trimmed_but_strict(self):
        pk = self.project.pk
        # Leading/trailing whitespace is tolerated...
        self.client.post(self.url, {'confirm_text': '  ' + self.phrase + '  '})
        self.assertFalse(Project.objects.filter(pk=pk).exists())

    def test_file_backed_cleans_up_managed_files_but_not_external(self):
        import tempfile as _tf
        d = _tf.mkdtemp()
        ext = os.path.join(d, 'server-owned.txt'); open(ext, 'w').write('a\n')
        p = Project.objects.create(name='FBDEL', hashtype=self.ht,
                                   hashfile_path=ext, hashfile_managed=False)
        pot = p.resolve_potfile_path()
        os.makedirs(os.path.dirname(pot), exist_ok=True); open(pot, 'w').write('a:x\n')
        phrase = 'Permanently delete the project FBDEL and all of its data'
        self.client.post('/zebra/project/%d/delete/' % p.pk, {'confirm_text': phrase})
        self.assertFalse(Project.objects.filter(pk=p.pk).exists())
        self.assertFalse(os.path.exists(pot))    # zebra-managed potfile removed
        self.assertTrue(os.path.exists(ext))     # operator's external file untouched
        os.remove(ext)


class SmartIncrementTests(TestCase):
    """--increment-min auto-raises past leading lengths already fully covered."""

    def setUp(self):
        self.ht = HashType.objects.create(name='SI-MD5', hashcat_module=0)
        self.project = Project.objects.create(name='SIP', hashtype=self.ht,
                                              universe='?a')

    def _exhaust(self, pattern, inc_min=None, inc_max=None):
        m = Mask.objects.create(project=self.project, pattern=pattern,
                                increment_min=inc_min, increment_max=inc_max)
        ch.compute_and_cache_keyspace(m); m.save()
        Run.objects.create(mask=m, project=self.project, attack_mode=3,
                           status='exhausted')
        return m

    def test_raises_min_past_fully_covered_lengths(self):
        self._exhaust('?a?a?a?a?a?a', inc_min=1, inc_max=6)  # lengths 1-6 covered
        ev = ch.evaluate_candidate(self.project, '?d?d?d?d?d?d?d?d?d?d',
                                   increment_min=1, increment_max=10)
        self.assertEqual(ev['increment_min_requested'], 1)
        self.assertEqual(ev['increment_min'], 7)     # first uncovered length
        self.assertEqual(ev['increment_skipped'], 6)
        self.assertFalse(ev['redundant_increment'])

    def test_fully_covered_sweep_is_redundant(self):
        self._exhaust('?a?a?a?a?a?a', inc_min=1, inc_max=6)
        ev = ch.evaluate_candidate(self.project, '?d?d?d?d?d',
                                   increment_min=1, increment_max=5)
        self.assertTrue(ev['redundant_increment'])
        self.assertTrue(ev['subsumed'])

    def test_no_adjustment_when_nothing_covered(self):
        ev = ch.evaluate_candidate(self.project, '?d?d?d?d',
                                   increment_min=1, increment_max=4)
        self.assertEqual(ev['increment_min'], 1)
        self.assertEqual(ev['increment_skipped'], 0)

    def test_only_leading_contiguous_lengths_skipped(self):
        # Cover lengths 1 and 3 but NOT 2: only length 1 (leading) can be skipped.
        self._exhaust('?a')            # length 1
        self._exhaust('?a?a?a')        # length 3
        ev = ch.evaluate_candidate(self.project, '?d?d?d?d',
                                   increment_min=1, increment_max=4)
        self.assertEqual(ev['increment_min'], 2)   # stops at the first gap
        self.assertEqual(ev['increment_skipped'], 1)

    def test_record_stores_effective_min(self):
        self._exhaust('?a?a?a?a?a?a', inc_min=1, inc_max=6)
        url = '/zebra/project/%d/mask/new/' % self.project.pk
        self.client.post(url, {'pattern': '?d?d?d?d?d?d?d?d', 'custom_charsets': '',
                               'increment': '1', 'increment_max': '8',
                               'status': 'planned', 'action': 'record'})
        run = Run.objects.filter(project=self.project, attack_mode=3,
                                 mask__pattern='?d?d?d?d?d?d?d?d').latest('pk')
        self.assertEqual(run.mask.increment_min, 7)   # auto-raised, not 1
        self.assertEqual(run.mask.increment_max, 8)
        self.assertIn('--increment-min 7', run.command)

    def test_redundant_sweep_is_not_recordable(self):
        self._exhaust('?a?a?a?a?a?a', inc_min=1, inc_max=6)
        url = '/zebra/project/%d/mask/new/' % self.project.pk
        r = self.client.post(url, {'pattern': '?d?d?d?d', 'custom_charsets': '',
                                   'increment': '1', 'increment_max': '4',
                                   'status': 'planned', 'action': 'record'})
        self.assertContains(r, 'Nothing to run')
        self.assertFalse(Run.objects.filter(mask__pattern='?d?d?d?d').exists())


class PotfileCrackRangeTests(TestCase):
    """Per-run potfile row range pinpoints exactly which cracks each job made."""

    def setUp(self):
        import tempfile as _tf
        self.ht = HashType.objects.create(name='PR-MD5', hashcat_module=0)
        self.d = _tf.mkdtemp()
        ext = os.path.join(self.d, 'h.txt'); open(ext, 'w').write('a\nb\nc\n')
        self.project = Project.objects.create(name='PRP', hashtype=self.ht,
                                              hashfile_path=ext, hash_count=3)
        self.mask = Mask.objects.create(project=self.project, pattern='?d?d')
        # A shared, append-only project potfile written by successive runs.
        self.pot = self.project.resolve_potfile_path()
        os.makedirs(os.path.dirname(self.pot), exist_ok=True)
        open(self.pot, 'w').write('h1:alpha\nh2:beta\nh3:gamma\n')  # 3 cracks total

    def tearDown(self):
        if os.path.exists(self.pot):
            os.remove(self.pot)

    def _run(self, start, end):
        return Run.objects.create(mask=self.mask, project=self.project, attack_mode=3,
                                  status='exhausted', crack_baseline=start,
                                  crack_range_end=end)

    def test_potfile_cracks_returns_only_this_runs_block(self):
        r1 = self._run(0, 2)   # rows 0-1: h1, h2
        r2 = self._run(2, 3)   # row 2: h3
        self.assertEqual(r1.potfile_cracks(),
                         [('h1', 'alpha'), ('h2', 'beta')])
        self.assertEqual(r2.potfile_cracks(), [('h3', 'gamma')])
        self.assertEqual(r1.crack_count(), 2)
        self.assertEqual(r2.crack_count(), 1)

    def test_empty_range_returns_no_cracks(self):
        r = self._run(3, 3)    # found nothing
        self.assertEqual(r.potfile_cracks(), [])
        self.assertEqual(r.crack_count(), 0)

    def test_limit_caps_returned_pairs(self):
        r = self._run(0, 3)
        self.assertEqual(len(r.potfile_cracks(limit=2)), 2)  # capped
        self.assertEqual(r.crack_count(), 3)                 # true count unaffected

    def test_db_backed_run_has_no_potfile_cracks(self):
        p = Project.objects.create(name='DBB', hashtype=self.ht)
        run = Run.objects.create(project=p, attack_mode=3, status='exhausted')
        self.assertIsNone(run.potfile_cracks())


class RunOrQueueTests(TestCase):
    """Unified run/queue action: run when idle, queue when a job is in progress."""

    def setUp(self):
        self.ht = HashType.objects.create(name='RQ-MD5', hashcat_module=0)
        self.project = Project.objects.create(name='RQP', hashtype=self.ht)
        Hash.objects.create(hashstring='h', project=self.project, cracked=False)

    def tearDown(self):
        with launcher._lock:
            launcher._active.clear()
        launcher.set_queue_paused(False)

    def _mask_run(self, status='planned', pattern='?d?d'):
        m = Mask.objects.create(project=self.project, pattern=pattern)
        r = Run.objects.create(mask=m, project=self.project, attack_mode=3, status=status)
        r.hashes.set(self.project.hash_set.all())
        return r

    def _mark_busy(self):
        busy = self._mask_run(status='running')
        with launcher._lock:
            launcher._active[busy.pk] = type('P', (), {'pid': 4242})()
        return busy

    def test_would_queue_reflects_busy_state(self):
        self.assertFalse(launcher.would_queue())      # idle
        self._mark_busy()
        self.assertTrue(launcher.would_queue())       # a live run is in progress

    def test_run_or_queue_starts_when_idle(self):
        run = self._mask_run()
        with mock.patch.object(launcher, 'start_run', return_value=None) as m:
            action, err = launcher.run_or_queue(run)
        m.assert_called_once_with(run)
        self.assertEqual((action, err), ('started', None))

    def test_run_or_queue_queues_when_busy(self):
        self._mark_busy()
        run = self._mask_run(pattern='?d?d?d')
        with mock.patch.object(launcher, 'start_run') as m:
            action, err = launcher.run_or_queue(run)
        m.assert_not_called()                         # never tries to start
        self.assertEqual(action, 'queued')
        run.refresh_from_db()
        self.assertEqual(run.status, 'queued')

    def test_run_or_queue_surfaces_real_error(self):
        run = self._mask_run()
        with mock.patch.object(launcher, 'start_run',
                               return_value='hashcat is not installed on this machine.'):
            action, err = launcher.run_or_queue(run)
        self.assertEqual(action, 'error')
        self.assertIn('not installed', err)


class RecommenderPipelineTests(TestCase):
    """The recommender excludes masks already planned/queued, not just exhausted."""

    def setUp(self):
        self.ht = HashType.objects.create(name='RP-HT', hashcat_module=111)
        self.project = Project.objects.create(name='recopipe', hashtype=self.ht,
                                              universe='?l?u?d', benchmark_hs=10**10)
        Hash.objects.create(hashstring='a' * 32, project=self.project)

    def _record_mask(self, pattern, status):
        m = Mask.objects.create(project=self.project, pattern=pattern)
        ch.compute_and_cache_keyspace(m); m.save()
        Run.objects.create(mask=m, project=self.project, attack_mode=3, status=status)
        return m

    def _patterns(self, seconds=3600):
        j = self.client.get('/zebra/project/%d/recommend.json?seconds=%d'
                            % (self.project.pk, seconds)).json()
        return {r['pattern'] for r in j.get('recommendations', [])}

    def test_planned_expansion_includes_all_non_failed_states(self):
        for st in ('planned', 'queued', 'running', 'exhausted', 'cracked'):
            self._record_mask('?d?d', st)
        # aborted / error are NOT counted (can be suggested again)
        self._record_mask('?l?l', 'aborted')
        got = {m.pattern for m in ch.planned_masks(self.project)}
        self.assertIn('?d?d', got)
        self.assertNotIn('?l?l', got)

    def test_queued_mask_is_not_re_suggested(self):
        # Find a pattern the recommender would offer, then queue it and confirm it
        # disappears from the suggestions (previously only 'exhausted' excluded it).
        offered = self._patterns()
        self.assertTrue(offered, 'expected at least one suggestion to test with')
        target = next(iter(offered))
        self._record_mask(target, 'queued')          # merely queued, never run
        self.assertNotIn(target, self._patterns())

    def test_coverage_still_counts_only_exhausted(self):
        # The broader recommender set must NOT leak into coverage math.
        self._record_mask('?d?d', 'queued')
        self.assertEqual(ch.project_coverage(self.project), [])  # nothing exhausted


class QueueMasterSwitchTests(TestCase):
    """The header master switch: three persistent modes (off / on / auto)."""

    def tearDown(self):
        launcher.set_queue_mode('on')

    def test_mode_persists_on_settings(self):
        from zebra.models import Settings
        launcher.set_queue_mode('off')
        self.assertTrue(launcher.is_paused())
        self.assertEqual(Settings.load().queue_mode, 'off')  # persisted
        launcher.set_queue_mode('auto')
        self.assertTrue(launcher.is_auto())
        self.assertFalse(launcher.is_paused())

    def test_header_shows_active_mode(self):
        launcher.set_queue_mode('auto')
        html = self.client.get('/zebra/').content.decode()
        self.assertIn('qseg-btn auto active', html)
        self.assertNotIn('qseg-btn off active', html)

    def test_mode_endpoint_sets_and_returns_to_next(self):
        with mock.patch.object(launcher, '_advance_queue', return_value=None):
            r = self.client.post('/zebra/queue/mode/',
                                 {'mode': 'off', 'next': '/zebra/settings/'})
            self.assertRedirects(r, '/zebra/settings/', fetch_redirect_response=False)
            self.assertTrue(launcher.is_paused())
            self.client.post('/zebra/queue/mode/', {'mode': 'auto', 'next': '/zebra/'})
            self.assertTrue(launcher.is_auto())

    def test_mode_endpoint_rejects_offsite_next(self):
        with mock.patch.object(launcher, '_advance_queue', return_value=None):
            r = self.client.post('/zebra/queue/mode/',
                                 {'mode': 'off', 'next': '//evil.example'})
        self.assertRedirects(r, '/zebra/queue/', fetch_redirect_response=False)

    def test_off_does_not_auto_advance(self):
        ht = HashType.objects.create(name='MS-MD5', hashcat_module=0)
        p = Project.objects.create(name='MSP', hashtype=ht)
        Hash.objects.create(hashstring='h', project=p, cracked=False)
        mask = Mask.objects.create(project=p, pattern='?d?d')
        run = Run.objects.create(mask=mask, project=p, attack_mode=3, status='planned')
        run.hashes.set(p.hash_set.all())
        launcher.set_queue_mode('off')
        with mock.patch.object(launcher, 'start_run', return_value=None) as m:
            launcher.enqueue(run)                 # queued, but not started (off)
            self.assertIsNone(launcher._advance_queue())
            m.assert_not_called()
        run.refresh_from_db()
        self.assertEqual(run.status, 'queued')    # waits until switched on

    def test_settings_page_sets_auto_task_length(self):
        from zebra.models import Settings
        self.client.post('/zebra/settings/',
                         {'hashcat_binary': '', 'auto_task_minutes': '15'})
        self.assertEqual(Settings.load().auto_task_seconds, 900)


class AutoPilotTests(TestCase):
    """Auto mode fills an empty queue with a fresh suggested attack."""

    def setUp(self):
        self.ht = HashType.objects.create(name='AP-HT', hashcat_module=222)
        self.project = Project.objects.create(name='autop', hashtype=self.ht,
                                              universe='?l?u?d', benchmark_hs=10**10)
        Hash.objects.create(hashstring='a' * 32, project=self.project)

    def tearDown(self):
        launcher.set_queue_mode('on')

    def test_build_auto_run_records_a_suggested_attack(self):
        from zebra import autopilot
        run = autopilot.build_auto_run(self.project, seconds=3600)
        self.assertIsNotNone(run)
        self.assertEqual(run.attack_mode, 3)
        self.assertIsNotNone(run.mask)
        self.assertTrue(run.optimized)
        self.assertEqual(run.comment, 'auto-pilot')

    def test_auto_task_sized_to_configured_length(self):
        from zebra import autopilot
        from zebra.models import Settings
        s = Settings.load(); s.auto_task_seconds = 60; s.save()
        run = autopilot.build_auto_run(self.project)   # uses Settings default
        ks = int(run.mask.keyspace)
        # keyspace should land near benchmark_hs * 60 (well under the 1h target's).
        self.assertLess(ks, 10**10 * 3600)

    def test_eligible_requires_benchmark_and_hashes(self):
        from zebra import autopilot
        Project.objects.create(name='nobench', hashtype=self.ht)  # no benchmark
        names = {p.name for p in autopilot._eligible_projects()}
        self.assertIn('autop', names)
        self.assertNotIn('nobench', names)

    def test_advance_auto_fills_when_queue_empty(self):
        # Auto mode + empty queue + idle -> a suggested run is created and started.
        launcher.set_queue_mode('auto')
        with mock.patch('zebra.services.hashcat.HashcatRunner.available',
                        return_value=True), \
             mock.patch.object(launcher, 'start_run', return_value=None) as start:
            started = launcher._advance_queue()
        self.assertIsNotNone(started)               # auto-pilot produced a run
        self.assertEqual(started.comment, 'auto-pilot')
        start.assert_called_once()

    def test_on_mode_does_not_auto_fill(self):
        launcher.set_queue_mode('on')
        with mock.patch('zebra.services.hashcat.HashcatRunner.available',
                        return_value=True), \
             mock.patch.object(launcher, 'start_run', return_value=None) as start:
            self.assertIsNone(launcher._advance_queue())   # nothing queued, no fill
        start.assert_not_called()
        self.assertFalse(Run.objects.exists())


class ComplementEngineTests(SimpleTestCase):
    """Pure complement math: exact untried-region cover as boxes/masks."""

    def _vol(self, box):
        v = 1
        for s in box:
            v *= len(s)
        return v

    def test_untried_volume_matches_invariant(self):
        U = cov.expand_charset('?a')
        covered = [P('?l?l?a?a'), P('?d?d?a?a')]
        res = cov.complement_boxes(covered, U, 4)
        self.assertEqual(res['untried'], 74447225)             # 95^4 - (26²+10²)·95²
        self.assertFalse(res['truncated'])
        self.assertEqual(sum(self._vol(b) for b in res['boxes']), res['untried'])

    def test_empty_covered_is_whole_space(self):
        U = cov.expand_charset('?d')
        res = cov.complement_boxes([], U, 3)
        self.assertEqual(res['untried'], 1000)
        self.assertEqual(sum(self._vol(b) for b in res['boxes']), 1000)

    def test_fully_covered_has_no_gaps(self):
        U = cov.expand_charset('?d')
        res = cov.complement_boxes([P('?d?d')], U, 2)
        self.assertEqual(res['untried'], 0)
        self.assertEqual(res['boxes'], [])

    def test_boxes_disjoint_from_covered(self):
        U = cov.expand_charset('?a')
        covered = [P('?l?l?a?a'), P('?d?d?a?a')]
        res = cov.complement_boxes(covered, U, 4)
        for box in res['boxes']:
            for cm in covered:
                # a box overlaps a covered mask only if every position intersects
                self.assertTrue(any(not (set(box[p]) & set(cm[p])) for p in range(4)))

    def test_merge_preserves_volume_and_cuts_count(self):
        U = cov.expand_charset('?a')
        res = cov.complement_boxes([P('?l?l?a?a'), P('?d?d?a?a')], U, 4)
        merged = cov.merge_boxes(res['boxes'])
        self.assertEqual(sum(self._vol(b) for b in merged), res['untried'])

    def test_builtin_expansion_is_builtin_only_and_exact(self):
        U = cov.expand_charset('?a')
        res = cov.complement_boxes([P('?l?l?a?a'), P('?d?d?a?a')], U, 4)
        boxes = [b for box in res['boxes'] for b in cov.expand_box_builtins(box)]
        self.assertEqual(sum(self._vol(b) for b in boxes), res['untried'])
        builtins = {frozenset(cov.BUILTIN_CHARSETS[s]) for s in 'ludsahH'}
        for box in boxes:
            for s in box:
                self.assertTrue(s in builtins or len(s) == 1)   # single class or literal
            for pat, custom in cov.render_box(box):
                self.assertEqual(custom, {})                    # no custom charsets

    def test_render_builtin_and_custom(self):
        u = frozenset(cov.BUILTIN_CHARSETS['u'])
        s = frozenset(cov.BUILTIN_CHARSETS['s'])
        a = frozenset(cov.BUILTIN_CHARSETS['a'])
        [(pat, custom)] = cov.render_box((u | s, a, a, a))
        self.assertEqual(pat, '?1?a?a?a')
        self.assertEqual(custom, {'1': '?u?s'})

    def test_render_splits_when_over_four_slots(self):
        B = {c: frozenset(cov.BUILTIN_CHARSETS[c]) for c in 'luds'}
        # five positions, each a distinct multi-class (custom) set -> needs >4 slots
        box = (B['l'] | B['u'], B['l'] | B['d'], B['u'] | B['d'],
               B['u'] | B['s'], B['d'] | B['s'])
        masks = cov.render_box(box)
        self.assertGreater(len(masks), 1)                       # had to split
        total = 1
        for st in box:
            total *= len(st)
        got = 0
        for pat, custom in masks:
            self.assertLessEqual(len(custom), 4)                # within hashcat's limit
            self.assertNotIn('?c', pat)
            got += cov.mask_keyspace(cov.parse_mask(pat, custom_charsets=custom))
        self.assertEqual(got, total)                            # split preserves union

    def test_cap_truncates_without_emitting_covered(self):
        U = cov.expand_charset('?a')
        res = cov.complement_boxes([P('?l?l?a?a'), P('?d?d?a?a')], U, 4, box_cap=1)
        self.assertTrue(res['truncated'])
        self.assertGreater(res['omitted_boxes'], 0)
        # shown boxes still lie entirely in the untried region
        self.assertLessEqual(sum(self._vol(b) for b in res['boxes']), res['untried'])


class ComplementViewTests(TestCase):
    """Fill-gaps glue, endpoint, record round-trip, and Queue-all."""

    def setUp(self):
        self.ht = HashType.objects.create(name='CX-MD5', hashcat_module=0)
        self.project = Project.objects.create(name='CXP', hashtype=self.ht,
                                              universe='?a', benchmark_hs=10**9)
        Hash.objects.create(hashstring='a' * 32, project=self.project)

    def _exhaust(self, pattern):
        m = Mask.objects.create(project=self.project, pattern=pattern)
        Run.objects.create(mask=m, project=self.project, attack_mode=3, status='exhausted')
        return m

    def _plan(self, pattern):
        m = Mask.objects.create(project=self.project, pattern=pattern)
        Run.objects.create(mask=m, project=self.project, attack_mode=3, status='planned')
        return m

    def test_glue_requires_universe(self):
        p = Project.objects.create(name='NOUNIV', hashtype=self.ht)
        self.assertEqual(ch.project_complement_masks(p, 4), {'error': 'no-universe'})

    def test_glue_excludes_planned_and_queued(self):
        self._exhaust('?l?l?a?a')
        self._plan('?d?d?a?a')                     # planned counts as tried
        res = ch.project_complement_masks(self.project, 4)
        self.assertEqual(res['summary']['untried'], 74447225)  # both excluded

    def test_json_compact_and_builtins(self):
        self._exhaust('?l?l?a?a'); self._exhaust('?d?d?a?a')
        d = self.client.get('/zebra/project/%d/complement/4.json?style=compact'
                            % self.project.pk).json()
        self.assertTrue(d['ok'])
        self.assertEqual(d['summary']['untried'], '74447225')  # string (JS precision)
        self.assertTrue(any(m['custom_charsets'] for m in d['masks']))
        b = self.client.get('/zebra/project/%d/complement/4.json?style=builtins'
                            % self.project.pk).json()
        self.assertTrue(all(m['custom_charsets'] == {} for m in b['masks']))

    def test_record_url_round_trips_custom_charsets(self):
        self._exhaust('?l?l?a?a'); self._exhaust('?d?d?a?a')
        d = self.client.get('/zebra/project/%d/complement/4.json'
                            % self.project.pk).json()
        m = next(x for x in d['masks'] if x['custom_charsets'])
        r = self.client.get(m['record_url'])                   # follow the Record link
        self.assertContains(r, m['pattern'])
        self.assertContains(r, m['custom_charsets_raw'])       # e.g. "1=?u?s" in textarea

    def test_record_run_persists_custom_charsets(self):
        from unittest import mock
        with mock.patch('zebra.views.launcher.run_or_queue',
                        return_value=('queued', None)):
            self.client.post('/zebra/project/%d/mask/new/' % self.project.pk,
                             {'attack_mode': '3', 'pattern': '?1?a?a?a',
                              'custom_charsets': '1=?u?s', 'status': 'planned',
                              'optimized': '1', 'action': 'record_run'})
        mask = Mask.objects.get(project=self.project, pattern='?1?a?a?a')
        self.assertEqual(mask.custom_charsets, {'1': '?u?s'})

    def test_queue_all_enqueues_and_is_idempotent(self):
        from unittest import mock
        self._exhaust('?l?l?a?a'); self._exhaust('?d?d?a?a')
        url = '/zebra/project/%d/complement/4/queue' % self.project.pk
        with mock.patch('zebra.views.launcher.enqueue', return_value=None):
            d1 = self.client.post(url, {'style': 'compact'}).json()
            self.assertGreater(d1['queued'], 0)              # queued the gap masks
            self.assertEqual(d1['skipped'], 0)
            self.assertEqual(Run.objects.filter(project=self.project,
                             status='planned').count(), d1['queued'])
            # Re-run: the just-queued masks now count as tried, so no gaps remain.
            d2 = self.client.post(url, {'style': 'compact'}).json()
        self.assertEqual(d2['queued'], 0)
        # The length is now fully covered by queued masks -> zero untried keyspace.
        self.assertEqual(ch.project_complement_masks(self.project, 4)['summary']['untried'], 0)
