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
        self.other = HashType.objects.create(name='T-NTLM', hashcat_module=1000)
        self.project = Project.objects.create(name='RUNTEST', universe='0123456789')
        self.h1 = Hash.objects.create(hashstring='h1', hashtype=self.ht,
                                      project=self.project, cracked=False)
        self.h2 = Hash.objects.create(hashstring='h2', hashtype=self.ht,
                                      project=self.project, cracked=False)
        self.h3 = Hash.objects.create(hashstring='h3', hashtype=self.other,
                                      project=self.project, cracked=False)

    def _record(self, pattern, status):
        mask = Mask.objects.create(project=self.project, pattern=pattern)
        ch.compute_and_cache_keyspace(mask); mask.save()
        run = Run.objects.create(mask=mask, attack_mode=3, hashtype=self.ht,
                                 status=status)
        run.hashes.set(self.project.hash_set.filter(hashtype=self.ht))
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

    def test_run_targets_only_chosen_hashtype_hashes(self):
        _, run = self._record('?d?d', 'exhausted')
        self.assertEqual(set(run.hashes.values_list('hashstring', flat=True)),
                         {'h1', 'h2'})  # h3 is a different hashtype


class RecordAttackViewTests(TestCase):
    def setUp(self):
        self.ht = HashType.objects.create(name='V-MD5', hashcat_module=0)
        self.project = Project.objects.create(name='VIEWTEST', universe='0123456789')
        Hash.objects.create(hashstring='vh1', hashtype=self.ht,
                            project=self.project, cracked=False)

    def test_record_attack_creates_run_and_counts_coverage(self):
        url = '/zebra/project/%d/mask/new/' % self.project.pk
        r = self.client.post(url, {'pattern': '?d?d', 'custom_charsets': '',
                                   'hashtype': str(self.ht.pk),
                                   'status': 'exhausted', 'action': 'record'})
        self.assertEqual(r.status_code, 302)
        run = Run.objects.get(mask__project=self.project)
        self.assertEqual(run.status, 'exhausted')
        self.assertEqual(run.hashtype_id, self.ht.pk)
        self.assertEqual(run.hashes.count(), 1)
        # dashboard shows the attack + non-zero coverage
        d = self.client.get('/zebra/project/%d/' % self.project.pk)
        self.assertContains(d, 'Attacks (1)')
        self.assertContains(d, '?d?d')

    def test_planned_attack_contributes_zero_coverage(self):
        url = '/zebra/project/%d/mask/new/' % self.project.pk
        self.client.post(url, {'pattern': '?d?d?d', 'custom_charsets': '',
                               'hashtype': str(self.ht.pk),
                               'status': 'planned', 'action': 'record'})
        self.assertTrue(Run.objects.filter(status='planned').exists())
        self.assertEqual(ch.project_coverage(self.project), [])


class AddHashesViewTests(TestCase):
    def setUp(self):
        self.ht = HashType.objects.create(name='A-MD5', hashcat_module=0)
        self.ntlm = HashType.objects.create(name='A-NTLM', hashcat_module=1000)
        self.project = Project.objects.create(name='ADDTEST')
        Hash.objects.create(hashstring='dup', hashtype=self.ht,
                            project=self.project, cracked=False)

    def test_add_hashes_dedups_and_skips_existing(self):
        url = '/zebra/project/%d/hashes/add/' % self.project.pk
        r = self.client.post(url, {'hashtype': str(self.ht.pk),
                                   'hashlist': 'a\nb\na\n dup \n\n'})  # dup + repeat + blank
        self.assertEqual(r.status_code, 200)
        self.assertContains(r, 'Added 2 hash(es)')
        self.assertContains(r, '2 duplicate(s) skipped')  # repeated 'a' + existing 'dup'
        got = set(self.project.hash_set.filter(hashtype=self.ht)
                  .values_list('hashstring', flat=True))
        self.assertEqual(got, {'dup', 'a', 'b'})

    def test_add_hashes_of_a_new_hashtype(self):
        url = '/zebra/project/%d/hashes/add/' % self.project.pk
        self.client.post(url, {'hashtype': str(self.ntlm.pk), 'hashlist': 'n1\nn2'})
        self.assertEqual(self.project.hash_set.filter(hashtype=self.ntlm).count(), 2)
        # now the record-attack form offers both hashtypes present in the project
        d = self.client.get('/zebra/project/%d/mask/new/' % self.project.pk)
        self.assertContains(d, 'A-MD5 (0)')
        self.assertContains(d, 'A-NTLM (1000)')

    def test_missing_hashtype_is_rejected(self):
        url = '/zebra/project/%d/hashes/add/' % self.project.pk
        r = self.client.post(url, {'hashtype': '', 'hashlist': 'x'})
        self.assertContains(r, 'choose a hashtype')
        self.assertFalse(self.project.hash_set.filter(hashstring='x').exists())


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
        self.project = Project.objects.create(name='NONMASK')
        Hash.objects.create(hashstring='nh1', hashtype=self.ht,
                            project=self.project, cracked=False)
        self.url = '/zebra/project/%d/mask/new/' % self.project.pk

    def _record_straight(self, wordlist, rules):
        return self.client.post(self.url, {
            'attack_mode': '0', 'hashtype': str(self.ht.pk), 'status': 'exhausted',
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
            'attack_mode': '0', 'hashtype': str(self.ht.pk), 'status': 'exhausted',
            'wordlist': 'rockyou.txt', 'rules': 'best64.rule', 'action': 'preview'})
        self.assertContains(r, 'Duplicate')

    def test_superset_rules_flagged_near_duplicate(self):
        self._record_straight('rockyou.txt', 'best64.rule')
        r = self.client.post(self.url, {
            'attack_mode': '0', 'hashtype': str(self.ht.pk), 'status': 'planned',
            'wordlist': 'rockyou.txt', 'rules': 'best64.rule\nd3ad0ne.rule',
            'action': 'preview'})
        self.assertContains(r, 'Near-duplicate')
        self.assertContains(r, 'subset')

    def test_combinator_records_ordered_pair(self):
        r = self.client.post(self.url, {
            'attack_mode': '1', 'hashtype': str(self.ht.pk), 'status': 'exhausted',
            'left_wordlist': 'left.txt', 'right_wordlist': 'right.txt', 'action': 'record'})
        self.assertEqual(r.status_code, 302)
        run = Run.objects.get(project=self.project, attack_mode=1)
        order_names = [Wordlist.objects.get(pk=i).name for i in run.params['order']]
        self.assertEqual(order_names, ['left.txt', 'right.txt'])
        self.assertEqual(run.describe(), 'left.txt × right.txt')

    def test_hybrid_records_wordlist_and_mask(self):
        r = self.client.post(self.url, {
            'attack_mode': '6', 'hashtype': str(self.ht.pk), 'status': 'exhausted',
            'wordlist': 'rockyou.txt', 'pattern': '?d?d?d', 'action': 'record'})
        self.assertEqual(r.status_code, 302)
        run = Run.objects.get(project=self.project, attack_mode=6)
        self.assertEqual(run.params.get('mask'), '?d?d?d')
        self.assertEqual(run.describe(), 'rockyou.txt + ?d?d?d')
        # hybrid mask must NOT pollute exact mask coverage
        self.assertEqual(ch.covered_masks(self.project).count(), 0)

    def test_missing_wordlist_rejected(self):
        r = self.client.post(self.url, {
            'attack_mode': '0', 'hashtype': str(self.ht.pk), 'status': 'exhausted',
            'wordlist': '', 'rules': '', 'action': 'record'})
        self.assertContains(r, 'needs a wordlist')
        self.assertFalse(Run.objects.filter(project=self.project).exists())

    def test_mask_mode_still_gets_exact_coverage(self):
        # regression: mode 3 unchanged
        r = self.client.post(self.url, {
            'attack_mode': '3', 'hashtype': str(self.ht.pk), 'status': 'exhausted',
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
        self.project = Project.objects.create(name='SELREG')
        Hash.objects.create(hashstring='s1', hashtype=self.ht,
                            project=self.project, cracked=False)
        self.url = '/zebra/project/%d/mask/new/' % self.project.pk

    def test_preview_keeps_mode_zero_selected(self):
        r = self.client.post(self.url, {
            'attack_mode': '0', 'hashtype': str(self.ht.pk), 'status': 'exhausted',
            'wordlist': 'rockyou.txt', 'rules': 'best64.rule', 'action': 'preview'})
        self.assertContains(r, '<option value="0" selected>')
        self.assertNotContains(r, '<option value="3" selected>')

    def test_get_defaults_to_mask_mode(self):
        r = self.client.get(self.url)
        self.assertContains(r, '<option value="3" selected>')
        self.assertNotContains(r, '<option value="0" selected>')
