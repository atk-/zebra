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
