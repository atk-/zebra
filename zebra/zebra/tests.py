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
