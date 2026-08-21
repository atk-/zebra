from django.db import models


class Project(models.Model):
    name = models.CharField(max_length=200, unique=True)
    description = models.CharField(max_length=8192, blank=True, null=True)
    # Characters considered in-scope for this project when computing the
    # "remaining" search space (total per length = len(universe) ** length).
    # If blank, coverage totals fall back to the union of charsets actually used.
    universe = models.CharField(max_length=1000, blank=True, null=True)

    def __str__(self):
        return self.name


class HashType(models.Model):
    name = models.CharField(max_length=200, unique=True)
    hashcat_module = models.IntegerField()
    comment = models.CharField(max_length=1024, null=True, blank=True)

    class Meta:
        ordering = ['hashcat_module']

    def __str__(self):
        return '%s (%d)' % (self.name, self.hashcat_module)


class Hash(models.Model):
    hashstring = models.CharField(max_length=65536)
    hashtype = models.ForeignKey(HashType, on_delete=models.CASCADE)
    project = models.ForeignKey(Project, on_delete=models.CASCADE)
    cracked = models.BooleanField(default=False)
    comment = models.CharField(max_length=4096, blank=True, null=True)

    def __str__(self):
        L = 32
        return self.hashstring[:L] + \
            ('...' if len(self.hashstring) > L else '') + \
            ' [%d]' % len(self.hashstring)


class CharacterSet(models.Model):
    # XXX this could also be another way around: charset is defined by its wildcards?
    name = models.CharField(max_length=100)
    characters = models.CharField(max_length=1000)
    comment = models.CharField(max_length=1024, null=True, blank=True)

    def __str__(self):
        return self.name


class Wildcard(models.Model):
    # TODO by default create a wildcard ?a for each character set
    # TODO maybe check that wildcard chars are a subset of charset?
    symbol = models.CharField(max_length=1)
    characters = models.CharField(max_length=1000)
    parent_set = models.ForeignKey(CharacterSet, on_delete=models.CASCADE)
    comment = models.CharField(max_length=1024, null=True, blank=True)

    def __str__(self):
        return '?%s' % self.symbol


class Mask(models.Model):
    """A hashcat mask (attack mode 3), e.g. ``?u?l?l?l?d?d``.

    The mask is the central object of the tool: coverage, overlap and the
    remaining search space are all computed from the set of masks already run.
    ``keyspace`` caches the exact candidate count (product of per-position
    charset sizes) computed by the coverage engine -- NOT hashcat --keyspace,
    which returns a different (host-side chunking) number for -a 3.
    """
    project = models.ForeignKey(Project, on_delete=models.CASCADE, related_name='masks')
    pattern = models.CharField(max_length=1024)
    # Optional hashcat custom charset definitions: {"1": "?l?d", "2": "abc", ...}
    custom_charsets = models.JSONField(default=dict, blank=True)
    length = models.IntegerField(default=0)  # number of positions, derived on save
    keyspace = models.DecimalField(max_digits=80, decimal_places=0, null=True, blank=True)
    comment = models.CharField(max_length=1024, null=True, blank=True)

    class Meta:
        ordering = ['length', 'pattern']

    def __str__(self):
        return self.pattern


class Wordlist(models.Model):
    """A dictionary file referenced by wordlist/combinator/hybrid runs.

    Global (reused across projects, like HashType). ``line_count`` is optional and
    reserved for future hybrid keyspace estimates (line_count * mask_keyspace)."""
    name = models.CharField(max_length=300, unique=True)
    path = models.CharField(max_length=1024, blank=True, null=True)
    line_count = models.BigIntegerField(null=True, blank=True)
    comment = models.CharField(max_length=1024, null=True, blank=True)

    class Meta:
        ordering = ['name']

    def __str__(self):
        return self.name


class RuleSet(models.Model):
    """A hashcat rule file (-r) referenced by wordlist/hybrid runs. Global."""
    name = models.CharField(max_length=300, unique=True)
    path = models.CharField(max_length=1024, blank=True, null=True)
    rule_count = models.BigIntegerField(null=True, blank=True)
    comment = models.CharField(max_length=1024, null=True, blank=True)

    class Meta:
        ordering = ['name']

    def __str__(self):
        return self.name


class Run(models.Model):
    """One execution of an attack against a set of hashes.

    Mask runs (attack_mode 3) carry a ``Mask`` and feed the exact coverage engine.
    Non-mask runs (straight/combinator/hybrid) can't have their keyspace computed,
    so they instead reference ``Wordlist``/``RuleSet`` (+ ``params`` scalars) and are
    compared with the similarity engine to catch repeated / near-duplicate work.
    """
    STATUS_CHOICES = [
        ('planned', 'Planned'),
        ('running', 'Running'),
        ('exhausted', 'Exhausted'),
        ('aborted', 'Aborted'),
        ('cracked', 'Cracked'),
        ('error', 'Error'),
    ]
    # hashcat attack modes zebra records
    ATTACK_MODES = [
        (0, 'Straight'),
        (1, 'Combinator'),
        (3, 'Mask'),
        (6, 'Hybrid WL+Mask'),
        (7, 'Hybrid Mask+WL'),
    ]
    project = models.ForeignKey(Project, on_delete=models.CASCADE, null=True,
                                blank=True, related_name='runs')
    hashes = models.ManyToManyField(Hash)
    # attack_mode 3 only: the mask feeding the exact coverage engine.
    mask = models.ForeignKey(Mask, on_delete=models.SET_NULL, null=True, blank=True,
                             related_name='runs')
    attack_mode = models.IntegerField(default=3, choices=ATTACK_MODES)
    # Non-mask components (straight/combinator/hybrid).
    wordlists = models.ManyToManyField(Wordlist, blank=True, related_name='runs')
    rules = models.ManyToManyField(RuleSet, blank=True, related_name='runs')
    # Mode-specific scalars: combinator {"order":[l,r],"left_rule","right_rule"};
    # hybrid {"mask","custom_charsets"}. (Pure mode-3 uses the mask FK, not params.)
    params = models.JSONField(default=dict, blank=True)
    # Canonical dedup key set on record (see services.similarity.signature).
    signature = models.CharField(max_length=512, blank=True, default='', db_index=True)
    hashtype = models.ForeignKey(HashType, on_delete=models.SET_NULL, null=True, blank=True)
    device = models.CharField(max_length=200, null=True, blank=True)
    command = models.CharField(max_length=4096, null=True, blank=True)
    status = models.CharField(max_length=16, choices=STATUS_CHOICES, default='planned')
    speed_hs = models.DecimalField(max_digits=80, decimal_places=0, null=True, blank=True)
    progress = models.FloatField(default=0.0)  # 0..1
    started_at = models.DateTimeField(null=True, blank=True)
    ended_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True, null=True)
    comment = models.CharField(max_length=1024, null=True, blank=True)

    class Meta:
        ordering = ['-created_at']

    @property
    def attack_mode_label(self):
        return dict(self.ATTACK_MODES).get(self.attack_mode, str(self.attack_mode))

    def describe(self):
        """Human-readable one-line summary of what this run searched."""
        m, p = self.attack_mode, (self.params or {})
        if m == 3:
            return self.mask.pattern if self.mask else '(no mask)'
        wls = list(self.wordlists.all())
        wl_names = [w.name for w in wls]
        rule_names = [r.name for r in self.rules.all()]
        if m == 0:
            s = ' + '.join(wl_names) or '(no wordlist)'
            if rule_names:
                s += '  | rules: ' + ', '.join(rule_names)
            return s
        if m == 1:
            by_id = {w.id: w.name for w in wls}
            pair = [by_id.get(i, '?') for i in (p.get('order') or [])] or wl_names
            s = ' × '.join(pair) if pair else '(combinator)'
            extra = []
            if p.get('left_rule'):
                extra.append('-j ' + p['left_rule'])
            if p.get('right_rule'):
                extra.append('-k ' + p['right_rule'])
            if extra:
                s += ' [' + ' '.join(extra) + ']'
            return s
        if m in (6, 7):
            wl = wl_names[0] if wl_names else '(no wordlist)'
            mask = p.get('mask', '(no mask)')
            return '%s + %s' % ((wl, mask) if m == 6 else (mask, wl))
        return '(attack %s)' % m

    def __str__(self):
        return '%s [%s]' % (self.describe(), self.status)


class Crack(models.Model):
    """A recovered plaintext for a hash (replaces the bare Hash.cracked bool,
    which is kept as a denormalised flag updated on import)."""
    hash = models.ForeignKey(Hash, on_delete=models.CASCADE, related_name='cracks')
    plaintext = models.CharField(max_length=1024)
    run = models.ForeignKey(Run, on_delete=models.SET_NULL, null=True, blank=True,
                            related_name='cracks')
    found_at = models.DateTimeField(auto_now_add=True, null=True)

    def __str__(self):
        return '%s = %s' % (self.hash, self.plaintext)


class Benchmark(models.Model):
    """Measured hashcat speed for a hashtype on a device (hashcat -b).

    Grounds run-time estimates now and the deferred recommender later
    (feasible keyspace = speed_hs * time_budget)."""
    hashtype = models.ForeignKey(HashType, on_delete=models.CASCADE, related_name='benchmarks')
    device = models.CharField(max_length=200)
    speed_hs = models.DecimalField(max_digits=80, decimal_places=0)
    measured_at = models.DateTimeField(auto_now_add=True, null=True)

    class Meta:
        ordering = ['-measured_at']

    def __str__(self):
        return '%s @ %s H/s (%s)' % (self.hashtype, self.speed_hs, self.device)
