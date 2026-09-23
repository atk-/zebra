from django.db import models


class Settings(models.Model):
    """Global, project-independent program settings — a single row (pk=1).

    A singleton so the whole app shares one row of knobs; ``load()`` fetches (and
    lazily creates) it. Today it only overrides the hashcat binary; future global
    options can hang off the same row without another model or migration churn.
    """
    # Absolute path (or a name resolvable on PATH) to the hashcat binary to use,
    # overriding any globally installed copy. Blank -> fall back to 'hashcat' on
    # PATH (services.hashcat.DEFAULT_BINARY). Resolved by hashcat.configured_binary.
    hashcat_binary = models.CharField(max_length=1024, blank=True, default='')

    class Meta:
        verbose_name = 'settings'
        verbose_name_plural = 'settings'

    def save(self, *args, **kwargs):
        self.pk = 1  # enforce the singleton: there is only ever one settings row
        super().save(*args, **kwargs)

    @classmethod
    def load(cls):
        """Return the singleton settings row, creating it on first access."""
        obj, _ = cls.objects.get_or_create(pk=1)
        return obj

    def __str__(self):
        return 'zebra settings'


class Project(models.Model):
    name = models.CharField(max_length=200, unique=True)
    description = models.CharField(max_length=8192, blank=True, null=True)
    # A project targets exactly one hash type (a hashcat run takes one -m module);
    # its hashes and attacks inherit this. Nullable only so the schema migration and
    # any hash-less legacy project don't break -- the create form requires it.
    hashtype = models.ForeignKey('HashType', on_delete=models.PROTECT, null=True,
                                 blank=True, related_name='projects')
    # Characters considered in-scope for this project when computing the
    # "remaining" search space (total per length = len(universe) ** length).
    # If blank, coverage totals fall back to the union of charsets actually used.
    universe = models.CharField(max_length=1000, blank=True, null=True)
    # Measured/estimated hashcat speed (H/s) for this project's hash type on the
    # current machine -- either entered by hand or filled from ``hashcat -m N -b``.
    # DecimalField (not BigIntegerField) because hash rates for fast modes overflow
    # 64 bits; the engine treats it as a plain int.
    benchmark_hs = models.DecimalField(max_digits=80, decimal_places=0,
                                       null=True, blank=True)
    # --- hash source (hybrid: DB-backed OR file-backed) ---------------------
    # When set, the project's hashes live in this external file and are NEVER
    # ingested as Hash rows -- hashcat reads the file directly (zero-copy). This
    # single nullable field is the mode discriminator: NULL => DB-backed (the
    # default; hashes are Hash rows, exactly as before). Lets a campaign of
    # millions of hashes skip duplicating gigabytes into SQLite.
    hashfile_path = models.CharField(max_length=4096, blank=True, null=True)
    # Cached line count of hashfile_path (the cracked-% denominator for a
    # file-backed project); computed once when the path is set. BigInteger, not
    # Decimal: a hash *count* never overflows 63 bits (unlike keyspaces).
    hash_count = models.BigIntegerField(null=True, blank=True)
    # Persistent per-project potfile for a file-backed project (hashcat
    # --potfile-path): the source of truth for recovered hashes, so no Crack rows
    # are created. NULL => resolve_potfile_path() derives a managed default.
    potfile_path = models.CharField(max_length=4096, blank=True, null=True)
    # True when zebra *saved* an upload into its managed dir (so it may replace
    # that file on refresh); False for a zero-copy server-side path we never touch.
    hashfile_managed = models.BooleanField(default=False)

    @property
    def is_file_backed(self):
        """True when this project's hashes live in an external file, not the DB."""
        return bool(self.hashfile_path)

    def has_hashes(self):
        """Whether the project has hashes to attack (launch guard).

        File-backed: the referenced file exists and is non-empty. DB-backed: any
        Hash rows exist."""
        if self.is_file_backed:
            import os
            return os.path.isfile(self.hashfile_path) and os.path.getsize(self.hashfile_path) > 0
        return self.hash_set.exists()

    def hash_count_value(self):
        """Total number of hashes (the coverage/cracked-% denominator).

        File-backed: the cached line count (recomputed if missing). DB-backed: a
        live row count (cheap)."""
        if self.is_file_backed:
            if self.hash_count is None:
                self.refresh_hash_count()
            return self.hash_count or 0
        return self.hash_set.count()

    def cracked_count(self):
        """How many hashes are cracked.

        File-backed: line count of the persistent potfile (hashcat's own record).
        DB-backed: the denormalized ``cracked`` flag."""
        if self.is_file_backed:
            from .services import hashfile
            return hashfile.potfile_cracked_count(self.resolve_potfile_path())
        return self.hash_set.filter(cracked=True).count()

    def resolve_potfile_path(self):
        """The persistent per-project potfile path (explicit, else managed default)."""
        if self.potfile_path:
            return self.potfile_path
        from django.conf import settings
        import os
        return os.path.join(settings.ZEBRA_DATA_DIR, 'potfiles', 'project-%s.pot' % self.pk)

    def refresh_hash_count(self):
        """Recount lines of the external hashfile and cache it on the project."""
        from .services import hashfile
        self.hash_count = hashfile.count_lines(self.hashfile_path)
        if self.pk:
            self.save(update_fields=['hash_count'])
        return self.hash_count

    def launch_hashfile(self, workdir):
        """Path to the hashfile hashcat should read for this project.

        File-backed: the external file itself (zero-copy). DB-backed: materialize
        the project's Hash rows to ``workdir/hashes.txt`` (one per line) and return
        that -- the caller's workdir cleanup disposes of it."""
        if self.is_file_backed:
            return self.hashfile_path
        import os
        path = os.path.join(workdir, 'hashes.txt')
        with open(path, 'w', encoding='utf-8') as f:
            for hs in self.hash_set.values_list('hashstring', flat=True):
                f.write('%s\n' % hs)
        return path

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
    # hashcat --increment: when increment_min is set, the mask is run at every length
    # from increment_min to increment_max (the mask truncated to k positions), so it
    # covers the union of its length-prefixes. Null means a plain single-length mask.
    increment_min = models.IntegerField(null=True, blank=True)
    increment_max = models.IntegerField(null=True, blank=True)
    keyspace = models.DecimalField(max_digits=80, decimal_places=0, null=True, blank=True)
    comment = models.CharField(max_length=1024, null=True, blank=True)

    class Meta:
        ordering = ['length', 'pattern']

    @property
    def is_incremental(self):
        return self.increment_min is not None

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
        ('queued', 'Queued'),
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
    device = models.CharField(max_length=200, null=True, blank=True)
    command = models.CharField(max_length=4096, null=True, blank=True)
    status = models.CharField(max_length=16, choices=STATUS_CHOICES, default='planned')
    speed_hs = models.DecimalField(max_digits=80, decimal_places=0, null=True, blank=True)
    progress = models.FloatField(default=0.0)  # 0..1 (of the current sub-run)
    # Live position within a --increment sweep: which of how many length sub-runs
    # hashcat is on. offset is hashcat's 1-based guess_base_offset (1..count, as in
    # its "Guess.Queue: X/Y"); both null for a non-incremental run.
    increment_offset = models.IntegerField(null=True, blank=True)
    increment_count = models.IntegerField(null=True, blank=True)
    # Ordering key while status == 'queued' (the machine-wide attack queue); null
    # when the run isn't queued. Lower position runs first.
    queue_position = models.IntegerField(null=True, blank=True)
    pid = models.IntegerField(null=True, blank=True)  # OS pid while running (launcher)
    started_at = models.DateTimeField(null=True, blank=True)
    ended_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True, null=True)
    comment = models.CharField(max_length=1024, null=True, blank=True)

    class Meta:
        ordering = ['-created_at']

    @property
    def attack_mode_label(self):
        return dict(self.ATTACK_MODES).get(self.attack_mode, str(self.attack_mode))

    def target_count(self):
        """How many hashes this run targeted, for display.

        The Run<->Hash M2M is snapshotted at record time for DB-backed projects,
        but left empty for file-backed ones (millions of join rows won't scale), so
        fall back to the project's hash count."""
        n = self.hashes.count()
        if n:
            return n
        return self.project.hash_count_value() if self.project else 0

    def describe(self):
        """Human-readable one-line summary of what this run searched."""
        m, p = self.attack_mode, (self.params or {})
        if m == 3:
            if not self.mask:
                return '(no mask)'
            if self.mask.is_incremental:
                return '%s (increment %d–%d)' % (
                    self.mask.pattern, self.mask.increment_min, self.mask.increment_max)
            return self.mask.pattern
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
