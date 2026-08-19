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


class Run(models.Model):
    """One execution of an attack against a set of hashes.

    Only mask attacks (attack_mode 3) are modelled today, but the schema and
    the ``status`` state machine already carry the fields a future active
    launcher needs (running/progress/speed), so it can be added without rework.
    """
    STATUS_CHOICES = [
        ('planned', 'Planned'),
        ('running', 'Running'),
        ('exhausted', 'Exhausted'),
        ('aborted', 'Aborted'),
        ('cracked', 'Cracked'),
        ('error', 'Error'),
    ]
    hashes = models.ManyToManyField(Hash)
    mask = models.ForeignKey(Mask, on_delete=models.SET_NULL, null=True, blank=True,
                             related_name='runs')
    attack_mode = models.IntegerField(default=3)  # 3 = brute-force / mask
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

    def __str__(self):
        return '%s [%s]' % (self.mask.pattern if self.mask else '(no mask)', self.status)


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
