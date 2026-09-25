"""Custom model fields for zebra.

``ExactBigIntegerField`` stores a non-negative arbitrary-precision integer without
loss. It exists because Django's ``DecimalField`` is stored as SQLite ``REAL``
(a C double), which silently rounds integers past ~15 significant digits -- fatal
for hashcat keyspaces and hash rates that reach 80 digits (e.g. ``95**24``). Storing
the value as ``TEXT`` and handing Python a plain ``int`` makes the exact value
round-trip. All arithmetic on these values happens in Python (the coverage engine
already works in ``int``); no DB-side numeric ordering/aggregation is done on these
columns, so text storage is transparent to callers.
"""

from decimal import Decimal, InvalidOperation

from django import forms
from django.core.exceptions import ValidationError
from django.db import models


class ExactBigIntegerField(models.Field):
    """An exact (lossless) integer, stored as text, surfaced to Python as ``int``."""

    description = 'Exact arbitrary-precision integer (text-backed)'

    def get_internal_type(self):
        # Mapped to the backend's TEXT column type -- exact, unlike REAL/DECIMAL.
        return 'TextField'

    def from_db_value(self, value, expression, connection):
        return self.to_python(value)

    def to_python(self, value):
        if value is None or value == '':
            return None
        if isinstance(value, int):
            return value
        try:
            return int(value)  # str (from the DB) or Decimal (from app code)
        except (TypeError, ValueError):
            pass
        # Legacy rows migrated from the old REAL/DecimalField column can arrive as a
        # float or scientific-notation text (e.g. '5.4e+23'); accept them (already
        # rounded -- lossless from here on) rather than failing to load.
        try:
            return int(Decimal(value))
        except (InvalidOperation, TypeError, ValueError):
            raise ValidationError('%r is not an integer' % (value,),
                                  code='invalid')

    def get_prep_value(self, value):
        value = self.to_python(value)
        return None if value is None else str(value)

    def formfield(self, **kwargs):
        defaults = {'form_class': forms.IntegerField}
        defaults.update(kwargs)
        return super().formfield(**defaults)
