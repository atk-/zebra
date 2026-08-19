from django.contrib import admin
from .models import (Project, HashType, Hash, CharacterSet, Wildcard,
                     Mask, Run, Crack, Benchmark)


@admin.register(Mask)
class MaskAdmin(admin.ModelAdmin):
    list_display = ('pattern', 'project', 'length', 'keyspace')
    list_filter = ('project',)


@admin.register(Run)
class RunAdmin(admin.ModelAdmin):
    list_display = ('__str__', 'status', 'attack_mode', 'progress', 'created_at')
    list_filter = ('status',)


@admin.register(Crack)
class CrackAdmin(admin.ModelAdmin):
    list_display = ('hash', 'plaintext', 'run', 'found_at')


@admin.register(Benchmark)
class BenchmarkAdmin(admin.ModelAdmin):
    list_display = ('hashtype', 'device', 'speed_hs', 'measured_at')


admin.site.register(Hash)
admin.site.register(HashType)
admin.site.register(Project)
admin.site.register(Wildcard)
admin.site.register(CharacterSet)
