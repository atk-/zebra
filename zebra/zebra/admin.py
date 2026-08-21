from django.contrib import admin
from .models import (Project, HashType, Hash, CharacterSet, Wildcard,
                     Mask, Run, Crack, Benchmark, Wordlist, RuleSet)


@admin.register(Mask)
class MaskAdmin(admin.ModelAdmin):
    list_display = ('pattern', 'project', 'length', 'keyspace')
    list_filter = ('project',)


@admin.register(Run)
class RunAdmin(admin.ModelAdmin):
    list_display = ('__str__', 'status', 'attack_mode', 'project', 'progress', 'created_at')
    list_filter = ('status', 'attack_mode', 'project')
    filter_horizontal = ('hashes', 'wordlists', 'rules')


@admin.register(Wordlist)
class WordlistAdmin(admin.ModelAdmin):
    list_display = ('name', 'path', 'line_count')
    search_fields = ('name', 'path')


@admin.register(RuleSet)
class RuleSetAdmin(admin.ModelAdmin):
    list_display = ('name', 'path', 'rule_count')
    search_fields = ('name', 'path')


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
