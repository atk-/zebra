from django.apps import AppConfig


class ZebraConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'zebra'
    # Recovery of runs orphaned by a restart happens lazily (adopt_live_orphans on
    # the dashboard/queue/run-detail views + reconcile on the launch/queue paths),
    # not in ready() -- querying the DB during app init is discouraged by Django.


