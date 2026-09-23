from django.urls import path
from . import views

urlpatterns = [
    path("", views.index, name="index"),
    path("project/new/", views.project_new, name="project_new"),
    path("project/<int:pk>/", views.project_detail, name="project_detail"),
    path("project/<int:pk>/hashes/add/", views.hashes_add, name="hashes_add"),
    path("project/<int:pk>/mask/new/", views.mask_new, name="mask_new"),
    path("run/<int:pk>/", views.run_detail, name="run_detail"),
    path("run/<int:pk>/delete/", views.run_delete, name="run_delete"),
    path("run/<int:pk>/status.json", views.run_status_json, name="run_status"),
    path("run/<int:pk>/start/", views.run_start, name="run_start"),
    path("run/<int:pk>/stop/", views.run_stop, name="run_stop"),
    path("run/<int:pk>/enqueue/", views.run_enqueue, name="run_enqueue"),
    path("run/<int:pk>/dequeue/", views.run_dequeue, name="run_dequeue"),
    path("run/<int:pk>/move/", views.run_move, name="run_move"),
    path("queue/", views.queue, name="queue"),
    path("queue/pause/", views.queue_pause, name="queue_pause"),
    path("queue/resume/", views.queue_resume, name="queue_resume"),
    path("project/<int:pk>/import/", views.import_results, name="import_results"),
    path("project/<int:pk>/benchmark/", views.project_benchmark, name="project_benchmark"),
    path("project/<int:pk>/recommend.json", views.recommend_json, name="recommend"),
    path("project/<int:pk>/coverage/<int:length>.json", views.coverage_decomposition_json, name="coverage_decomposition"),
]
