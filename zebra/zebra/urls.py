from django.urls import path
from . import views

urlpatterns = [
    path("", views.index, name="index"),
    path("project/new/", views.project_new, name="project_new"),
    path("project/<int:pk>/", views.project_detail, name="project_detail"),
    path("project/<int:pk>/hashes/add/", views.hashes_add, name="hashes_add"),
    path("project/<int:pk>/mask/new/", views.mask_new, name="mask_new"),
    path("project/<int:pk>/import/", views.import_results, name="import_results"),
]
