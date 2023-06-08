from django.urls import path
from . import views

urlpatterns = [
    path('check-url/', views.check_product, name='check-url'),
    path('', views.my_view, name='my-view'),
]
