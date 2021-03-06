from django.urls import path

from . import views

urlpatterns = [
    path('', views.index),
    path('create_twitter/', views.create_twitter),
    path('webhooks/twitter/<int:account_id>/', views.twitter_webhook_url),
    path('message/', views.message),
    path('status/', views.status),
    path('events/', views.events),
]
