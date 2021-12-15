from django.urls import path, include
from . import views

urlpatterns = [
    path('accounts/logout', views.user_view, name='logout'),
    path('accounts/profile', views.user_view, name='profile'),
    path('api/user/', views.user, name='user'),
    path('api/login/', views.issue_token, name='login'),
    path('', include('frontend.urls'))
]