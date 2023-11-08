from Authorization.views import *
from django.urls import path, re_path
from .views import LoginView

api_urls = [
    path('login/', LoginView.as_view(), name='login'),
    path('refresh/', RefreshView.as_view(), name='refresh'),
    

]

urlpatterns = api_urls