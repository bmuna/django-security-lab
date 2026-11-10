from django import views
from django.contrib import admin
from django.urls import path
from users.views import CustomTokenObtainPairView, LogoutView, complete_mfa_login, get_csrf_token, my_profile, register, setup_mfa, user_login, user_logout, verify_mfa_setup
from rest_framework_simplejwt.views import (TokenObtainPairView,TokenRefreshView)

urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/token/', CustomTokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('api/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('api/register/', register),
    path('api/login/', user_login),
    path('api/mfa/setup/', setup_mfa, name='setup_mfa'),
    path('api/mfa/verify-setup/', verify_mfa_setup, name='verify_mfa_setup'),
    path('api/mfa/complete-login/',complete_mfa_login,name='complete-mfa-login'),
    path('api/me/', my_profile), 
    path('api/logout/', user_logout),
    path('api/csrf/', get_csrf_token),   
    path('api/token/logout/', LogoutView.as_view(), name='token_logout'),       
]
