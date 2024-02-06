from django.urls import path
from .views import UserRegisterAPI, UserLoginAPI, UserProfileAPI, UserChangePassAPI,SendPasswordResetEmailAPI,UserPasswordResetAPI,UserLogoutAPI

urlpatterns = [
    path('register/', UserRegisterAPI.as_view(), name='register'),
    path('login/', UserLoginAPI.as_view(), name='login'),
    path('profile/', UserProfileAPI.as_view(), name='profile'),
    path('logout/', UserLogoutAPI.as_view(), name='logout'),
    path('changepass/', UserChangePassAPI.as_view(), name='changepass'),
    path('send-email-pass/', SendPasswordResetEmailAPI.as_view(),name='send_email'),
    path('rest-password/<uid>/<token>/',UserPasswordResetAPI.as_view(),name='rest_password'),
]
