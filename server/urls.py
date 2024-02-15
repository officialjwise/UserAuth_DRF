from django.urls import path
from .views import login_view, signup_view, update_user, custom_logout, test_token

urlpatterns = [
    path('login/', login_view, name='login'),
    path('signup/', signup_view, name='signup'),
    path('update_user/', update_user, name='update_user'),
    path('logout/', custom_logout, name='custom_logout'),
    path('test_token/', test_token, name='test_token'),
]
