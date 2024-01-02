from django.urls import path
from  taskapp.views import Registerview,reset,fpsd,log,userregister,Loginview,PasswordResetRequestView,PasswordResetConfirmView
urlpatterns=[
    path('register/', Registerview.as_view(),name="register"),
    path('Login/', Loginview.as_view(),name="Login"),
    path('resetlink/', PasswordResetRequestView.as_view(),name="resetlink"),
    path('pswddd', PasswordResetConfirmView.as_view(),name='pswddd'),
    path('userregister/',userregister,name="userregister"),
    path('log/',log,name="log"),
    path('fpsd/',fpsd,name="fpsd"),
    path('reset/',reset,name="reset"),
]