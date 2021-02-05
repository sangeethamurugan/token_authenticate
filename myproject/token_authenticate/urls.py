from django.urls import path
from .views import CreateAPI, authenticate_user, Update, get_token

urlpatterns = [
    path('create/', CreateAPI.as_view()),
    path('obtain_token/', authenticate_user),
    path('update/', Update.as_view()),
    path('get_token/', get_token)
]
