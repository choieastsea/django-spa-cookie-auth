# https://stackoverflow.com/questions/50833980/how-to-prevent-multiple-login-in-django
from django.conf import settings
from django.db import models
from django.contrib.sessions.models import Session


class UserSession(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, editable=False)
    session = models.OneToOneField(Session, on_delete=models.CASCADE)
