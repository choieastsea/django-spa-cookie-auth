import json

from django.contrib.auth import authenticate, login, logout
from django.http import JsonResponse
from django.middleware.csrf import get_token
from django.shortcuts import render
from django.views.decorators.csrf import ensure_csrf_cookie
from django.views.decorators.http import require_POST


def index_view(request):
    return render(request, "build/index.html")


def get_csrf(request):
    return JsonResponse({"csrf": get_token(request)})


@ensure_csrf_cookie
def check_session(request):
    if not request.user.is_authenticated:
        return JsonResponse({"loggedIn": False})

    return JsonResponse({"loggedIn": True})


@require_POST
def login_view(request):
    data = json.loads(request.body)
    username = data.get('username')
    password = data.get('password')

    if username is None or password is None:
        return JsonResponse({"detail": "Please provide both username & password."}, status=400)

    user = authenticate(username=username, password=password)

    if user is None:
        return JsonResponse({"detail": "Invalid credentials."}, status=400)

    login(request, user)
    return JsonResponse({"detail": "Successfully logged in."})


def logout_view(request):
    if not request.user.is_authenticated:
        return JsonResponse({"detail": "You're not logged in."}, status=400)

    logout(request)
    return JsonResponse({"detail": "Successfully logged out."})