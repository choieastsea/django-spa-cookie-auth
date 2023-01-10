import json

from django.contrib.auth import authenticate, login, logout
from django.http import JsonResponse
from django.middleware.csrf import get_token
from django.views.decorators.csrf import ensure_csrf_cookie, csrf_exempt
from django.views.decorators.http import require_POST

#prevent multiple login
from django.contrib.auth import user_logged_in
from django.dispatch.dispatcher import receiver
from .models import UserSession
from django.contrib.sessions.models import Session
from django.contrib.auth.decorators import login_required

def get_csrf(request):
    response = JsonResponse({'detail': 'CSRF cookie set'})
    response['X-CSRFToken'] = get_token(request)
    print(response['X-CSRFToken'])  #client와 동일함을 확인
    return response


@require_POST
def login_view(request):
    data = json.loads(request.body)
    username = data.get('username')
    password = data.get('password')

    if username is None or password is None:
        return JsonResponse({'detail': 'Please provide username and password.'}, status=400)

    user = authenticate(username=username, password=password)   #active user에 대하여 authentication 수행

    if user is None:
        return JsonResponse({'detail': 'Invalid credentials.'}, status=400)

    #session 처리
    # request.session.set_expiry(3000) #3000초로 설정 -> sessionkey 설정은 안해줌
    login(request, user)

    return JsonResponse({'detail': 'Successfully logged in.'})


def logout_view(request):
    if not request.user.is_authenticated:
        return JsonResponse({'detail': 'You\'re not logged in.'}, status=400)

    logout(request)
    return JsonResponse({'detail': 'Successfully logged out.'})


@ensure_csrf_cookie
def session_view(request):
    if not request.user.is_authenticated:
        return JsonResponse({'isAuthenticated': False})

    return JsonResponse({'isAuthenticated': True})


@ensure_csrf_cookie #이거 없어도 되는디... get이라서 그런듯?
def whoami_view(request):
    print('whoami')
    if not request.user.is_authenticated:
        return JsonResponse({'isAuthenticated': False})

    return JsonResponse({'username': request.user.username})

@require_POST
# @csrf_exempt    #이거하면 csrf token 검사 안하긴 하는데...
@login_required
def test(request):
    print('test')
    return JsonResponse({'info' : 'hello'})

@receiver(user_logged_in)
def remove_other_sessions(sender, user, request, **kwargs):
    print('login successful and let me remove other sessions!')
    # remove other sessions
    print(user) #username 출력됨
    session = Session.objects.filter(usersession__user=user)
    print(session)
    session.delete()
    
    # save current session
    request.session.save()

    # create a link from the user to the current session (for later removal)
    UserSession.objects.get_or_create(
        user=user,
        session_id=request.session.session_key
    )
