from django.http import *
from django.shortcuts import render, resolve_url
from rest_framework.authentication import TokenAuthentication
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.decorators import api_view, authentication_classes, permission_classes
from rest_framework.response import Response
from rest_framework.request import Request
from .serializers import PassUserSerializer, IssueTokenRequestSerializer, TokenSerializer
from rest_framework.authtoken.models import Token
from django.contrib.auth import authenticate

from .lib.crypto import *

from .forms import *
from django.urls import reverse_lazy
from django.views.generic.edit import CreateView


from .models import *
# Create your views here.


@api_view(['POST'])
@permission_classes([AllowAny])
def issue_token(request: Request):
    serializer = IssueTokenRequestSerializer(data=request.data)
    if serializer.is_valid():
        authenticated_user = authenticate(**serializer.validated_data)
        try:
            token = Token.objects.get(user=authenticated_user)
        except Token.DoesNotExist:
            token = Token.objects.create(user=authenticated_user)
        return Response(TokenSerializer(token).data)
    else:
        return Response(serializer.errors, status=400)


@api_view()
@authentication_classes([TokenAuthentication])
@permission_classes([IsAuthenticated])
def user(request: Request):
    if request.user.is_authenticated:
        response = Response({
        'status': 'ok',
        'data': PassUserSerializer(request.user).data
    })
    else:
        response = Response({
            'status': 'err',
            'err': 'need_login'
        })
    return response



@api_view(['POST'])
def create_password_view(request):
    if request.method == "POST":
        form = PasswordCreationForm(request.POST)
        if form.is_valid():
            wallet_id = int(request.POST['wallet_id'])
            wallet_pwd = hasher(form.cleaned_data.get('wallet_pwd'))
            pass_name = form.cleaned_data.get('name').encode()
            pass_url = form.cleaned_data.get('url').encode()
            pass_pass = form.cleaned_data.get('password').encode()

            dpass = DecryptedPassword(id=-1, wallet_id=wallet_id, name=pass_name, url=pass_url, passw=pass_pass)
            wallet = Wallet.objects.filter(id=wallet_id)[0]
            wallet.add_password(wallet_pwd, dpass)
            return Response({
                'status': 'ok',
            })

    return Response({
        'status': 'err',
    })


@api_view(['POST'])
def wallet_view(request):
    if request.method == "POST":
        if 'wallet' in request.POST and 'wallet_pwd' in request.POST:
            template_name = "passwords/wallet.html"
            wallet_id = int(request.POST['wallet'])
            wallet_pwd = hasher(request.POST['wallet_pwd'])
            wallet = Wallet.objects.filter(id=wallet_id)[0]
            if wallet.is_password_valid(wallet_pwd):
                passwords = wallet.get_passwords(wallet_pwd)
                context = {
                    'passwords': passwords,
                    'wallet_id': wallet.id,
                    'create_password_form': PasswordCreationForm()
                }
                return render(request, template_name, context)

    return HttpResponseForbidden('Wrong Password')


@api_view(['POST'])
def create_wallet_view(request):
    template_name = "passwords/new_wallet.html"
    if request.method == 'POST':
        form = WalletCreationForm(request.POST)
        if form.is_valid():
            usr = request.user
            passwd = form.cleaned_data.get('master_pwd')

            if usr.is_password_valid(passwd):
                name = form.cleaned_data.get('name')
                wallet = DecryptedWallet(id=0, user_id=usr.id, name=name.encode())
                usr.add_wallet(passwd, wallet, form.cleaned_data.get('wallet_pwd'))
                return HttpResponseRedirect(resolve_url('user-view'))
            else:
                form = WalletCreationForm()
    else:
        form = WalletCreationForm()

    context = {
        'form': form,
    }

    return render(request, template_name, context)


@api_view(['POST'])
def user_view(request):
    if request.method == 'POST':
        unlock_form = UnlockForm(request.POST)
        if unlock_form.is_valid():
            template_name = "passwords/home.html"
            passbytes = hasher(unlock_form.cleaned_data['pwd'])

            if request.user.is_password_valid(passbytes):
                wallets = request.user.get_wallets(passbytes)
                wselect = WalletSelectionForm(wallets)
                context = {
                    'wallets': wallets,
                    'wallet_selection_form': wselect
                }
                return render(request, template_name, context)
            else:
                unlock_form = UnlockForm()
                template_name = "passwords/unlock.html"
                context = {
                    'form': unlock_form,
                    'redirect': resolve_url('user-view')
                }
                return Response({
                    'status': 'ok',
                    'context': context
                })
    else:
        unlock_form = UnlockForm()
        template_name = "passwords/unlock.html"
        context = {
            'form': unlock_form,
            'redirect': resolve_url('user-view')
        }
        return Response({
            'status': 'err',
            'err_code': 'need_unlock'
        })


class SignUpView(CreateView):
    form_class = PassUserCreationForm
    success_url = reverse_lazy('login')
    template_name = 'registration/signup.html'
