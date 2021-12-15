from typing import List

from django import forms
from django.contrib.auth.forms import UserCreationForm, UserChangeForm
from .models import *

from .lib.crypto import cryptor


class PasswordCreationForm(forms.Form):
    name = forms.CharField(label="Password name", max_length=100)
    url = forms.CharField(label="URL", max_length=100)
    password = forms.CharField(label="Password", max_length=100)
    wallet_pwd = forms.CharField(label="Wallet Password", widget=forms.PasswordInput)



class WalletCreationForm(forms.Form):
    name = forms.CharField(label="Wallet name: ", max_length=100)
    wallet_pwd = forms.CharField(label="Master Password", widget=forms.PasswordInput)
    master_pwd = forms.CharField(label="Master Password", widget=forms.PasswordInput)


class WalletSelectionForm(forms.Form):
    wallet = forms.ChoiceField()
    wallet_pwd = forms.CharField(label="Wallet Password: ", widget=forms.PasswordInput)

    def __init__(self, wallets: List[DecryptedWallet], *args, **kwargs):
        super().__init__(*args, **kwargs)
        wallet_map = ((w.id, w.name.decode()) for w in wallets)
        self.fields['wallet'] = forms.ChoiceField(choices=wallet_map)


class UnlockForm(forms.Form):
    pwd = forms.CharField(label="enter password: ", widget=forms.PasswordInput)


class PassUserCreationForm(UserCreationForm):

    pwd = forms.CharField(label="Master password:", widget=forms.PasswordInput)

    class Meta:
        model = PassUser
        fields = ('username', 'email')

    def save(self, commit=True):
        user = super().save(commit=commit)
        encryptor = cryptor(self.cleaned_data.get('pwd'))
        user.code_word = encryptor.encrypt(user.id.to_bytes(BYTE_LEN, BYTE_ORGER))
        if commit:
            user.save()

        return user


class PassUserChangeForm(UserChangeForm):
    class Meta:
        model = PassUser
        fields = ('username', 'email')
