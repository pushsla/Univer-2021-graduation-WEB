from django.contrib import admin
from django.contrib.auth.admin import UserAdmin

from .forms import PassUserCreationForm, PassUserChangeForm
from .models import PassUser


class PassUserAdmin(UserAdmin):
    add_form = PassUserCreationForm
    form = PassUserChangeForm
    model = PassUser
    list_display = ['email', 'username']


admin.site.register(PassUser, PassUserAdmin)
