from rest_framework import serializers
from rest_framework.authtoken.models import Token
from .models import *


class IssueTokenRequestSerializer(serializers.Serializer):
    model = PassUser
    username = serializers.CharField(required=True)
    password = serializers.CharField(required=True)


class TokenSerializer(serializers.ModelSerializer):
    class Meta:
        model = Token
        fields = ('key')


class PassUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = PassUser
        fields = ("username", "email", "date_joined")

