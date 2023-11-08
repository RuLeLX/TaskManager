from datetime import datetime, timedelta

from django.contrib.auth import get_user_model
from rest_framework import serializers
from django.utils.translation import gettext_lazy as _
import jwt

UserModel = get_user_model()
JWT_SECRET = 'my_secret'  #   секретное слово для подписи
JWT_ACCESS_TTL = 60 * 5   # время жизни access токена в секундах (5 мин)
JWT_REFRESH_TTL = 3600 * 24 * 7 # время жизни refresh токена в секундах (неделя)

class LoginSerializer(serializers.Serializer):
    # ==== INPUT ====
    email = serializers.EmailField(required=True, write_only=True)
    password = serializers.CharField(required=True, write_only=True)
    # ==== OUTPUT ====
    access = serializers.CharField(read_only=True)
    refresh = serializers.CharField(read_only=True)

    def validate(self, attrs):
        # standard validation
        validated_data = super().validate(attrs)

        # validate email and password
        email = validated_data['email']
        password = validated_data['password']
        error_msg = _('email or password are incorrect')
        try:
            user = UserModel.objects.get(email=email)
            if not user.check_password(password):
                raise serializers.ValidationError(error_msg)
            validated_data['user'] = user
        except UserModel.DoesNotExist:
            raise serializers.ValidationError(error_msg)

        return validated_data
    
    JWT_SECRET = 'my_secret'  #   секретное слово для подписи
    JWT_ACCESS_TTL = 60 * 5   # время жизни access токена в секундах (5 мин)
    JWT_REFRESH_TTL = 3600 * 24 * 7 # время жизни refresh токена в секундах (неделя)

    def create(self, validated_data):
        access_payload = {
            'iss': 'backend-api',
            'user_id': validated_data['user'].id,
            'exp': datetime.utcnow() + timedelta(seconds=JWT_ACCESS_TTL),
            'type': 'access'
        }
        access = jwt.encode(payload=access_payload, key=JWT_SECRET)

        refresh_payload = {
            'iss': 'backend-api',
            'user_id': validated_data['user'].id,
            'exp': datetime.utcnow() + timedelta(seconds=JWT_REFRESH_TTL),
            'type': 'refresh'
        }
        refresh = jwt.encode(payload=refresh_payload, key=JWT_SECRET)

        return {
            'access': access,
            'refresh': refresh
        }
    
class RefreshSerializer(serializers.Serializer):
    # ==== INPUT ====
    refresh_token = serializers.CharField(required=True, write_only=True)
    # ==== OUTPUT ====
    access = serializers.CharField(read_only=True)
    refresh = serializers.CharField(read_only=True)

    def validate(self, attrs):
        # standard validation
        validated_data = super().validate(attrs)

        # validate refresh
        refresh_token = validated_data['refresh_token']
        try:
            payload = jwt.decode(refresh_token, JWT_SECRET)
            if payload['type'] != 'refresh':
                error_msg = {'refresh_token': _('Token type is not refresh!')}
                raise serializers.ValidationError(error_msg)
            validated_data['payload'] = payload
        except jwt.ExpiredSignatureError:
            error_msg = {'refresh_token': _('Refresh token is expired!')}
            raise serializers.ValidationError(error_msg)
        except jwt.InvalidTokenError:
            error_msg = {'refresh_token': _('Refresh token is invalid!')}
            raise serializers.ValidationError(error_msg)

        return validated_data

    def create(self, validated_data):
        access_payload = {
            'iss': 'backend-api',
            'user_id': validated_data['payload']['user_id'],
            'exp': datetime.utcnow() + timedelta(seconds=JWT_ACCESS_TTL),
            'type': 'access'
        }
        access = jwt.encode(payload=access_payload, key=JWT_SECRET)

        refresh_payload = {
            'iss': 'backend-api',
            'user_id': validated_data['payload']['user_id'],
            'exp': datetime.utcnow() + timedelta(seconds=JWT_REFRESH_TTL),
            'type': 'refresh'
        }
        refresh = jwt.encode(payload=refresh_payload, key=JWT_SECRET)

        return {
            'access': access,
            'refresh': refresh
        }
