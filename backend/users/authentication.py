from urllib import request

from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.exceptions import AuthenticationFailed
from users.models import RevokedAccessToken

class CustomJWTAuthentication(JWTAuthentication):

    def authenticate(self, request):
        print("AUTH HEADER RECEIVED:", bool(
            request.META.get('HTTP_AUTHORIZATION')
        ))

        result = super().authenticate(request)

        print("JWT AUTHENTICATION RESULT:", result is not None)

        if result is None:
            return None

        user, validated_token = result

        jti = validated_token.get('jti')

        print("TOKEN JTI:", jti)

        if RevokedAccessToken.objects.filter(jti=jti).exists():
            print("TOKEN FOUND IN REVOKED TABLE")
            raise AuthenticationFailed('Access token has been revoked.')

        return user, validated_token