import uuid

from django.contrib.auth.models import User
from django.contrib.auth.password_validation import validate_password
from django.core import signing
from django.core.exceptions import ValidationError
from django.contrib.auth import authenticate, login, logout
from django.http import JsonResponse
import pyotp
from rest_framework.permissions import AllowAny, IsAuthenticated

from rest_framework.decorators import api_view, permission_classes, throttle_classes
from rest_framework.response import Response
from rest_framework import status
from django.views.decorators.csrf import ensure_csrf_cookie


from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.response import Response
from rest_framework import status
from django.db import transaction
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework_simplejwt.exceptions import TokenError

from .models import RevokedAccessToken, UserMFA
from rest_framework.throttling import AnonRateThrottle
from .throttles import LoginRateThrottle, GlobalLoginRateThrottle, get_account_risk_level, is_mfa_rate_limited, record_mfa_failure
from .throttles import record_failed_login,reset_failed_login,get_account_risk_level
from django_redis import get_redis_connection


class LoginRateThrottle(AnonRateThrottle):
    scope = 'login'

class CustomTokenObtainPairView(TokenObtainPairView):
    throttle_classes = [LoginRateThrottle,GlobalLoginRateThrottle]
    
    
CONSUME_MFA_CHALLENGE_SCRIPT = """
local stored_user_id = redis.call('GET', KEYS[1])

if not stored_user_id then
    return 0
end

if stored_user_id ~= ARGV[1] then
    return 0
end

redis.call('DEL', KEYS[1])

return 1
"""
    
    
@api_view(['POST'])
def register(request):
    username = request.data.get('username')
    email = request.data.get('email')
    password = request.data.get('password')

    if not username or not email or not password:
        return Response(
            {"error": "All fields are required"},
            status=status.HTTP_400_BAD_REQUEST
        )

    if User.objects.filter(username=username).exists():
        return Response(
            {"error": "Username already exists"},
            status=status.HTTP_400_BAD_REQUEST
        )

    try:
        validate_password(password)
    except ValidationError as error:
        return Response(
            {"error": error.messages},
            status=status.HTTP_400_BAD_REQUEST
        )

    user = User.objects.create_user(
        username=username,
        email=email,
        password=password
    )

    return Response(
        {"message": "User registered successfully"},
        status=status.HTTP_201_CREATED
    )
    
    
@api_view(['POST'])
@throttle_classes([LoginRateThrottle, GlobalLoginRateThrottle])
def user_login(request):
    username = request.data.get('username')
    password = request.data.get('password')

    if not username or not password:
        return Response(
            {"error": "Username and password are required"},
            status=status.HTTP_400_BAD_REQUEST
        )
    
    user = authenticate(
        request,
        username=username,
        password=password
    )

    if user is None:
        record_failed_login(username)
        return Response(
            {"error": "Invalid username or password"},
            status=status.HTTP_401_UNAUTHORIZED
        )
    
    risk_level = get_account_risk_level(username)

    if risk_level != "normal":
        challenge_token = create_mfa_challenge(user)

        return Response(
            {
                "message": "Additional verification required",
                "risk_level": risk_level,
                "requires_additional_verification": True,
                "challenge_token": challenge_token,
                "expires_in": 300
            },
            status=status.HTTP_200_OK
        )

    reset_failed_login(username)
    login(request, user)

    return Response({
        "message": "Login successful"
    })
    # reset_failed_login(username)

    # login(request, user)
    
    # return Response({
    #     "message": "Login successful"
    # })
    
    
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def my_profile(request):
    return Response({
        "username": request.user.username,
        "email": request.user.email,
    })
    
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def user_logout(request):
    logout(request)

    return Response({
        "message": "Logout successful"
    })
    
@ensure_csrf_cookie
def get_csrf_token(request):
    return JsonResponse({
        "message": "CSRF cookie set"
    })
    
    
def create_mfa_challenge(user):
    challenge_id = uuid.uuid4().hex

    redis_client = get_redis_connection('default')

    redis_key = f'security:mfa:challenge:{challenge_id}'

    redis_client.setex(
        redis_key,
        300,
        str(user.id)
    )

    return signing.dumps(
        {
            "user_id": user.id,
            "purpose": "mfa_login",
            "jti": challenge_id
        },
        salt="mfa-login-challenge"
    )


def validate_mfa_challenge(token):
    try:
        payload = signing.loads(
            token,
            salt="mfa-login-challenge",
            max_age=300
        )
    except signing.BadSignature:
        return None

    if payload.get("purpose") != "mfa_login":
        return None

    user_id = payload.get("user_id")
    challenge_id = payload.get("jti")

    if not user_id or not challenge_id:
        return None

    redis_client = get_redis_connection('default')

    redis_key = f'security:mfa:challenge:{challenge_id}'

    stored_user_id = redis_client.get(redis_key)

    if stored_user_id is None:
        return None

    if stored_user_id.decode('utf-8') != str(user_id):
        return None

    return payload


def consume_mfa_challenge(payload):
    redis_client = get_redis_connection('default')

    redis_key = (
        f'security:mfa:challenge:{payload["jti"]}'
    )

    result = redis_client.eval(
        CONSUME_MFA_CHALLENGE_SCRIPT,
        1,
        redis_key,
        str(payload["user_id"])
    )

    return result == 1

@api_view(['POST'])
@permission_classes([AllowAny])
def complete_mfa_login(request):
    challenge_token = request.data.get('challenge_token')
    code = request.data.get('code')

    # 1. Check required fields
    if not challenge_token or not code:
        return Response(
            {"error": "Challenge token and verification code are required"},
            status=status.HTTP_400_BAD_REQUEST
        )

    # 2. Validate the temporary challenge
    payload = validate_mfa_challenge(challenge_token)

    if payload is None:
        return Response(
            {"error": "Invalid or expired challenge"},
            status=status.HTTP_401_UNAUTHORIZED
        )
        
    ip_address = request.META.get('REMOTE_ADDR', '')

    if is_mfa_rate_limited(
        payload['user_id'],
        payload['jti'],
        ip_address
    ):
        print("CUSTOM MFA RATE LIMIT TRIGGERED")
        return Response(
            {
                "error": "Too many MFA verification attempts. Try again later."
            },
            status=status.HTTP_429_TOO_MANY_REQUESTS
        )

    # 3. Validate the TOTP format
    if not isinstance(code, str) or len(code) != 6 or not code.isdigit():
        return Response(
            {"error": "Invalid verification code"},
            status=status.HTTP_400_BAD_REQUEST
        )

    # 4. Find the user
    try:
        user = User.objects.get(id=payload['user_id'])
    except User.DoesNotExist:
        return Response(
            {"error": "Invalid authentication challenge"},
            status=status.HTTP_401_UNAUTHORIZED
        )

    # 5. Confirm MFA is enabled
    try:
        mfa = UserMFA.objects.get(user=user, is_enabled=True)
    except UserMFA.DoesNotExist:
        return Response(
            {"error": "MFA is not enabled for this account"},
            status=status.HTTP_403_FORBIDDEN
        )

    # 6. Verify the authenticator code
    totp = pyotp.TOTP(mfa.totp_secret)

    if not totp.verify(code, valid_window=1):
        
        record_mfa_failure(
            user.id,
            payload['jti'],
            ip_address
        )

        return Response(
            {"error": "Invalid verification code"},
            status=status.HTTP_401_UNAUTHORIZED
        )

    # 7. Consume the challenge (must succeed only once)
    if not consume_mfa_challenge(payload):
        return Response(
            {"error": "Challenge has already been used or expired"},
            status=status.HTTP_401_UNAUTHORIZED
        )

    # 8. Complete authentication
    reset_failed_login(user.username)
    login(request, user)

    return Response({
        "message": "Login successful",
        "mfa_verified": True
    })
    
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def setup_mfa(request):
    user = request.user

    secret = pyotp.random_base32()

    mfa, created = UserMFA.objects.get_or_create(
        user=user,
        defaults={
            'totp_secret': secret,
            'is_enabled': False
        }
    )

    if not created:
        if mfa.is_enabled:
            return Response(
                {"error": "MFA is already enabled"},
                status=status.HTTP_400_BAD_REQUEST
            )

        mfa.totp_secret = secret
        mfa.save()

    totp = pyotp.TOTP(secret)

    provisioning_uri = totp.provisioning_uri(
        name=user.email or user.username,
        issuer_name="Security Lab"
    )

    return Response({
        "secret": secret,
        "provisioning_uri": provisioning_uri
    })

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def verify_mfa_setup(request):
    code = request.data.get('code')

    if not code:
        return Response(
            {"error": "Verification code is required"},
            status=status.HTTP_400_BAD_REQUEST
        )

    try:
        mfa = UserMFA.objects.get(user=request.user)
    except UserMFA.DoesNotExist:
        return Response(
            {"error": "MFA setup has not been started"},
            status=status.HTTP_400_BAD_REQUEST
        )

    if mfa.is_enabled:
        return Response(
            {"error": "MFA is already enabled"},
            status=status.HTTP_400_BAD_REQUEST
        )

    totp = pyotp.TOTP(mfa.totp_secret)

    if not totp.verify(code, valid_window=1):
        return Response(
            {"error": "Invalid verification code"},
            status=status.HTTP_400_BAD_REQUEST
        )

    mfa.is_enabled = True
    mfa.save(update_fields=['is_enabled', 'updated_at'])

    return Response({
        "message": "MFA enabled successfully"
    })
    
    
class LogoutView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        refresh_token = request.data.get('refresh')

        if not refresh_token:
            return Response(
                {'error': 'Refresh token is required'},
                status=status.HTTP_400_BAD_REQUEST
            )                   

        try:
            refresh = RefreshToken(refresh_token)

            # Make sure this refresh token belongs to the logged-in user
            if str(refresh.get('user_id')) != str(request.user.pk):
                return Response(
                    {'error': 'Refresh token does not belong to this user'},
                    status=status.HTTP_403_FORBIDDEN
                )

            # Get the unique ID of the current access token
            access_token_jti = request.auth.get('jti')

            with transaction.atomic():
                # Revoke the access token
                RevokedAccessToken.objects.get_or_create(
                    jti=access_token_jti,
                    defaults={'user': request.user}
                )

                # Blacklist the refresh token
                refresh.blacklist()

            return Response(
                {'message': 'Successfully logged out'},
                status=status.HTTP_205_RESET_CONTENT
            )

        except TokenError:
            return Response(
                {'error': 'Invalid or expired refresh token'},
                status=status.HTTP_400_BAD_REQUEST
            )