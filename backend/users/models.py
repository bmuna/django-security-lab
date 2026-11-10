from django.db import models
from django.contrib.auth.models import User
from django.conf import settings


class RevokedAccessToken(models.Model):
    user = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name='revoked_access_tokens'
    )

    jti = models.CharField(max_length=255, unique=True)

    revoked_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.jti
    
class UserMFA(models.Model):
    user = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='mfa'
    )

    totp_secret = models.CharField(
        max_length=64
    )

    is_enabled = models.BooleanField(
        default=False
    )
    
    last_totp_counter = models.BigIntegerField(
        null=True,
        blank=True
    )

    created_at = models.DateTimeField(
        auto_now_add=True
    )

    updated_at = models.DateTimeField(
        auto_now=True
    )



    def __str__(self):
        return f"MFA for {self.user.username}"