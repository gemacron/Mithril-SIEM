import secrets
import pyotp
from django.db import models
from django.contrib.auth.models import User

class UserProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='mithril_profile')
    must_change_password = models.BooleanField(default=True, help_text="Exige cambio de contraseña en primer login")
    has_completed_2fa = models.BooleanField(default=False, help_text="Indica si configuró 2FA TOTP")
    totp_secret = models.CharField(max_length=64, blank=True, null=True)
    backup_codes = models.JSONField(default=list, blank=True, help_text="Códigos de emergencia de un solo uso")
    failed_login_attempts = models.IntegerField(default=0)
    locked_until = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def generate_totp_secret(self):
        if not self.totp_secret:
            self.totp_secret = pyotp.random_base32()
            self.save(update_fields=['totp_secret'])
        return self.totp_secret

    def get_totp_uri(self):
        secret = self.generate_totp_secret()
        return pyotp.totp.TOTP(secret).provisioning_uri(
            name=self.user.username,
            issuer_name="Mithril SIEM"
        )

    def verify_totp(self, token):
        if not self.totp_secret:
            return False
        totp = pyotp.TOTP(self.totp_secret)
        return totp.verify(token, valid_window=1)

    def generate_backup_codes(self, count=5):
        codes = [secrets.token_hex(4).upper() for _ in range(count)]
        self.backup_codes = codes
        self.save(update_fields=['backup_codes'])
        return codes

    def __str__(self):
        return f"Mithril Profile: {self.user.username}"


class UserLoginLog(models.Model):
    STATUS_CHOICES = [
        ('SUCCESS', 'Autenticado Correctamente'),
        ('FAILED_CREDENTIALS', 'Credenciales Inválidas'),
        ('FAILED_2FA', 'Fallo en 2FA TOTP'),
        ('LOCKED', 'Cuenta Bloqueada Temporalmente'),
    ]

    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    username_attempted = models.CharField(max_length=150)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(blank=True, default='')
    status = models.CharField(max_length=32, choices=STATUS_CHOICES)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.created_at} | {self.username_attempted} | {self.status}"
