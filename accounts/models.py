import secrets
import hashlib
from django.db import models
from django.utils import timezone

class Session(models.Model):
    user = models.ForeignKey("User", on_delete=models.CASCADE)
    token_hash = models.CharField(max_length=64, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()

    def is_valid(self):
        return self.expires_at > timezone.now()

    @staticmethod
    def generate_token():
        raw_token = secrets.token_urlsafe(32)
        token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
        return raw_token, token_hash

    def __str__(self):
        return f"Session for {self.user.email}"
