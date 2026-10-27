from django.shortcuts import redirect
from django.urls import reverse

class ForcePasswordChangeMiddleware:
    """
    Fuerza a cualquier usuario autenticado a cambiar su contraseña genérica
    y configurar 2FA TOTP antes de poder interactuar con Mithril SIEM.
    """
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if request.user.is_authenticated:
            exempt_paths = [
                reverse('core:first_run_setup'),
                reverse('core:logout'),
                '/static/',
                '/media/',
            ]
            path = request.path

            if not any(path.startswith(p) for p in exempt_paths):
                profile, _ = request.user.mithril_profile.__class__.objects.get_or_create(user=request.user)
                if profile.must_change_password or not profile.has_completed_2fa:
                    return redirect('core:first_run_setup')

        return self.get_response(request)
