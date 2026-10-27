import io
import base64
import qrcode
from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout, update_session_auth_hash
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.utils import timezone
from .models import UserProfile, UserLoginLog

def get_client_ip(request):
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        return x_forwarded_for.split(',')[0].strip()
    return request.META.get('REMOTE_ADDR')

def login_view(request):
    if request.user.is_authenticated:
        return redirect('analytics:dashboard')

    if request.method == 'POST':
        username = request.POST.get('username', '').strip()
        password = request.POST.get('password', '')
        ip_addr = get_client_ip(request)
        user_agent = request.META.get('HTTP_USER_AGENT', '')

        user = authenticate(request, username=username, password=password)

        if user is not None:
            profile, _ = UserProfile.objects.get_or_create(user=user)

            # Si ya tiene 2FA configurado y no debe cambiar password obligatoriamente
            if profile.has_completed_2fa and not profile.must_change_password:
                request.session['pre_2fa_user_id'] = user.id
                return redirect('core:verify_2fa')

            # Si es el primer login (o debe cambiar contraseña), iniciamos sesión para llevarlo al wizard
            login(request, user)
            UserLoginLog.objects.create(
                user=user,
                username_attempted=username,
                ip_address=ip_addr,
                user_agent=user_agent,
                status='SUCCESS'
            )
            return redirect('core:first_run_setup')
        else:
            UserLoginLog.objects.create(
                user=None,
                username_attempted=username,
                ip_address=ip_addr,
                user_agent=user_agent,
                status='FAILED_CREDENTIALS'
            )
            messages.error(request, 'Credenciales de acceso inválidas.')

    return render(request, 'auth/login.html')


def verify_2fa_view(request):
    user_id = request.session.get('pre_2fa_user_id')
    if not user_id:
        return redirect('core:login')

    from django.contrib.auth.models import User
    try:
        user = User.objects.get(id=user_id)
        profile = user.mithril_profile
    except Exception:
        return redirect('core:login')

    if request.method == 'POST':
        token = request.POST.get('token', '').strip().replace(' ', '')
        ip_addr = get_client_ip(request)
        user_agent = request.META.get('HTTP_USER_AGENT', '')

        # Verificar si es un token TOTP válido o código de emergencia
        is_valid = profile.verify_totp(token)
        is_backup = False

        if not is_valid and profile.backup_codes and token.upper() in profile.backup_codes:
            is_valid = True
            is_backup = True
            profile.backup_codes.remove(token.upper())
            profile.save(update_fields=['backup_codes'])

        if is_valid:
            login(request, user)
            del request.session['pre_2fa_user_id']
            UserLoginLog.objects.create(
                user=user,
                username_attempted=user.username,
                ip_address=ip_addr,
                user_agent=user_agent,
                status='SUCCESS'
            )
            if is_backup:
                messages.warning(request, 'Has accedido usando un código de respaldo. Te quedan menos códigos.')
            return redirect('analytics:dashboard')
        else:
            UserLoginLog.objects.create(
                user=user,
                username_attempted=user.username,
                ip_address=ip_addr,
                user_agent=user_agent,
                status='FAILED_2FA'
            )
            messages.error(request, 'Código de autenticación 2FA incorrecto o expirado.')

    return render(request, 'auth/verify_2fa.html', {'target_user': user})


@login_required
def first_run_setup_view(request):
    profile, _ = UserProfile.objects.get_or_create(user=request.user)

    # Generar URI de TOTP si aún no existe
    totp_uri = profile.get_totp_uri()
    
    # Generar código QR en memoria en base64
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=6,
        border=2,
    )
    qr.add_data(totp_uri)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    
    buffered = io.BytesIO()
    img.save(buffered, format="PNG")
    qr_b64 = base64.b64encode(buffered.getvalue()).decode()

    if request.method == 'POST':
        new_password = request.POST.get('new_password', '')
        confirm_password = request.POST.get('confirm_password', '')
        token_2fa = request.POST.get('token_2fa', '').strip().replace(' ', '')

        if len(new_password) < 12:
            messages.error(request, 'La nueva contraseña debe tener al menos 12 caracteres.')
        elif new_password != confirm_password:
            messages.error(request, 'Las contraseñas ingresadas no coinciden.')
        elif not profile.verify_totp(token_2fa):
            messages.error(request, 'El código de Google Authenticator no es válido. Comprueba la hora de tu dispositivo.')
        else:
            # Guardar nueva contraseña
            request.user.set_password(new_password)
            request.user.save()
            update_session_auth_hash(request, request.user)

            # Generar códigos de respaldo y actualizar flags
            backup_codes = profile.generate_backup_codes(count=5)
            profile.must_change_password = False
            profile.has_completed_2fa = True
            profile.save()

            messages.success(request, '¡Seguridad de Mithril configurada exitosamente! Bienvenido al centro de operaciones.')
            return render(request, 'auth/setup_completed.html', {'backup_codes': backup_codes})

    context = {
        'profile': profile,
        'totp_secret': profile.totp_secret,
        'qr_code_b64': qr_b64,
    }
    return render(request, 'auth/setup_2fa.html', context)


def logout_view(request):
    logout(request)
    messages.info(request, 'Sesión cerrada de forma segura.')
    return redirect('core:login')
