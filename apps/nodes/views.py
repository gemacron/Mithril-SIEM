import json
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.contrib import messages
from .models import ProxyNode

@login_required
def nodes_list_view(request):
    nodes = ProxyNode.objects.all()
    # Actualizar estados de salud
    for n in nodes:
        n.check_health()
    return render(request, 'nodes/list.html', {'nodes': nodes})

@login_required
def node_create_view(request):
    if request.method == 'POST':
        name = request.POST.get('name', '').strip()
        ip_address = request.POST.get('ip_address', '').strip()
        location_label = request.POST.get('location_label', '').strip()
        description = request.POST.get('description', '').strip()

        if not name or not ip_address:
            messages.error(request, 'El nombre y la IP del proxy son campos obligatorios.')
        else:
            node = ProxyNode.objects.create(
                name=name,
                ip_address=ip_address,
                location_label=location_label,
                description=description
            )
            messages.success(request, f"Servidor proxy '{node.name}' dado de alta exitosamente. Copia su token de conexión.")
            return redirect('nodes:list')

    return render(request, 'nodes/create.html')

@login_required
def node_delete_view(request, node_id):
    node = get_object_or_404(ProxyNode, id=node_id)
    if request.method == 'POST':
        name = node.name
        node.delete()
        messages.success(request, f"Nodo proxy '{name}' revocado y eliminado.")
        return redirect('nodes:list')
    return render(request, 'nodes/delete_confirm.html', {'node': node})

@csrf_exempt
def api_heartbeat(request):
    """
    Endpoint invocado periódicamente por el agente Mithril Bouncer en cada proxy Nginx
    """
    if request.method != 'POST':
        return JsonResponse({'error': 'POST required'}, status=405)

    auth_header = request.META.get('HTTP_AUTHORIZATION', '')
    if not auth_header.startswith('Bearer '):
        return JsonResponse({'error': 'Unauthorized'}, status=401)

    api_key = auth_header.split(' ')[1].strip()
    try:
        node = ProxyNode.objects.get(api_key=api_key)
    except ProxyNode.DoesNotExist:
        return JsonResponse({'error': 'Invalid node API key'}, status=403)

    try:
        data = json.loads(request.body.decode('utf-8'))
        rps = int(data.get('rps', 0))
    except Exception:
        rps = 0

    node.update_heartbeat(rps=rps)
    return JsonResponse({
        'status': 'ok',
        'node': node.name,
        'state': node.status
    })
