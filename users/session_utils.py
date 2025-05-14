from django.utils import timezone
from .models import UserSession

def get_client_ip(request):
    """
    Get the client IP address from the request
    """
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip

def create_user_session(user, request, token_jti):
    """
    Create a new user session record
    """
    # Get device info from user agent
    user_agent = request.META.get('HTTP_USER_AGENT', '')
    
    # Get client IP
    ip_address = get_client_ip(request)
    
    # Create session record
    session = UserSession.objects.create(
        user=user,
        session_id=token_jti,
        device_info=user_agent,
        ip_address=ip_address
    )
    
    return session

def invalidate_user_session(session_id):
    """
    Mark a user session as inactive
    """
    try:
        session = UserSession.objects.get(session_id=session_id)
        session.is_active = False
        session.save()
        return True
    except UserSession.DoesNotExist:
        return False

def invalidate_all_user_sessions(user):
    """
    Mark all of a user's sessions as inactive
    """
    UserSession.objects.filter(user=user, is_active=True).update(
        is_active=False
    )