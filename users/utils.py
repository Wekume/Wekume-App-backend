import uuid
from datetime import timedelta
from django.utils import timezone
from django.core.mail import send_mail
from django.conf import settings
from django.template.loader import render_to_string
from django.utils.html import strip_tags
import random
from .africas_talking import send_verification_sms


def generate_verification_token(user):
    """
    Generate a verification token for the user and save it to the database.
    """
    token = uuid.uuid4().hex
    expires = timezone.now() + timedelta(hours=24)  # Token expires in 24 hours
    
    # Save token to user
    user.email_verification_token = token
    user.email_verification_token_expires = expires
    user.save(update_fields=['email_verification_token', 'email_verification_token_expires'])
    
    return token

def send_verification_email(user, request=None):
    """
    Send a verification email to the user.
    """
    if not user.email:
        return False
    
    # Generate token if not already present
    if not user.email_verification_token:
        token = generate_verification_token(user)
    else:
        token = user.email_verification_token
    
    # Use SITE_URL from settings
    from django.conf import settings
    site_url = settings.SITE_URL  # Get the actual value
    verification_url = f"{site_url}/api/verify-email/{token}/"
    print(f"DEBUG - Verification URL: {verification_url}")
    
    # Prepare email content
    subject = "Verify your email address for Wekume"
    html_message = render_to_string('email/verification_email.html', {
        'user': user,
        'verification_url': verification_url,
        'token': token,
        'expires_in': '24 hours'
    })
    plain_message = strip_tags(html_message)
    
    # Send email
    try:
        send_mail(
            subject,
            plain_message,
            settings.DEFAULT_FROM_EMAIL,
            [user.email],
            html_message=html_message,
            fail_silently=False,
        )
        print(f"Email sent successfully to {user.email}")
        return True
    except Exception as e:
        print(f"Error sending verification email: {e}")
        return False
    
    
def send_verification_sms_old(user):
    """
    Send a verification SMS to the user.
    This is a placeholder for future implementation.
    """
    if not user.phone:
        return False
    
    # Generate token if not already present
    if not user.phone_verification_token:
        token = uuid.uuid4().hex
        expires = timezone.now() + timedelta(hours=1)  # Token expires in 1 hour
        
        # Save token to user
        user.phone_verification_token = token
        user.phone_verification_token_expires = expires
        user.save(update_fields=['phone_verification_token', 'phone_verification_token_expires'])
    else:
        token = user.phone_verification_token
    
    # In a real app, you would integrate with an SMS service here
    # For now, we'll just print the token
    print(f"Verification SMS for {user}: {token}")
    
    return True


def generate_phone_verification_code(user):
    """
    Generate a 6-digit verification code for phone verification.
    """
    # Generate a 6-digit code
    code = str(random.randint(100000, 999999))
    expires = timezone.now() + timedelta(minutes=15)  # Code expires in 15 minutes
    
    # Save code to user
    user.phone_verification_token = code
    user.phone_verification_token_expires = expires
    user.save(update_fields=['phone_verification_token', 'phone_verification_token_expires'])
    
    return code

def send_phone_verification(user):
    """
    Send a verification SMS to the user.
    """
    if not user.phone:
        return False
    
    # Generate code if not already present
    if not user.phone_verification_token:
        code = generate_phone_verification_code(user)
    else:
        code = user.phone_verification_token
    
    # Send SMS
    return send_verification_sms(user.phone, code)
