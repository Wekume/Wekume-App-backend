from google.oauth2 import id_token
from google.auth.transport import requests
from django.conf import settings
import time
import json
import base64
import logging

# Set up logging
logger = logging.getLogger(__name__)

def verify_google_token(token):
    """
    Verify the Google OAuth token and return user info
    """
    try:
        # Verify token with Google
        idinfo = id_token.verify_oauth2_token(
            token,
            requests.Request(),
            settings.GOOGLE_CLIENT_ID
        )
        
        # Check if the token is issued for our app
        if idinfo['aud'] != settings.GOOGLE_CLIENT_ID:
            logger.warning(f"Token audience mismatch: {idinfo['aud']} != {settings.GOOGLE_CLIENT_ID}")
            return None
            
        # Check if the token is expired
        if idinfo['exp'] < time.time():
            logger.warning(f"Token expired at {idinfo['exp']}, current time: {time.time()}")
            return None
            
        # Check if email is verified (security best practice)
        if not idinfo.get('email_verified', False):
            logger.warning(f"Email not verified for user: {idinfo.get('email')}")
            return None
            
        # Token is valid
        logger.info(f"Token successfully verified for user: {idinfo.get('email')}")
        
        # Return user info
        return {
            'email': idinfo['email'],
            'email_verified': idinfo['email_verified'],
            'name': idinfo.get('name', ''),
            'given_name': idinfo.get('given_name', ''),
            'family_name': idinfo.get('family_name', ''),
            'picture': idinfo.get('picture', ''),
            'locale': idinfo.get('locale', ''),
            'sub': idinfo['sub'],  # Google's unique user ID
        }
    except ValueError as e:
        # Invalid token
        logger.error(f"Token validation error: {str(e)}")
        return None
    except Exception as e:
        # Catch any other unexpected errors
        logger.error(f"Unexpected error during token verification: {str(e)}")
        return None