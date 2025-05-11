import africastalking
from django.conf import settings
import logging

logger = logging.getLogger(__name__)

class SMSService:
    def __init__(self):
        """Initialize the Africa's Talking SDK with credentials from settings."""
        try:
            # Initialize the SDK
            africastalking.initialize(
                settings.AFRICAS_TALKING_USERNAME,
                settings.AFRICAS_TALKING_API_KEY
            )
            self.sms = africastalking.SMS
            self.initialized = True
            logger.info("Africa's Talking SMS service initialized")
        except Exception as e:
            logger.error(f"Failed to initialize Africa's Talking: {str(e)}")
            self.initialized = False
    
    def send_verification(self, phone_number, code):
        """
        Send a verification SMS with the provided code.
        
        Args:
            phone_number (str): The recipient's phone number in international format (e.g., +254XXXXXXXXX)
            code (str): The verification code to send
            
        Returns:
            bool: True if the message was sent successfully, False otherwise
        """
        if not self.initialized:
            logger.error("SMS service not properly initialized")
            return False
            
        # Format the message
        message = f"Your Wekume verification code is: {code}. Valid for 15 minutes."
        
        # Make sure phone number is in international format
        if not phone_number.startswith('+'):
            phone_number = '+' + phone_number
            
        try:
            # Send the message
            response = self.sms.send(
                message=message,
                recipients=[phone_number],
                sender_id=settings.AFRICAS_TALKING_SENDER_ID
            )
            
            logger.info(f"SMS API Response: {response}")
            
            # Check if the message was sent successfully
            if response and 'SMSMessageData' in response and 'Recipients' in response['SMSMessageData']:
                recipients = response['SMSMessageData']['Recipients']
                if recipients and len(recipients) > 0:
                    status = recipients[0]['status']
                    if status == 'Success':
                        logger.info(f"SMS sent successfully to {phone_number}")
                        return True
                    else:
                        logger.error(f"Failed to send SMS to {phone_number}: {status}")
                        return False
            
            logger.error(f"Unexpected response format from Africa's Talking: {response}")
            return False
        except Exception as e:
            logger.error(f"Error sending SMS to {phone_number}: {str(e)}")
            return False

# Create a singleton instance
sms_service = SMSService()

def send_verification_sms(phone_number, code):
    """
    Wrapper function to send verification SMS.
    
    Args:
        phone_number (str): The recipient's phone number
        code (str): The verification code
        
    Returns:
        bool: True if sent successfully, False otherwise
    """
    if not getattr(settings, 'SMS_VERIFICATION_ENABLED', False):
        # If SMS verification is disabled, log the message and return success
        logger.info(f"SMS verification disabled. Would have sent to {phone_number}: Code {code}")
        return True
        
    return sms_service.send_verification(phone_number, code)