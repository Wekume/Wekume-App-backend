import uuid
from datetime import timedelta
from django.utils import timezone
from django.contrib.auth import get_user_model
from rest_framework import status, permissions, viewsets
from rest_framework.decorators import action
from django.utils.crypto import get_random_string
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken
from .models import UserProfile
from .google_auth import verify_google_token
from django.conf import settings
from rest_framework.throttling import UserRateThrottle, AnonRateThrottle
import logging

# Add logger
logger = logging.getLogger(__name__)

from .serializers import (
    RegisterSerializer, 
    LoginSerializer, 
    UserSerializer,
    GoogleAuthSerializer,
    UserProfileSerializer,
    UserProfileUpdateSerializer,
    UserUpdateSerializer,
    PasswordResetRequestSerializer,
    PasswordResetConfirmSerializer,
    PhoneVerificationSerializer,
    EmailVerificationSerializer
)

from .utils import (
    generate_verification_token, 
    send_verification_email,
    generate_phone_verification_code,
    send_phone_verification
)

User = get_user_model()

# Define the throttle class BEFORE it's used
class EmailResendThrottle(AnonRateThrottle):
    rate = '3/hour'  # Allow 3 resend requests per hour


class PhoneVerificationThrottle(AnonRateThrottle):
    rate = '3/hour'  # Allow 3 SMS requests per hour


class RegisterViewSet(viewsets.ViewSet):
    """
    ViewSet for user registration
    """
    permission_classes = [permissions.AllowAny]
    serializer_class = RegisterSerializer  # This helps the browsable API
    
    def list(self, request):
        """
        GET method - provides information about the registration endpoint
        """
        return Response({
            "message": "Use POST to register a new user",
            "required_fields": {
                "email": "email@example.com (optional if phone provided)",
                "phone": "1234567890 (optional if email provided)",
                "first_name": "First Name",
                "middle_name": "Middle Name (optional)",
                "last_name": "Last Name",
                "gender": "Male/Female/Other",
                "age": "Age in years",
                "school": "University name",
                "password": "Secure password",
                "password2": "Confirm password"
            }
        })
    
    def create(self, request):
        #POST method - registers a new user
    
        serializer = RegisterSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            
            # Variables to track verification status
            email_verification_sent = False
            phone_verification_sent = False
            
            # Send verification email if email is provided
            if user.email:
                # Generate verification token and send email
                token = generate_verification_token(user)
                email_verification_sent = send_verification_email(user, request)
            
            # Send phone verification if phone is provided and SMS verification is enabled
            if user.phone and getattr(settings, 'SMS_VERIFICATION_ENABLED', False):
                # Set phone verification required
                user.phone_verification_required = True
                user.save()
                
                # Generate verification code and send SMS
                code = generate_phone_verification_code(user)
                phone_verification_sent = send_phone_verification(user)
            
            # Generate tokens
            refresh = RefreshToken.for_user(user)
            
            # Initialize response_data ONCE with user data and tokens
            response_data = {
                'user': UserSerializer(user).data,
                'refresh': str(refresh),
                'access': str(refresh.access_token),
                'message': 'User registered successfully'
            }
            
            # Add email verification info if email is provided
            if user.email:
                response_data['email_verification'] = {
                    'required': True,
                    'sent': email_verification_sent,
                    'message': 'Please check your email to verify your account'
                }
            
            # Add phone verification info if phone is provided and SMS verification is enabled
            if user.phone and getattr(settings, 'SMS_VERIFICATION_ENABLED', False):
                response_data['phone_verification'] = {
                    'required': True,
                    'sent': phone_verification_sent,
                    'message': 'Please check your phone to verify your account'
                }
            
            return Response(response_data, status=status.HTTP_201_CREATED)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class LoginViewSet(viewsets.ViewSet):
    """
    ViewSet for user login
    """
    permission_classes = [permissions.AllowAny]
    serializer_class = LoginSerializer  # This helps the browsable API
    
    def list(self, request):
        """
        GET method - provides information about the login endpoint
        """
        return Response({
            "message": "Use POST to login",
            "required_fields": {
                "email": "email@example.com (optional if phone provided)",
                "phone": "1234567890 (optional if email provided)",
                "password": "Your password"
            }
        })


    def create(self, request):
    #POST method - logs in a user
    
        serializer = LoginSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data.get('email')
            phone = serializer.validated_data.get('phone')
            password = serializer.validated_data.get('password')
            
            # Find the user by email or phone
            if email:
                user = User.objects.filter(email=email).first()
            else:
                user = User.objects.filter(phone=phone).first()
            # Check if user exists and password is correct
            if user and user.check_password(password):
                # Check if email is verified (if using email login)
                if email and not user.email_verified:
                    return Response({
                        'message': 'Email not verified',
                        'email_verification_required': True
                    }, status=status.HTTP_403_FORBIDDEN)
                
                # Check if phone is verified (if using phone login) and SMS verification is enabled
                if phone and not user.phone_verified and getattr(settings, 'SMS_VERIFICATION_ENABLED', False):
                    # Generate a new verification code if needed
                    if not user.phone_verification_token or user.phone_verification_token_expires < timezone.now():
                        code = generate_phone_verification_code(user)
                        send_phone_verification(user)
                    
                    return Response({
                        'message': 'Phone not verified',
                        'phone_verification_required': True
                    }, status=status.HTTP_403_FORBIDDEN)
                
                # Generate tokens
                refresh = RefreshToken.for_user(user)
                
                # Return user data and tokens
                return Response({
                    'user': UserSerializer(user).data,
                    'refresh': str(refresh),
                    'access': str(refresh.access_token),
                    'message': 'Login successful'
                }, status=status.HTTP_200_OK)
            
            return Response({
                'message': 'Invalid credentials'
            }, status=status.HTTP_401_UNAUTHORIZED)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class LogoutViewSet(viewsets.ViewSet):
    """
    ViewSet for user logout
    """
    permission_classes = [permissions.AllowAny]  # Allow any user to access this viewset
    serializer_class = None  # No serializer needed for logout
    
    def list(self, request):
        """
        GET method - provides information about the logout endpoint
        """
        return Response({
            "message": "Use POST to logout",
            "required_fields": {
                "refresh": "Your refresh token"
            }
        })
    
    def create(self, request):
        """
        POST method - logs out a user by blacklisting their refresh token
        """
        try:
            refresh_token = request.data.get("refresh")
            if not refresh_token:
                return Response({"error": "Refresh token is required"}, status=status.HTTP_400_BAD_REQUEST)
                
            token = RefreshToken(refresh_token)
            token.blacklist()
            
            return Response({
                "message": "Logout successful, token has been blacklisted"
            }, status=status.HTTP_205_RESET_CONTENT)
        except Exception as e:
            return Response({
                "error": f"Logout failed: {str(e)}"
            }, status=status.HTTP_400_BAD_REQUEST)


class PasswordResetRequestViewSet(viewsets.ViewSet):
    """
    ViewSet for requesting password resets
    """
    permission_classes = [permissions.AllowAny]
    serializer_class = PasswordResetRequestSerializer  # This helps the browsable API
    
    def list(self, request):
        """
        GET method - provides information about the password reset request endpoint
        """
        return Response({
            "message": "Use POST to request a password reset",
            "required_fields": {
                "email_or_phone": "Your email or phone number"
            }
        })
    
    def create(self, request):
        """
        POST method - requests a password reset
        """
        serializer = PasswordResetRequestSerializer(data=request.data)
        if serializer.is_valid():
            email_or_phone = serializer.validated_data.get('email_or_phone')
            # Find user by email or phone
            user = User.objects.filter(email=email_or_phone).first()
            if not user:
                user = User.objects.filter(phone=email_or_phone).first()
            
            if user:
                # Generate reset token
                token = uuid.uuid4().hex
                expires = timezone.now() + timedelta(hours=1)
                
                # Save token to user
                user.reset_token = token
                user.reset_token_expires = expires
                user.save()

                # In a real app, you would send an email or SMS here
                # For now, we'll just print the token
                print(f"Reset token for {user}: {token}")
                
                return Response({
                    'message': 'Password reset instructions sent'
                }, status=status.HTTP_200_OK)
            
            # Don't reveal if user exists or not for security
            return Response({
                'message': 'If a user with this email/phone exists, reset instructions have been sent'
            }, status=status.HTTP_200_OK)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class PasswordResetConfirmViewSet(viewsets.ViewSet):
    """
    ViewSet for confirming password resets
    """
    permission_classes = [permissions.AllowAny]
    serializer_class = PasswordResetConfirmSerializer  # This helps the browsable API
    
    def list(self, request):
        """
        GET method - provides information about the password reset confirmation endpoint
        """
        return Response({
            "message": "Use POST to confirm password reset",
            "required_fields": {
                "token": "The reset token you received",
                "new_password": "Your new password",
                "confirm_password": "Confirm your new password"
            }
        })
    
    def create(self, request):
        """
        POST method - confirms a password reset
        """
        serializer = PasswordResetConfirmSerializer(data=request.data)
        if serializer.is_valid():
            token = serializer.validated_data.get('token')
            new_password = serializer.validated_data.get('new_password')
            
            # Find user with this token
            user = User.objects.filter(
                reset_token=token,
                reset_token_expires__gt=timezone.now()
            ).first()
            
            if user:
                # Set new password
                user.set_password(new_password)
                
                # Clear reset token
                user.reset_token = None
                user.reset_token_expires = None
                user.save()
                
                return Response({
                    'message': 'Password reset successful'
                }, status=status.HTTP_200_OK)
            
            return Response({
                'message': 'Invalid or expired token'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class UserViewSet(viewsets.ViewSet):
    """
    ViewSet for user details
    """
    serializer_class = UserSerializer  # This helps the browsable API
    
    @action(detail=False, methods=['get'])
    def me(self, request):
        """
        GET method - gets the current user's details
        """
        serializer = UserSerializer(request.user)
        return Response(serializer.data)


class ProfileViewSet(viewsets.ViewSet):
    """
    ViewSet for managing user profiles
    """
    serializer_class = UserProfileSerializer  # This helps the browsable API
    
    def list(self, request):
        """
        GET method - provides information about the profile endpoint
        """
        return Response({
            "message": "Use the following endpoints to manage your profile",
            "endpoints": {
                "GET /api/profile/me/": "Get your profile",
                "POST /api/profile/": "Create or update your profile",
                "PUT /api/profile/update_profile/": "Completely update your profile",
                "PATCH /api/profile/update_profile/": "Partially update your profile",
                "PUT /api/profile/update_user/": "Update user information (first_name, middle_name, last_name, gender, age, school, email, phone)",
                "PATCH /api/profile/update_user/": "Partially update user information",
                "POST /api/profile/upload_picture/": "Upload a profile picture"
            }
        })
    
    @action(detail=False, methods=['get'])
    def me(self, request):
        """
        GET method - gets the current user's profile
        """
        # Try to get the user's profile
        try:
            profile = UserProfile.objects.get(user=request.user)
            serializer = UserProfileSerializer(profile)
            return Response(serializer.data)
        except UserProfile.DoesNotExist:
            # Return empty profile data if profile doesn't exist
            return Response({
                "profile_picture": None,
                "bio": None
            })
    
    def create(self, request):
        """
        POST method - creates or updates the user's profile
        """
        # Get or create the user's profile
        profile, created = UserProfile.objects.get_or_create(user=request.user)
        
        # Use partial=True to allow partial updates
        serializer = UserProfileUpdateSerializer(profile, data=request.data, partial=True)
        
        if serializer.is_valid():
            serializer.save()
            return Response({
                'message': 'Profile updated successfully',
                'profile': serializer.data
            }, status=status.HTTP_200_OK)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    @action(detail=False, methods=['put', 'patch'])
    def update_profile(self, request):
        """
        PUT/PATCH method - updates the user's profile
        """
        # Get or create the user's profile
        profile, created = UserProfile.objects.get_or_create(user=request.user)
        
        # For PUT, we expect all fields; for PATCH, we allow partial updates
        is_partial = request.method == 'PATCH'
        serializer = UserProfileUpdateSerializer(profile, data=request.data, partial=is_partial)
        
        if serializer.is_valid():
            serializer.save()
            return Response({
                'message': f'Profile {"partially " if is_partial else ""}updated successfully',
                'profile': serializer.data
            }, status=status.HTTP_200_OK)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    @action(detail=False, methods=['put', 'patch'])
    def update_user(self, request):
        """
        PUT/PATCH method - updates the user's information (first_name, middle_name, last_name, gender, age, school)
        """
        user = request.user
        
        # For PUT, we expect all fields; for PATCH, we allow partial updates
        is_partial = request.method == 'PATCH'
        
        # Pass the request in the context
        serializer = UserUpdateSerializer(
            user, 
            data=request.data, 
            partial=is_partial,
            context={'request': request}  # Add this line
        )

        if serializer.is_valid():
            # Check if email is being updated
            email_updated = False
            email_verification_required = False
            
            if 'email' in serializer.validated_data and serializer.validated_data['email'] != user.email:
                old_email = user.email
                email_updated = True
                
                # Mark email as unverified
                user.email_verified = False
                
                # Save the user with the new email
                serializer.save()
                
                # Generate verification token and send email
                token = generate_verification_token(user)
                verification_sent = send_verification_email(user, request)
                
                email_verification_required = True
            else:
                # No email update, just save the user
                serializer.save()
            
            response_data = {
                'message': f'User information {"partially " if is_partial else ""}updated successfully',
                'user': UserSerializer(user).data
            }
            
            # Add email verification info if email was updated
            if email_updated:
                response_data['email_verification_required'] = email_verification_required
                response_data['email_verification_sent'] = verification_sent if 'verification_sent' in locals() else False
            
            return Response(response_data, status=status.HTTP_200_OK)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


    @action(detail=False, methods=['post'])
    def upload_picture(self, request):
        """
        POST method - uploads a profile picture
        """
        # Get or create the user's profile
        profile, created = UserProfile.objects.get_or_create(user=request.user)
        
        if 'profile_picture' not in request.FILES:
            return Response({"error": "No profile picture provided"}, status=status.HTTP_400_BAD_REQUEST)
        
        # Update the profile picture
        profile.profile_picture = request.FILES['profile_picture']
        profile.save()

        return Response({
            'message': 'Profile picture uploaded successfully',
            'profile': UserProfileSerializer(profile).data
        }, status=status.HTTP_200_OK)


class EmailVerificationViewSet(viewsets.ViewSet):
    """
    ViewSet for email verification
    """
    permission_classes = [permissions.AllowAny]
    serializer_class = EmailVerificationSerializer  # This helps the browsable API
    
    def list(self, request):
        """
        GET method - provides information about the email verification endpoint
        """
        return Response({
            "message": "Use the following endpoints for email verification",
            "endpoints": {
                "GET /api/verify-email/{token}/": "Verify your email with a token",
                "POST /api/verify-email/resend/": "Resend verification email"
            }
        })
    
    def retrieve(self, request, pk=None):
        """
        GET method - verifies an email with the provided token
        """
        token = pk  # The token is passed as the pk parameter
        
        # Find user with this token
        user = User.objects.filter(
            email_verification_token=token,
            email_verification_token_expires__gt=timezone.now()
        ).first()
        
        if user:
            # Mark email as verified
            user.email_verified = True
            
            # Clear verification token
            user.email_verification_token = None
            user.email_verification_token_expires = None
            user.save()
            
            return Response({
                'message': 'Email verified successfully',
                'email': user.email
            }, status=status.HTTP_200_OK)
        
        return Response({
            'message': 'Invalid or expired token'
        }, status=status.HTTP_400_BAD_REQUEST)
    
    @action(detail=False, methods=['post'], throttle_classes=[EmailResendThrottle])
    def resend(self, request):
        """
        POST method - resends a verification email
        """
        logger.info("Verification email resend requested")
        
        serializer = EmailVerificationSerializer(data=request.data, context={'request': request})
        if serializer.is_valid():
            email = serializer.validated_data.get('email')
            
            logger.info(f"Resend verification requested for email: {email}")
            
            if not email:
                return Response({
                    'message': 'Email is required'
                }, status=status.HTTP_400_BAD_REQUEST)
            
            # Find user by email
            user = User.objects.filter(email=email).first()
            
            if user:
                # Check if email is already verified
                if user.email_verified:
                    logger.info(f"Email already verified: {email}")
                    return Response({
                        'message': 'Email is already verified'
                    }, status=status.HTTP_400_BAD_REQUEST)
                
                # Generate new token and send email
                token = generate_verification_token(user)
                verification_sent = send_verification_email(user, request)
                
                if verification_sent:
                    logger.info(f"Verification email sent successfully to: {email}")
                    return Response({
                        'message': 'Verification email sent successfully'
                    }, status=status.HTTP_200_OK)
                else:
                    logger.error(f"Failed to send verification email to: {email}")
                    return Response({
                        'message': 'Failed to send verification email'
                    }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            
            # Don't reveal if user exists or not for security
            logger.info(f"Resend verification response sent for: {email}")
            return Response({
                'message': 'If a user with this email exists, a verification email has been sent'
            }, status=status.HTTP_200_OK)
        logger.warning(f"Invalid resend verification request: {serializer.errors}")
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class PhoneVerificationViewSet(viewsets.ViewSet):
    """
    ViewSet for phone verification
    """
    serializer_class = PhoneVerificationSerializer
    throttle_classes = [PhoneVerificationThrottle]
    
    def list(self, request):
        """
        GET method - provides information about the phone verification endpoint
        """
        # Check if SMS verification is enabled
        if not getattr(settings, 'SMS_VERIFICATION_ENABLED', False):
            return Response({
                "message": "Phone verification is currently disabled",
                "status": "disabled"
            })
            
        return Response({
            "message": "Use the following endpoints for phone verification",
            "endpoints": {
                "POST /api/verify-phone/request/": "Request a verification code via SMS",
                "POST /api/verify-phone/confirm/": "Verify your phone with the code received"
            }
        })
    
    @action(detail=False, methods=['post'])
    def request(self, request):
        """
        Request phone verification by sending an SMS with a verification code.
        """
        # Check if SMS verification is enabled
        if not getattr(settings, 'SMS_VERIFICATION_ENABLED', False):
            return Response({
                'message': 'Phone verification is currently disabled',
                'status': 'disabled'
            }, status=status.HTTP_400_BAD_REQUEST)
            
        user = request.user
        
        if not user.phone:
            return Response({
                'message': 'No phone number associated with this account'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        if user.phone_verified:
            return Response({
                'message': 'Phone number is already verified'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # Generate and send verification code
        code = generate_phone_verification_code(user)
        verification_sent = send_phone_verification(user)
        
        if verification_sent:
            return Response({
                'message': 'Verification code sent successfully',
                'phone': user.phone[-4:]  # Return last 4 digits for reference
            }, status=status.HTTP_200_OK)
        else:
            return Response({
                'message': 'Failed to send verification code'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    @action(detail=False, methods=['post'])
    def confirm(self, request):
        """
        Confirm phone verification with the code received via SMS.
        """
        # Check if SMS verification is enabled
        if not getattr(settings, 'SMS_VERIFICATION_ENABLED', False):
            return Response({
                'message': 'Phone verification is currently disabled',
                'status': 'disabled'
            }, status=status.HTTP_400_BAD_REQUEST)
            
        user = request.user
        code = request.data.get('code')
        
        if not code:
            return Response({
                'message': 'Verification code is required'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        if not user.phone_verification_token:
            return Response({
                'message': 'No verification code has been requested'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        if user.phone_verification_token_expires < timezone.now():
            return Response({
                'message': 'Verification code has expired'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        if user.phone_verification_token != code:
            return Response({
                'message': 'Invalid verification code'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # Mark phone as verified
        user.phone_verified = True
        user.phone_verification_token = None
        user.phone_verification_token_expires = None
        user.save()
        
        return Response({
            'message': 'Phone number verified successfully',
            'phone': user.phone
        }, status=status.HTTP_200_OK)


class GoogleAuthViewSet(viewsets.ViewSet):
    """
    ViewSet for Google authentication
    """
    permission_classes = [permissions.AllowAny]
    serializer_class = GoogleAuthSerializer
    
    def create(self, request):
        """
        Handle Google authentication (both signup and signin)
        """
        serializer = self.serializer_class(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
            
        token = serializer.validated_data['token']
        user_info = verify_google_token(token)
        
        if not user_info:
            return Response({'error': 'Invalid token'}, status=status.HTTP_400_BAD_REQUEST)
            
        # Check if user exists
        user = User.objects.filter(email=user_info['email']).first()
        
        if user:
            # This is a sign-in
            refresh = RefreshToken.for_user(user)
            return Response({
                'user': UserSerializer(user).data,
                'refresh': str(refresh),
                'access': str(refresh.access_token),
                'message': 'Login successful',
                'is_new_user': False
            })
        else:
            # This is a signup
            # Create new user
            user = User.objects.create_user(
                email=user_info['email'],
                first_name=user_info.get('given_name', ''),
                middle_name='',
                last_name=user_info.get('family_name', ''),
                # You'll need to handle required fields like gender, age, school
                gender='Other',  # Default value, update as needed
                age=0,  # Default value, update as needed
                school='',  # Default value, update as needed
                # Set a random password since they'll use Google to login
                password=get_random_string(32)
            )
            
            # Mark email as verified since Google already verified it
            user.email_verified = True
            user.save()
            
            # Generate tokens
            refresh = RefreshToken.for_user(user)
            
            return Response({
                'user': UserSerializer(user).data,
                'refresh': str(refresh),
                'access': str(refresh.access_token),
                'message': 'User registered successfully',
                'is_new_user': True
            }, status=status.HTTP_201_CREATED)
