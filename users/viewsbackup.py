"""
BACKUP FILE - NOT IN USE

This file contains the combined AuthViewSet approach that was replaced by
individual ViewSets in viewsets.py. Kept for reference purposes only.

Date: [Current Date]
"""


import uuid
from datetime import timedelta
from django.utils import timezone
from django.contrib.auth import get_user_model
from rest_framework import status, permissions, viewsets
from rest_framework.decorators import action
from rest_framework.response import Response
from users.models import UserProfile
from rest_framework_simplejwt.tokens import RefreshToken
from .serializers import (
    RegisterSerializer, 
    LoginSerializer, 
    UserSerializer,
    UserProfileSerializer,
    UserProfileUpdateSerializer,
    PasswordResetRequestSerializer,
    PasswordResetConfirmSerializer,
    EmailVerificationSerializer,  # Add this import if you create this serializer
)
from .utils import generate_verification_token, send_verification_email

User = get_user_model()


class AuthViewSet(viewsets.GenericViewSet):
    """
    ViewSet for authentication-related actions
    """
    permission_classes = [permissions.AllowAny]
    
    def get_serializer_class(self):
        """
        Return the appropriate serializer class based on the action
        """
        if self.action == 'register':
            return RegisterSerializer
        elif self.action == 'login':
            return LoginSerializer
        elif self.action == 'password_reset_request':
            return PasswordResetRequestSerializer
        elif self.action == 'password_reset_confirm':
            return PasswordResetConfirmSerializer
        elif self.action == 'verify_email':
            return EmailVerificationSerializer  # You may need to create this
        elif self.action == 'resend_verification':
            return EmailVerificationSerializer  # You may need to create this
        return UserSerializer
    
    @action(detail=False, methods=['post'])
    def register(self, request):
        """
        Register a new user
        """
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            
            # Send verification email if email is provided
            verification_sent = False
            if user.email:
                # Generate verification token and send email
                token = generate_verification_token(user)
                verification_sent = send_verification_email(user, request)
            
            # Generate tokens
            refresh = RefreshToken.for_user(user)
            
            # Return user data, tokens, and verification status
            response_data = {
                'user': UserSerializer(user).data,
                'refresh': str(refresh),
                'access': str(refresh.access_token),
                'message': 'User registered successfully'
            }
            
            if user.email:
                response_data['email_verification'] = {
                    'required': True,
                    'sent': verification_sent,
                    'message': 'Please check your email to verify your account'
                }
            
            return Response(response_data, status=status.HTTP_201_CREATED)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    @action(detail=False, methods=['post'])
    def login(self, request):
        """
        Login a user
        """
        serializer = self.get_serializer(data=request.data)
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
    
    @action(detail=False, methods=['post'])
    def password_reset_request(self, request):
        """
        Request a password reset
        """
        serializer = self.get_serializer(data=request.data)
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
    
    @action(detail=False, methods=['post'])
    def password_reset_confirm(self, request):
        """
        Confirm a password reset
        """
        serializer = self.get_serializer(data=request.data)
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
    
    @action(detail=False, methods=['get', 'post'])
    def verify_email(self, request):
        """
        Verify a user's email with the provided token
        """
        # For GET requests, we expect the token as a query parameter
        if request.method == 'GET':
            token = request.query_params.get('token')
            if not token:
                return Response({
                    'message': 'Token is required'
                }, status=status.HTTP_400_BAD_REQUEST)
        # For POST requests, we expect the token in the request body
        else:
            token = request.data.get('token')
            if not token:
                return Response({
                    'message': 'Token is required'
                }, status=status.HTTP_400_BAD_REQUEST)
        
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
    
    @action(detail=False, methods=['post'])
    def resend_verification(self, request):
        """
        Resend a verification email
        """
        email = request.data.get('email')
        
        if not email:
            return Response({
                'message': 'Email is required'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # Find user by email
        user = User.objects.filter(email=email).first()
        
        if user:
            # Check if email is already verified
            if user.email_verified:
                return Response({
                    'message': 'Email is already verified'
                }, status=status.HTTP_400_BAD_REQUEST)
            
            # Generate new token and send email
            token = generate_verification_token(user)
            verification_sent = send_verification_email(user, request)
            
            if verification_sent:
                return Response({
                    'message': 'Verification email sent successfully'
                }, status=status.HTTP_200_OK)
            else:
                return Response({
                    'message': 'Failed to send verification email'
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
        # Don't reveal if user exists or not for security
        return Response({
            'message': 'If a user with this email exists, a verification email has been sent'
        }, status=status.HTTP_200_OK)


class UserViewSet(viewsets.ReadOnlyModelViewSet):
    """
    ViewSet for user-related actions
    """
    serializer_class = UserSerializer
    
    def get_queryset(self):
        """
        Return only the current user
        """
        return User.objects.filter(id=self.request.user.id)
    
    @action(detail=False, methods=['get'])
    def me(self, request):
        """
        Get the current user's details
        """
        serializer = self.get_serializer(request.user)
        return Response(serializer.data)


class ProfileViewSet(viewsets.GenericViewSet):
    """
    ViewSet for managing user profiles
    """
    
    def get_serializer_class(self):
        """
        Return the appropriate serializer class based on the action
        """
        if self.action in ['update', 'partial_update', 'create']:
            return UserProfileUpdateSerializer
        return UserProfileSerializer
    
    def get_queryset(self):
        """
        Return only the current user's profile
        """
        return UserProfile.objects.filter(user=self.request.user)
    
    @action(detail=False, methods=['get'])
    def me(self, request):
        """
        Get the current user's profile
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
    
    @action(detail=False, methods=['post', 'put', 'patch'])
    def update_profile(self, request):
        """
        Create or update the user's profile
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
    
    @action(detail=False, methods=['post'])
    def upload_picture(self, request):
        """
        Upload a profile picture
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
