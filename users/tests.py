from django.test import TestCase
from django.urls import reverse
from django.utils import timezone
from django.contrib.auth import get_user_model
from django.core import mail
from rest_framework.test import APIClient
from rest_framework import status
from .utils import generate_phone_verification_code, send_phone_verification
from unittest.mock import patch, MagicMock
from datetime import timedelta
import uuid
import json

from .models import UserProfile
from .utils import generate_verification_token

User = get_user_model()

class UserModelTests(TestCase):
    """Tests for the User model"""
    
    def test_create_user_with_email(self):
        """Test creating a user with an email address"""
        email = 'test@example.com'
        password = 'testpass123'
        user = User.objects.create_user(
            email=email,
            password=password,
            first_name='Test',
            last_name='User',
            gender='Male',
            age=25,
            school='Test University'
        )
        
        self.assertEqual(user.email, email)
        self.assertTrue(user.check_password(password))
        self.assertFalse(user.is_staff)
        self.assertTrue(user.is_active)
        self.assertFalse(user.is_superuser)
        self.assertFalse(user.email_verified)
        
    def test_create_user_with_phone(self):
        """Test creating a user with a phone number"""
        phone = '1234567890'
        password = 'testpass123'
        user = User.objects.create_user(
            phone=phone,
            password=password,
            first_name='Test',
            last_name='User',
            gender='Male',
            age=25,
            school='Test University'
        )
        
        self.assertEqual(user.phone, phone)
        self.assertTrue(user.check_password(password))
        self.assertFalse(user.phone_verified)
        
    def test_create_user_without_email_or_phone(self):
        """Test creating a user without email or phone raises error"""
        with self.assertRaises(ValueError):
            User.objects.create_user(
                email=None,
                phone=None,
                password='testpass123',
                first_name='Test',
                last_name='User',
                gender='Male',
                age=25,
                school='Test University'
            )
            
    def test_create_superuser(self):
        """Test creating a superuser"""
        user = User.objects.create_superuser(
            email='admin@example.com',
            password='admin123',
            first_name='Admin',
            last_name='User',
            gender='Male',
            age=30,
            school='Admin University'
        )
        
        self.assertTrue(user.is_staff)
        self.assertTrue(user.is_superuser)
        
    def test_get_full_name(self):
        """Test getting the full name of a user"""
        user = User.objects.create_user(
            email='test@example.com',
            password='testpass123',
            first_name='Test',
            middle_name='Middle',
            last_name='User',
            gender='Male',
            age=25,
            school='Test University'
        )
        
        self.assertEqual(user.get_full_name(), 'Test Middle User')
        
        # Test without middle name
        user.middle_name = None
        user.save()
        self.assertEqual(user.get_full_name(), 'Test User')
        
    def test_get_short_name(self):
        """Test getting the short name of a user"""
        user = User.objects.create_user(
            email='test@example.com',
            password='testpass123',
            first_name='Test',
            last_name='User',
            gender='Male',
            age=25,
            school='Test University'
        )
        
        self.assertEqual(user.get_short_name(), 'Test')
        
    def test_user_str_representation(self):
        """Test the string representation of a user"""
        user = User.objects.create_user(
            email='test@example.com',
            password='testpass123',
            first_name='Test',
            last_name='User',
            gender='Male',
            age=25,
            school='Test University'
        )
        
        self.assertEqual(str(user), 'test@example.com')
        
        # Test with phone only
        user2 = User.objects.create_user(
            phone='1234567890',
            password='testpass123',
            first_name='Phone',
            last_name='User',
            gender='Male',
            age=25,
            school='Test University'
        )
        
        self.assertEqual(str(user2), '1234567890')


class UserProfileModelTests(TestCase):
    """Tests for the UserProfile model"""
    
    def setUp(self):
        self.user = User.objects.create_user(
            email='test@example.com',
            password='testpass123',
            first_name='Test',
            last_name='User',
            gender='Male',
            age=25,
            school='Test University'
        )
        
    def test_profile_creation(self):
        """Test that a profile is created for a new user"""
        self.assertTrue(hasattr(self.user, 'profile'))
        self.assertIsInstance(self.user.profile, UserProfile)
        
    def test_profile_str_representation(self):
        """Test the string representation of a profile"""
        self.assertEqual(str(self.user.profile), "test@example.com's profile")


class RegisterViewSetTests(TestCase):
    """Tests for the RegisterViewSet"""
    
    def setUp(self):
        self.client = APIClient()
        self.register_url = reverse('register-list')
        self.valid_payload = {
            'email': 'newuser@example.com',
            'first_name': 'New',
            'last_name': 'User',
            'gender': 'Male',
            'age': 25,
            'school': 'Test University',
            'password': 'securepassword123',
            'password2': 'securepassword123'
        }
        
    def test_register_valid_user_with_email(self):
        """Test registering a valid user with email"""
        with patch('users.utils.send_verification_email') as mock_send_email:
            mock_send_email.return_value = True
            response = self.client.post(
                self.register_url,
                data=json.dumps(self.valid_payload),
                content_type='application/json'
            )
            
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertTrue(User.objects.filter(email='newuser@example.com').exists())
        self.assertIn('refresh', response.data)
        self.assertIn('access', response.data)
        self.assertIn('email_verification', response.data)
        
    def test_register_valid_user_with_phone(self):
        """Test registering a valid user with phone"""
        payload = self.valid_payload.copy()
        payload.pop('email')
        payload['phone'] = '1234567890'
        
        response = self.client.post(
            self.register_url,
            data=json.dumps(payload),
            content_type='application/json'
        )
        
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertTrue(User.objects.filter(phone='1234567890').exists())
        self.assertIn('refresh', response.data)
        self.assertIn('access', response.data)
        self.assertNotIn('email_verification', response.data)
        
    def test_register_invalid_no_email_or_phone(self):
        """Test registering without email or phone"""
        payload = self.valid_payload.copy()
        payload.pop('email')
        
        response = self.client.post(
            self.register_url,
            data=json.dumps(payload),
            content_type='application/json'
        )
        
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        
    def test_register_invalid_password_mismatch(self):
        """Test registering with mismatched passwords"""
        payload = self.valid_payload.copy()
        payload['password2'] = 'differentpassword'
        
        response = self.client.post(
            self.register_url,
            data=json.dumps(payload),
            content_type='application/json'
        )
        
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        
    def test_register_invalid_email_already_exists(self):
        """Test registering with an email that already exists"""
        # Create a user with the email first
        User.objects.create_user(
            email='newuser@example.com',
            password='existingpass123',
            first_name='Existing',
            last_name='User',
            gender='Male',
            age=30,
            school='Existing University'
        )
        
        response = self.client.post(
            self.register_url,
            data=json.dumps(self.valid_payload),
            content_type='application/json'
        )
        
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        
    def test_register_list_endpoint(self):
        """Test the GET method on register endpoint"""
        response = self.client.get(self.register_url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('message', response.data)
        self.assertIn('required_fields', response.data)


class LoginViewSetTests(TestCase):
    """Tests for the LoginViewSet"""
    
    def setUp(self):
        self.client = APIClient()
        self.login_url = reverse('login-list')
        
        # Create a verified user with email
        self.email_user = User.objects.create_user(
            email='verified@example.com',
            password='testpass123',
            first_name='Verified',
            last_name='User',
            gender='Male',
            age=25,
            school='Test University'
        )
        self.email_user.email_verified = True
        self.email_user.save()
        
        # Create a user with unverified email
        self.unverified_user = User.objects.create_user(
            email='unverified@example.com',
            password='testpass123',
            first_name='Unverified',
            last_name='User',
            gender='Male',
            age=25,
            school='Test University'
        )
        
        # Create a user with phone
        self.phone_user = User.objects.create_user(
            phone='1234567890',
            password='testpass123',
            first_name='Phone',
            last_name='User',
            gender='Male',
            age=25,
            school='Test University'
        )
        
    def test_login_with_verified_email(self):
        """Test login with a verified email"""
        payload = {
            'email': 'verified@example.com',
            'password': 'testpass123'
        }
        
        response = self.client.post(
            self.login_url,
            data=json.dumps(payload),
            content_type='application/json'
        )
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('refresh', response.data)
        self.assertIn('access', response.data)
        self.assertEqual(response.data['message'], 'Login successful')
        
    def test_login_with_unverified_email(self):
        """Test login with an unverified email"""
        payload = {
            'email': 'unverified@example.com',
            'password': 'testpass123'
        }
        
        response = self.client.post(
            self.login_url,
            data=json.dumps(payload),
            content_type='application/json'
        )
        
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertIn('email_verification_required', response.data)
        
    def test_login_with_phone(self):
        """Test login with a phone number"""
        # Mark the phone as verified
        self.phone_user.phone_verified = True
        self.phone_user.save()
        
        payload = {
            'phone': '1234567890',
            'password': 'testpass123'
        }
        
        with patch('django.conf.settings.SMS_VERIFICATION_ENABLED', False):
            response = self.client.post(
                self.login_url,
                data=json.dumps(payload),
                content_type='application/json'
            )
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('refresh', response.data)
        self.assertIn('access', response.data)
        
    def test_login_invalid_credentials(self):
        """Test login with invalid credentials"""
        payload = {
            'email': 'verified@example.com',
            'password': 'wrongpassword'
        }
        
        response = self.client.post(
            self.login_url,
            data=json.dumps(payload),
            content_type='application/json'
        )
        
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertEqual(response.data['message'], 'Invalid credentials')
        
    def test_login_missing_email_and_phone(self):
        """Test login without email or phone"""
        payload = {
            'password': 'testpass123'
        }
        
        response = self.client.post(
            self.login_url,
            data=json.dumps(payload),
            content_type='application/json'
        )
        
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        
    def test_login_list_endpoint(self):
        """Test the GET method on login endpoint"""
        response = self.client.get(self.login_url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('message', response.data)
        self.assertIn('required_fields', response.data)


class LogoutViewSetTests(TestCase):
    """Tests for the LogoutViewSet"""
    
    def setUp(self):
        self.client = APIClient()
        self.logout_url = reverse('logout-list')
        self.login_url = reverse('login-list')
        
        # Create a user
        self.user = User.objects.create_user(
            email='test@example.com',
            password='testpass123',
            first_name='Test',
            last_name='User',
            gender='Male',
            age=25,
            school='Test University',
            email_verified=True
        )
        
        # Login to get a refresh token
        response = self.client.post(
            self.login_url,
            data=json.dumps({
                'email': 'test@example.com',
                'password': 'testpass123'
            }),
            content_type='application/json'
        )
        
        self.refresh_token = response.data['refresh']
        
        # Authenticate the client for all tests
        self.client.force_authenticate(user=self.user)
    
    def test_logout_success(self):
        """Test successful logout"""
        response = self.client.post(
            self.logout_url,
            data=json.dumps({'refresh': self.refresh_token}),
            content_type='application/json'
        )
        
        self.assertEqual(response.status_code, status.HTTP_205_RESET_CONTENT)
        self.assertEqual(response.data['message'], 'Logout successful, token has been blacklisted')
        
    def test_logout_missing_token(self):
        """Test logout without a refresh token"""
        response = self.client.post(
            self.logout_url,
            data=json.dumps({}),
            content_type='application/json'
        )
        
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('error', response.data)
        
    def test_logout_invalid_token(self):
        """Test logout with an invalid refresh token"""
        response = self.client.post(
            self.logout_url,
            data=json.dumps({'refresh': 'invalid-token'}),
            content_type='application/json'
        )
        
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('error', response.data)
        
    def test_logout_list_endpoint(self):
        """Test the GET method on logout endpoint"""
        response = self.client.get(self.logout_url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('message', response.data)
        self.assertIn('required_fields', response.data)


class PasswordResetTests(TestCase):
    """Tests for password reset functionality"""
    
    def setUp(self):
        self.client = APIClient()
        self.request_url = reverse('password-reset-request-list')
        self.confirm_url = reverse('password-reset-confirm-list')
        
        # Create a user
        self.user = User.objects.create_user(
            email='test@example.com',
            password='oldpassword123',
            first_name='Test',
            last_name='User',
            gender='Male',
            age=25,
            school='Test University'
        )
        
    def test_password_reset_request_with_email(self):
        """Test requesting a password reset with email"""
        response = self.client.post(
            self.request_url,
            data=json.dumps({'email_or_phone': 'test@example.com'}),
            content_type='application/json'
        )
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['message'], 'Password reset instructions sent')
        
        # Check that the user has a reset token
        self.user.refresh_from_db()
        self.assertIsNotNone(self.user.reset_token)
        self.assertIsNotNone(self.user.reset_token_expires)
        
    def test_password_reset_request_with_nonexistent_email(self):
        """Test requesting a password reset with a nonexistent email"""
        response = self.client.post(
            self.request_url,
            data=json.dumps({'email_or_phone': 'nonexistent@example.com'}),
            content_type='application/json'
        )
        
        # Should still return 200 for security reasons
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['message'], 'If a user with this email/phone exists, reset instructions have been sent')
        
    def test_password_reset_confirm_valid(self):
        """Test confirming a password reset with a valid token"""
        # First, request a reset to get a token
        self.client.post(
            self.request_url,
            data=json.dumps({'email_or_phone': 'test@example.com'}),
            content_type='application/json'
        )
        
        # Get the token from the user
        self.user.refresh_from_db()
        token = self.user.reset_token
        
        # Now confirm the reset
        response = self.client.post(
            self.confirm_url,
            data=json.dumps({
                'token': token,
                'new_password': 'newpassword123',
                'confirm_password': 'newpassword123'
            }),
            content_type='application/json'
        )
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['message'], 'Password reset successful')
        
        # Check that the user's password has been updated
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password('newpassword123'))
        self.assertIsNone(self.user.reset_token)
        self.assertIsNone(self.user.reset_token_expires)
        
    def test_password_reset_confirm_invalid_token(self):
        """Test confirming a password reset with an invalid token"""
        response = self.client.post(
            self.confirm_url,
            data=json.dumps({
                'token': 'invalid-token',
                'new_password': 'newpassword123',
                'confirm_password': 'newpassword123'
            }),
            content_type='application/json'
        )
        
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data['message'], 'Invalid or expired token')
        
    def test_password_reset_confirm_expired_token(self):
        """Test confirming a password reset with an expired token"""
        # First, request a reset to get a token
        self.client.post(
            self.request_url,
            data=json.dumps({'email_or_phone': 'test@example.com'}),
            content_type='application/json'
        )
        
        # Get the token from the user and make it expired
        self.user.refresh_from_db()
        token = self.user.reset_token
        self.user.reset_token_expires = timezone.now() - timedelta(hours=1)
        self.user.save()
        
        # Now try to confirm the reset
        response = self.client.post(
            self.confirm_url,
            data=json.dumps({
                'token': token,
                'new_password': 'newpassword123',
                'confirm_password': 'newpassword123'
            }),
            content_type='application/json'
        )
        
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data['message'], 'Invalid or expired token')
        
    def test_password_reset_confirm_password_mismatch(self):
        """Test confirming a password reset with mismatched passwords"""
        # First, request a reset to get a token
        self.client.post(
            self.request_url,
            data=json.dumps({'email_or_phone': 'test@example.com'}),
            content_type='application/json'
        )
        
        # Get the token from the user
        self.user.refresh_from_db()
        token = self.user.reset_token
        
        # Now try to confirm the reset with mismatched passwords
        response = self.client.post(
            self.confirm_url,
            data=json.dumps({
                'token': token,
                'new_password': 'newpassword123',
                'confirm_password': 'differentpassword'
            }),
            content_type='application/json'
        )
        
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('password', str(response.data))


class EmailVerificationTests(TestCase):
    """Tests for email verification functionality"""
    
    def setUp(self):
        self.client = APIClient()
        self.verify_url = reverse('verify-email-list')
        self.resend_url = reverse('verify-email-resend')
        
        # Create a user with unverified email
        self.user = User.objects.create_user(
            email='unverified@example.com',
            password='testpass123',
            first_name='Unverified',
            last_name='User',
            gender='Male',
            age=25,
            school='Test University'
        )
        
        # Generate a verification token
        self.token = generate_verification_token(self.user)
        
    def test_verify_email_valid_token(self):
        """Test verifying an email with a valid token"""
        url = reverse('verify-email-detail', args=[self.token])
        response = self.client.get(url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['message'], 'Email verified successfully')
        
        # Check that the user's email is now verified
        self.user.refresh_from_db()
        self.assertTrue(self.user.email_verified)
        self.assertIsNone(self.user.email_verification_token)
        self.assertIsNone(self.user.email_verification_token_expires)
        
    def test_verify_email_invalid_token(self):
        """Test verifying an email with an invalid token"""
        url = reverse('verify-email-detail', args=['invalid-token'])
        response = self.client.get(url)
        
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data['message'], 'Invalid or expired token')
        
    def test_verify_email_expired_token(self):
        """Test verifying an email with an expired token"""
        # Make the token expired
        self.user.email_verification_token_expires = timezone.now() - timedelta(hours=1)
        self.user.save()
        
        url = reverse('verify-email-detail', args=[self.token])
        response = self.client.get(url)
        
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data['message'], 'Invalid or expired token')
        
    def test_resend_verification_email(self):
        """Test resending a verification email"""
        with patch('users.utils.send_verification_email') as mock_send_email:
            mock_send_email.return_value = True
            response = self.client.post(
                self.resend_url,
                data=json.dumps({'email': 'unverified@example.com'}),
                content_type='application/json'
            )
            
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['message'], 'Verification email sent successfully')
        
    def test_resend_verification_email_already_verified(self):
        """Test resending a verification email for an already verified email"""
        # Verify the email first
        self.user.email_verified = True
        self.user.save()
        
        response = self.client.post(
            self.resend_url,
            data=json.dumps({'email': 'unverified@example.com'}),
            content_type='application/json'
        )
        
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data['message'], 'Email is already verified')
        
    def test_resend_verification_email_nonexistent(self):
        """Test resending a verification email for a nonexistent email"""
        response = self.client.post(
            self.resend_url,
            data=json.dumps({'email': 'nonexistent@example.com'}),
            content_type='application/json'
        )
        
        # Should still return 200 for security reasons
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['message'], 'If a user with this email exists, a verification email has been sent')


class UserViewSetTests(TestCase):
    """Tests for the UserViewSet"""
    
    def setUp(self):
        self.client = APIClient()
        self.me_url = reverse('user-me')
        
        # Create a user
        self.user = User.objects.create_user(
            email='test@example.com',
            password='testpass123',
            first_name='Test',
            last_name='User',
            gender='Male',
            age=25,
            school='Test University'
        )
        
        # Authenticate the client
        self.client.force_authenticate(user=self.user)
        
    def test_get_me_authenticated(self):
        """Test getting the current user's details when authenticated"""
        response = self.client.get(self.me_url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['email'], 'test@example.com')
        self.assertEqual(response.data['first_name'], 'Test')
        self.assertEqual(response.data['last_name'], 'User')
        
    def test_get_me_unauthenticated(self):
        """Test getting the current user's details when not authenticated"""
        self.client.force_authenticate(user=None)
        response = self.client.get(self.me_url)
        
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)


class ProfileViewSetTests(TestCase):
    """Tests for the ProfileViewSet"""
    
    def setUp(self):
        self.client = APIClient()
        self.profile_url = reverse('profile-list')
        self.me_url = reverse('profile-me')
        self.update_profile_url = reverse('profile-update-profile')
        self.update_user_url = reverse('profile-update-user')
        self.upload_picture_url = reverse('profile-upload-picture')
        
        # Create a user
        self.user = User.objects.create_user(
            email='test@example.com',
            password='testpass123',
            first_name='Test',
            middle_name='Middle',
            last_name='User',
            gender='Male',
            age=25,
            school='Test University'
        )
        
        # Authenticate the client
        self.client.force_authenticate(user=self.user)
        
    def test_get_profile_info(self):
        """Test getting profile information"""
        response = self.client.get(self.profile_url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('message', response.data)
        self.assertIn('endpoints', response.data)
        
    def test_get_me_profile(self):
        """Test getting the current user's profile"""
        response = self.client.get(self.me_url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('profile_picture', response.data)
        self.assertIn('bio', response.data)
        
    def test_update_profile(self):
        """Test updating the user's profile"""
        payload = {
            'bio': 'This is my updated bio'
        }
        
        response = self.client.patch(
            self.update_profile_url,
            data=json.dumps(payload),
            content_type='application/json'
        )
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['profile']['bio'], 'This is my updated bio')
        
        # Check that the profile was updated in the database
        self.user.refresh_from_db()
        self.assertEqual(self.user.profile.bio, 'This is my updated bio')
        
    def test_update_user(self):
        """Test updating the user's information"""
        payload = {
            'first_name': 'Updated',
            'middle_name': 'New',
            'last_name': 'Name',
            'gender': 'Female',
            'age': 30,
            'school': 'Updated University'
        }
        
        with patch('users.utils.send_verification_email') as mock_send_email:
            mock_send_email.return_value = True
            response = self.client.patch(
                self.update_user_url,
                data=json.dumps(payload),
                content_type='application/json'
            )
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['user']['first_name'], 'Updated')
        self.assertEqual(response.data['user']['middle_name'], 'New')
        self.assertEqual(response.data['user']['last_name'], 'Name')
        self.assertEqual(response.data['user']['gender'], 'Female')
        self.assertEqual(response.data['user']['age'], 30)
        self.assertEqual(response.data['user']['school'], 'Updated University')
        
        # Check that the user was updated in the database
        self.user.refresh_from_db()
        self.assertEqual(self.user.first_name, 'Updated')
        self.assertEqual(self.user.gender, 'Female')
        
    def test_update_user_email(self):
        """Test updating the user's email"""
        payload = {
            'email': 'newemail@example.com'
        }
        
        with patch('users.utils.send_verification_email') as mock_send_email:
            mock_send_email.return_value = True
            response = self.client.patch(
                self.update_user_url,
                data=json.dumps(payload),
                content_type='application/json'
            )
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['user']['email'], 'newemail@example.com')
        
        # Check for email verification flags in the response
        self.assertTrue(response.data.get('email_verification_required', False))
        self.assertTrue(response.data.get('email_verification_sent', False))
        
        # Check that the user's email was updated and marked as unverified
        self.user.refresh_from_db()
        self.assertEqual(self.user.email, 'newemail@example.com')
        self.assertFalse(self.user.email_verified)
        
    def test_update_user_phone(self):
        """Test updating the user's phone number"""
        payload = {
            'phone': '9876543210'
        }
        
        response = self.client.patch(
            self.update_user_url,
            data=json.dumps(payload),
            content_type='application/json'
        )
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['user']['phone'], '9876543210')
        
        # Check that the user's phone was updated
        self.user.refresh_from_db()
        self.assertEqual(self.user.phone, '9876543210')
        self.assertFalse(self.user.phone_verified)
        
    def test_update_user_invalid_gender(self):
        """Test updating the user with an invalid gender"""
        payload = {
            'gender': 'Invalid'
        }
        
        response = self.client.patch(
            self.update_user_url,
            data=json.dumps(payload),
            content_type='application/json'
        )
        
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('gender', str(response.data))
        
    def test_upload_profile_picture(self):
        """Test uploading a profile picture"""
        # Create a temporary image file
        from PIL import Image
        import tempfile
        
        image = Image.new('RGB', (100, 100))
        tmp_file = tempfile.NamedTemporaryFile(suffix='.jpg')
        image.save(tmp_file)
        tmp_file.seek(0)
        
        # Upload the image
        response = self.client.post(
            self.upload_picture_url,
            {'profile_picture': tmp_file},
            format='multipart'
        )
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('profile', response.data)
        self.assertIn('profile_picture', response.data['profile'])
        
        # Check that the profile picture was updated
        self.user.refresh_from_db()
        self.assertIsNotNone(self.user.profile.profile_picture)
        
    def test_upload_profile_picture_no_image(self):
        """Test uploading a profile picture without providing an image"""
        response = self.client.post(
            self.upload_picture_url,
            {},
            format='multipart'
        )
        
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('error', response.data)


class GoogleAuthViewSetTests(TestCase):
    """Tests for the GoogleAuthViewSet"""
    
    def setUp(self):
        self.client = APIClient()
        self.google_auth_url = reverse('google-auth-list')
        
    @patch('users.viewsets.verify_google_token')
    def test_google_auth_signin(self, mock_verify_token):
        """Test signing in with Google (existing user)"""
        # Create a user with the email that Google will return
        User.objects.create_user(
            email='google@example.com',
            password='testpass123',
            first_name='Google',
            last_name='User',
            gender='Male',
            age=25,
            school='Test University'
        )
        
        # Mock the Google token verification
        mock_verify_token.return_value = {
            'email': 'google@example.com',
            'given_name': 'Google',
            'family_name': 'User'
        }
        
        response = self.client.post(
            self.google_auth_url,
            data=json.dumps({'token': 'valid-google-token'}),
            content_type='application/json'
        )
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('refresh', response.data)
        self.assertIn('access', response.data)
        self.assertFalse(response.data['is_new_user'])
        
    @patch('users.viewsets.verify_google_token')
    def test_google_auth_signup(self, mock_verify_token):
        """Test signing up with Google (new user)"""
        # Mock the Google token verification
        mock_verify_token.return_value = {
            'email': 'newgoogle@example.com',
            'given_name': 'New',
            'family_name': 'GoogleUser'
        }
        
        response = self.client.post(
            self.google_auth_url,
            data=json.dumps({'token': 'valid-google-token'}),
            content_type='application/json'
        )
        
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertIn('refresh', response.data)
        self.assertIn('access', response.data)
        self.assertTrue(response.data['is_new_user'])
        
        # Check that a new user was created
        self.assertTrue(User.objects.filter(email='newgoogle@example.com').exists())
        user = User.objects.get(email='newgoogle@example.com')
        self.assertEqual(user.first_name, 'New')
        self.assertEqual(user.last_name, 'GoogleUser')
        self.assertTrue(user.email_verified)  # Email should be verified for Google users
        
    @patch('users.viewsets.verify_google_token')
    def test_google_auth_invalid_token(self, mock_verify_token):
        """Test Google authentication with an invalid token"""
        # Mock the Google token verification to return None (invalid token)
        mock_verify_token.return_value = None
        
        response = self.client.post(
            self.google_auth_url,
            data=json.dumps({'token': 'invalid-google-token'}),
            content_type='application/json'
        )
        
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('error', response.data)


class PhoneVerificationTests(TestCase):
    """Tests for phone verification functionality"""
    
    def setUp(self):
        self.client = APIClient()
        self.request_url = reverse('verify-phone-request')
        self.confirm_url = reverse('verify-phone-confirm')
        self.verify_phone_list_url = reverse('verify-phone-list')
        
        # Create a user with unverified phone
        self.user = User.objects.create_user(
            phone='+2347033495178',
            password='testpass123',
            first_name='Phone',
            last_name='User',
            gender='Male',
            age=25,
            school='Test University'
        )
        
        # Authenticate the client
        self.client.force_authenticate(user=self.user)
    
    def test_phone_verification_disabled(self):
        """Test that phone verification endpoints return appropriate responses when SMS is disabled"""
        # Test with SMS_VERIFICATION_ENABLED = False
        with patch('django.conf.settings.SMS_VERIFICATION_ENABLED', False):
            # Test the list endpoint
            response = self.client.get(self.verify_phone_list_url)
            self.assertEqual(response.status_code, status.HTTP_200_OK)
            self.assertEqual(response.data['message'], 'Phone verification is currently disabled')
            
            # Test the request endpoint
            response = self.client.post(self.request_url)
            self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
            self.assertEqual(response.data['message'], 'Phone verification is currently disabled')
            
            # Test the confirm endpoint
            response = self.client.post(
                self.confirm_url,
                data=json.dumps({'code': '123456'}),
                content_type='application/json'
            )
            self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
            self.assertEqual(response.data['message'], 'Phone verification is currently disabled')


class RegisterWithPhoneTests(TestCase):
    """Tests for registering with a phone number and SMS verification"""
    
    def setUp(self):
        self.client = APIClient()
        self.register_url = reverse('register-list')
        self.valid_payload = {
            'phone': '+2347033495178',
            'first_name': 'Phone',
            'last_name': 'User',
            'gender': 'Male',
            'age': 25,
            'school': 'Test University',
            'password': 'securepassword123',
            'password2': 'securepassword123'
        }
    
    def test_register_with_phone_when_sms_disabled(self):
        """Test registering with a phone number when SMS verification is disabled"""
        # Use settings override for this specific test
        with patch('django.conf.settings.SMS_VERIFICATION_ENABLED', False):
            response = self.client.post(
                self.register_url,
                data=json.dumps(self.valid_payload),
                content_type='application/json'
            )
        
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        
        # Check that the user was created and phone is automatically verified
        user = User.objects.get(phone='+2347033495178')
        self.assertTrue(user.phone_verified)
        self.assertFalse(user.phone_verification_required)
        
        # Check that phone verification info is not in the response
        self.assertNotIn('phone_verification', response.data)


class LoginWithPhoneVerificationTests(TestCase):
    """Tests for login with phone verification requirement"""
    
    def setUp(self):
        self.client = APIClient()
        self.login_url = reverse('login-list')
        
        # Create a user with unverified phone
        self.unverified_user = User.objects.create_user(
            phone='+2347033495178',
            password='testpass123',
            first_name='Unverified',
            last_name='Phone',
            gender='Male',
            age=25,
            school='Test University',
            phone_verification_required=True
        )
        
        # Create a user with verified phone
        self.verified_user = User.objects.create_user(
            phone='+2347033495179',
            password='testpass123',
            first_name='Verified',
            last_name='Phone',
            gender='Male',
            age=25,
            school='Test University',
            phone_verification_required=True,
            phone_verified=True
        )
    
    def test_login_with_unverified_phone_when_sms_disabled(self):
        """Test login with an unverified phone when SMS verification is disabled"""
        payload = {
            'phone': '+2347033495178',
            'password': 'testpass123'
        }
        
        # Use settings override for this specific test
        with patch('django.conf.settings.SMS_VERIFICATION_ENABLED', False):
            response = self.client.post(
                self.login_url,
                data=json.dumps(payload),
                content_type='application/json'
            )
        
        # Should be able to login even with unverified phone
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('refresh', response.data)
        self.assertIn('access', response.data)


class SMSUtilsTests(TestCase):
    """Tests for SMS utility functions"""
    
    def setUp(self):
        self.user = User.objects.create_user(
            phone='+2347033495178',
            password='testpass123',
            first_name='Test',
            last_name='User',
            gender='Male',
            age=25,
            school='Test University'
        )
    
    def test_generate_phone_verification_code(self):
        """Test generating a phone verification code"""
        code = generate_phone_verification_code(self.user)
        
        # Code should be a 6-digit string
        self.assertEqual(len(code), 6)
        self.assertTrue(code.isdigit())
        
        # User should have the code and expiry time set
        self.user.refresh_from_db()
        self.assertEqual(self.user.phone_verification_token, code)
        self.assertIsNotNone(self.user.phone_verification_token_expires)
        
        # Expiry should be 15 minutes in the future
        time_diff = self.user.phone_verification_token_expires - timezone.now()
        self.assertTrue(time_diff.total_seconds() > 14 * 60)  # At least 14 minutes
    
    def test_send_phone_verification_when_disabled(self):
        """Test sending a phone verification SMS when SMS verification is disabled"""
        # Generate a code first
        code = generate_phone_verification_code(self.user)
        
        # Test with SMS_VERIFICATION_ENABLED = False
        with patch('django.conf.settings.SMS_VERIFICATION_ENABLED', False):
            result = send_phone_verification(self.user)
        
        # Should return True even though no actual SMS is sent
        self.assertTrue(result)