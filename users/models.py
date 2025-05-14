from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.utils import timezone

class CustomUserManager(BaseUserManager):
    """
    Custom user manager where email or phone is the unique identifier
    for authentication instead of usernames.
    """
    def create_user(self, email=None, phone=None, password=None, **extra_fields):
        """
        Create and save a user with the given email/phone and password.
        """
        if not email and not phone:
            raise ValueError('Users must have either an email address or phone number')
        
        if email:
            email = self.normalize_email(email)
        
        user = self.model(
            email=email,
            phone=phone,
            **extra_fields
        )
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email=None, phone=None, password=None, **extra_fields):
        """
        Create and save a SuperUser with the given email/phone and password.
        """
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('is_active', True)

        if extra_fields.get('is_staff') is not True:
            raise ValueError('Superuser must have is_staff=True.')
        if extra_fields.get('is_superuser') is not True:
            raise ValueError('Superuser must have is_superuser=True.')
        
        return self.create_user(email, phone, password, **extra_fields)


class User(AbstractBaseUser, PermissionsMixin):
    """
    Custom User model that supports using email or phone as the username field.
    """
    email = models.EmailField('email address', unique=True, null=True, blank=True)
    phone = models.CharField(max_length=20, unique=True, null=True, blank=True)
    phone_verification_required = models.BooleanField(default=True)
    
    # Replace name with first_name, middle_name, last_name
    first_name = models.CharField(max_length=100)
    middle_name = models.CharField(max_length=100, blank=True, null=True)
    last_name = models.CharField(max_length=100)
    gender = models.CharField(max_length=10, choices=[
        ('Male', 'Male'),
        ('Female', 'Female'),
        ('Other', 'Other')
    ])
    
    age = models.PositiveIntegerField()
    school = models.CharField(max_length=255)
    
    # Rest of your model remains the same
    is_staff = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)
    date_joined = models.DateTimeField(default=timezone.now)
    
    # Fields for password reset
    reset_token = models.CharField(max_length=100, null=True, blank=True)
    reset_token_expires = models.DateTimeField(null=True, blank=True)
    
    # Fields for email verification
    email_verified = models.BooleanField(default=False)
    email_verification_token = models.CharField(max_length=100, null=True, blank=True)
    email_verification_token_expires = models.DateTimeField(null=True, blank=True)
    
    # Fields for phone verification (if needed in the future)
    phone_verified = models.BooleanField(default=False)
    phone_verification_token = models.CharField(max_length=100, null=True, blank=True)
    phone_verification_token_expires = models.DateTimeField(null=True, blank=True)
    
    USERNAME_FIELD = 'email'  # This is used for login
    # Update REQUIRED_FIELDS to use first_name and last_name instead of name
    REQUIRED_FIELDS = ['first_name', 'last_name', 'gender', 'age', 'school']
    
    objects = CustomUserManager()
    
    @property
    def name(self):
        """Compatibility property for code that still uses user.name"""
        return self.get_full_name()
    
    def __str__(self):
        if self.email:
            return self.email
        elif self.phone:
            return self.phone
        return self.get_full_name()
    
    def get_full_name(self):
        if self.middle_name:
            return f"{self.first_name} {self.middle_name} {self.last_name}"
        return f"{self.first_name} {self.last_name}"
    
    def get_short_name(self):
        return self.first_name


class UserProfile(models.Model):
    """
    Extended profile information for users.
    """
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='profile')
    profile_picture = models.ImageField(upload_to='profile_pics/', null=True, blank=True)
    bio = models.TextField(null=True, blank=True)
    
    # You can add more profile fields here
    
    def __str__(self):
        return f"{self.user}'s profile"


# Move UserSession after User is defined
class UserSession(models.Model):
    """
    Model to track user sessions across devices
    """
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='sessions')
    session_id = models.CharField(max_length=255, unique=True)  # Store the JWT jti claim
    device_info = models.CharField(max_length=255, blank=True, null=True)
    ip_address = models.GenericIPAddressField(blank=True, null=True, protocol='both', unpack_ipv4=False)
    last_activity = models.DateTimeField(auto_now=True)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['-created_at']
    
    def __str__(self):
        return f"{self.user} - {self.device_info} - {self.created_at}"