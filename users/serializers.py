from rest_framework import serializers
from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password
from .models import UserProfile
from django.conf import settings

User = get_user_model()


class UserProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserProfile
        fields = ['profile_picture', 'bio']


class UserProfileUpdateSerializer(serializers.ModelSerializer):
    """
    Serializer for updating user profile information
    """
    class Meta:
        model = UserProfile
        fields = ['profile_picture', 'bio']
        

class UserSerializer(serializers.ModelSerializer):
    profile = UserProfileSerializer(read_only=True)
    full_name = serializers.SerializerMethodField()
    
    class Meta:
        model = User
        fields = ['id', 'email', 'phone', 'first_name', 'middle_name', 'last_name', 'full_name', 'gender', 'age', 'school', 'profile']
        read_only_fields = ['id']
    
    def get_full_name(self, obj):
        return obj.get_full_name()



class UserUpdateSerializer(serializers.ModelSerializer):
    """
    Serializer for updating user information
    """
    class Meta:
        model = User
        fields = ['first_name', 'middle_name', 'last_name', 'gender', 'age', 'school', 'email', 'phone']
        read_only_fields = []  # Allow all fields to be updated
    
    def validate_gender(self, value):
        """
        Validate gender field case-insensitively
        """
        valid_genders = ['male', 'female', 'other']
        if value.lower() not in valid_genders:
            raise serializers.ValidationError(f"Gender must be one of: {', '.join(valid_genders)} (case insensitive)")
        
        # Convert to proper case for consistency in database
        gender_mapping = {
            'male': 'Male',
            'female': 'Female',
            'other': 'Other'
        }
        return gender_mapping[value.lower()]
    
    def validate(self, data):
        """
        Validate that email and phone don't conflict with existing users
        """
        email = data.get('email')
        phone = data.get('phone')
        
        # Get the current user from the context if available
        request = self.context.get('request')
        if not request or not hasattr(request, 'user'):
            # If no request in context, we can't validate against the current user
            return data
            
        user = request.user
        
        # Check if email is being updated and is not blank
        if email and email != user.email:
            # Check if another user has this email
            if User.objects.filter(email=email).exclude(id=user.id).exists():
                raise serializers.ValidationError({"email": "This email is already in use."})
            
            # Mark email as unverified if it's changed
            data['email_verified'] = False
        
        # Check if phone is being updated and is not blank
        if phone and phone != user.phone:
            # Check if another user has this phone
            if User.objects.filter(phone=phone).exclude(id=user.id).exists():
                raise serializers.ValidationError({"phone": "This phone number is already in use."})
            
            # Mark phone as unverified if it's changed
            data['phone_verified'] = False
        
        return data
class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, required=True, validators=[validate_password])
    password2 = serializers.CharField(write_only=True, required=True)
    
    class Meta:
        model = User
        fields = ['email', 'phone', 'first_name', 'middle_name', 'last_name', 'gender', 'age', 'school', 'password', 'password2']
    
    def validate(self, attrs):
        if attrs['password'] != attrs['password2']:
            raise serializers.ValidationError({"password": "Password fields didn't match."})
        
        # Ensure either email or phone is provided
        if not attrs.get('email') and not attrs.get('phone'):
            raise serializers.ValidationError({"email_phone": "Either email or phone must be provided."})
        
        # Convert empty strings to None for unique fields
        if attrs.get('email') == '':
            attrs['email'] = None
        if attrs.get('phone') == '':
            attrs['phone'] = None
            
        return attrs
    
    def create(self, validated_data):
    # Remove password2 from the data
        validated_data.pop('password2', None)
        
        # If phone is provided and SMS verification is enabled, set phone_verification_required to True
        if validated_data.get('phone') and getattr(settings, 'SMS_VERIFICATION_ENABLED', False):
            validated_data['phone_verification_required'] = True
        elif validated_data.get('phone'):
            # If SMS verification is disabled, mark phone as verified automatically
            validated_data['phone_verified'] = True
            validated_data['phone_verification_required'] = False
        
        user = User.objects.create_user(**validated_data)
        return user


class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField(required=False, allow_blank=True)
    phone = serializers.CharField(required=False, allow_blank=True)
    password = serializers.CharField(required=True)
    
    def validate(self, attrs):
        email = attrs.get('email')
        phone = attrs.get('phone')
        
        if not email and not phone:
            raise serializers.ValidationError("Either email or phone must be provided.")
        
        # Convert empty strings to None
        if email == '':
            attrs['email'] = None
        if phone == '':
            attrs['phone'] = None
            
        return attrs


class PasswordResetRequestSerializer(serializers.Serializer):
    email_or_phone = serializers.CharField(required=True)


class PasswordResetConfirmSerializer(serializers.Serializer):
    token = serializers.CharField(required=True)
    new_password = serializers.CharField(required=True, validators=[validate_password])
    confirm_password = serializers.CharField(required=True)
    
    def validate(self, attrs):
        if attrs['new_password'] != attrs['confirm_password']:
            raise serializers.ValidationError({"password": "Password fields didn't match."})
        return attrs


class EmailVerificationSerializer(serializers.Serializer):
    """
    Serializer for email verification
    """
    token = serializers.CharField(required=False)
    email = serializers.EmailField(required=False)
    
    def validate(self, attrs):
        # For token verification, we need a token
        if self.context.get('request') and (
            self.context['request'].method == 'GET' or 
            getattr(self.context['request'], 'path', '').endswith('verify_email/')
        ):
            if not attrs.get('token'):
                raise serializers.ValidationError({"token": "Token is required for email verification."})
        
        # For resending verification, we need an email
        # CHANGE THIS LINE: 'resend_verification/' to 'resend/'
        if self.context.get('request') and getattr(self.context['request'], 'path', '').endswith('resend/'):
            if not attrs.get('email'):
                raise serializers.ValidationError({"email": "Email is required to resend verification."})
        
        return attrs
    
    
    
class GoogleAuthSerializer(serializers.Serializer):
    token = serializers.CharField(required=True)
    
class PhoneVerificationSerializer(serializers.Serializer):
    """
    Serializer for phone verification
    """
    code = serializers.CharField(required=False)
    phone = serializers.CharField(required=False)
    
    def validate(self, attrs):
        # For confirming verification, we need a code
        if self.context.get('request') and getattr(self.context['request'], 'path', '').endswith('confirm/'):
            if not attrs.get('code'):
                raise serializers.ValidationError({"code": "Verification code is required."})
        
        # For requesting verification, we need a phone number
        if self.context.get('request') and getattr(self.context['request'], 'path', '').endswith('request/'):
            if not attrs.get('phone'):
                raise serializers.ValidationError({"phone": "Phone number is required to send verification."})
        
        return attrs
