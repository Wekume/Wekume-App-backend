from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from django.utils.translation import gettext_lazy as _
from django.utils.html import format_html
from .models import User, UserProfile


class UserProfileInline(admin.StackedInline):
    model = UserProfile
    can_delete = False
    verbose_name_plural = 'Profile'
    readonly_fields = ['profile_picture_preview']
    
    def profile_picture_preview(self, obj):
        if obj.profile_picture:
            return format_html('<img src="{}" width="150" height="150" style="object-fit: cover; border-radius: 50%;" />', obj.profile_picture.url)
        return "No picture uploaded"
    profile_picture_preview.short_description = 'Profile Picture Preview'


@admin.register(User)
class UserAdmin(BaseUserAdmin):
    inlines = (UserProfileInline,)
    list_display = ('email', 'phone', 'get_full_name', 'gender', 'age', 'school', 
                   'email_verified', 'phone_verified', 'is_staff', 'is_active')
    list_filter = ('is_staff', 'is_active', 'gender', 'email_verified', 'phone_verified')
    search_fields = ('email', 'phone', 'first_name', 'middle_name', 'last_name', 'school')
    ordering = ('email',)
    
    fieldsets = (
        (None, {'fields': ('email', 'phone', 'password')}),
        (_('Personal info'), {'fields': ('first_name', 'middle_name', 'last_name', 'gender', 'age', 'school')}),
        (_('Email Verification'), {'fields': ('email_verified', 'email_verification_token', 
                                   'email_verification_token_expires')}),
        (_('Phone Verification'), {'fields': ('phone_verified', 'phone_verification_token',
                                   'phone_verification_token_expires')}),
        (_('Password Reset'), {'fields': ('reset_token', 'reset_token_expires')}),
        (_('Permissions'), {'fields': ('is_active', 'is_staff', 'is_superuser',
                                       'groups', 'user_permissions')}),
        (_('Important dates'), {'fields': ('last_login', 'date_joined')}),
    )
    
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('email', 'phone', 'first_name', 'middle_name', 'last_name', 'gender', 'age', 'school', 'password1', 'password2'),
        }),
    )
    
    actions = ['mark_email_verified', 'mark_phone_verified', 'mark_email_unverified', 'mark_phone_unverified']
    
    def mark_email_verified(self, request, queryset):
        updated = queryset.update(email_verified=True, email_verification_token=None, email_verification_token_expires=None)
        self.message_user(request, f'{updated} users marked as email verified.')
    mark_email_verified.short_description = "Mark selected users as email verified"
    
    def mark_phone_verified(self, request, queryset):
        updated = queryset.update(phone_verified=True, phone_verification_token=None, phone_verification_token_expires=None)
        self.message_user(request, f'{updated} users marked as phone verified.')
    mark_phone_verified.short_description = "Mark selected users as phone verified"
    
    def mark_email_unverified(self, request, queryset):
        updated = queryset.update(email_verified=False)
        self.message_user(request, f'{updated} users marked as email unverified.')
    mark_email_unverified.short_description = "Mark selected users as email unverified"
    
    def mark_phone_unverified(self, request, queryset):
        updated = queryset.update(phone_verified=False)
        self.message_user(request, f'{updated} users marked as phone unverified.')
    mark_phone_unverified.short_description = "Mark selected users as phone unverified"


class HasProfilePictureFilter(admin.SimpleListFilter):
    title = _('Profile Picture')
    parameter_name = 'has_picture'
    
    def lookups(self, request, model_admin):
        return (
            ('yes', _('Has Picture')),
            ('no', _('No Picture')),
        )
    
    def queryset(self, request, queryset):
        if self.value() == 'yes':
            return queryset.exclude(profile_picture='')
        if self.value() == 'no':
            return queryset.filter(profile_picture='')


@admin.register(UserProfile)
class UserProfileAdmin(admin.ModelAdmin):
    list_display = ('user', 'get_user_name', 'get_user_email', 'has_profile_picture', 'bio_preview')
    search_fields = ('user__first_name', 'user__last_name', 'user__email', 'bio')
    list_filter = ('user__gender', 'user__email_verified', HasProfilePictureFilter)
    readonly_fields = ['profile_picture_preview']
    
    def get_user_name(self, obj):
        return obj.user.get_full_name()
    get_user_name.short_description = 'Name'
    get_user_name.admin_order_field = 'user__first_name'
    
    def get_user_email(self, obj):
        return obj.user.email
    get_user_email.short_description = 'Email'
    get_user_email.admin_order_field = 'user__email'
    
    def has_profile_picture(self, obj):
        return bool(obj.profile_picture)
    has_profile_picture.boolean = True
    has_profile_picture.short_description = 'Has Picture'
    
    def bio_preview(self, obj):
        if obj.bio:
            return obj.bio[:50] + '...' if len(obj.bio) > 50 else obj.bio
        return '-'
    bio_preview.short_description = 'Bio Preview'
    
    def profile_picture_preview(self, obj):
        if obj.profile_picture:
            return format_html('<img src="{}" width="300" height="300" style="object-fit: cover;" />', obj.profile_picture.url)
        return "No picture uploaded"
    profile_picture_preview.short_description = 'Profile Picture Preview'
    
    fieldsets = (
        (None, {'fields': ('user',)}),
        (_('Profile Information'), {'fields': ('bio', 'profile_picture', 'profile_picture_preview')}),
    )
    
    # Make the user field read-only when editing (but not when adding)
    def get_readonly_fields(self, request, obj=None):
        if obj:  # editing an existing object
            return ('user', 'profile_picture_preview')
        return ('profile_picture_preview',)