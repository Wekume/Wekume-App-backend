from django.db.models.signals import post_save, pre_save
from django.dispatch import receiver
from .models import User, UserProfile


@receiver(pre_save, sender=User)
def convert_empty_to_null(sender, instance, **kwargs):
    """
    Convert empty strings to None for unique fields that allow null values.
    This prevents unique constraint violations with empty strings.
    """
    if instance.phone == '':
        instance.phone = None
    if instance.email == '':
        instance.email = None


@receiver(post_save, sender=User)
def create_user_profile(sender, instance, created, **kwargs):
    """
    Create a UserProfile for each new User.
    """
    if created:
        UserProfile.objects.create(user=instance)


@receiver(post_save, sender=User)
def save_user_profile(sender, instance, **kwargs):
    """
    Save the UserProfile when the User is saved.
    """
    # Add a safety check to prevent errors if profile doesn't exist
    try:
        instance.profile.save()
    except UserProfile.DoesNotExist:
        # Create profile if it doesn't exist
        UserProfile.objects.create(user=instance)