from pathlib import Path
from decouple import Csv, config
from datetime import timedelta
import dj_database_url
import os

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent


# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/5.2/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = config('SECRET_KEY', cast=str)

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = config("DEBUG", default=False, cast=bool)

ALLOWED_HOSTS = config("ALLOWED_HOSTS", default="localhost,127.0.0.1,wekume-user-api.onrender.com", cast=Csv())

# Application definition

INSTALLED_APPS = [
    'users.apps.UsersConfig', # MOVED TO THE TOP
    'jazzmin',
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    
    # Third-party apps
    'rest_framework',
    'rest_framework_simplejwt.token_blacklist',
    'corsheaders',
    
    # Local apps
    'ai_services',
    'api',
    'appointments',
    'blog',
    'chat',
    'delivery',
    'notifications',
    'shop',
    'utils',
]


JAZZMIN_SETTINGS = {
    # UI Customization
    "site_title": "Wekume Admin",
    "site_header": "Wekume",
    "site_brand": "Wekume",
    "site_logo": None,  # Add your logo path here if you have one
    "welcome_sign": "Welcome to Wekume Admin",
    "copyright": "Wekume",
    
    # Top Menu
    "topmenu_links": [
        {"name": "Home", "url": "admin:index", "permissions": ["auth.view_user"]},
        {"name": "Site", "url": "/", "new_window": True},
    ],
    
    # User Menu
    "usermenu_links": [
        {"name": "Support", "url": "https://github.com/yourusername/wekume/issues", "new_window": True},
    ],
    
    # UI Tweaks
    "show_ui_builder": True,
    "changeform_format": "horizontal_tabs",
    "changeform_format_overrides": {
        "auth.user": "collapsible",
        "users.user": "collapsible",
    },
    
    # Custom CSS/JS for extra styling
    "custom_css": None,
    "custom_js": None,
    
    # Icons
    "icons": {
        "users.user": "fas fa-user",
        "users.userprofile": "fas fa-id-card",
        "auth.Group": "fas fa-users",
    },
    
    # Default theme
    "default_theme": "default",
}

# Optional UI builder
JAZZMIN_UI_TWEAKS = {
    "navbar_small_text": False,
    "footer_small_text": False,
    "body_small_text": False,
    "brand_small_text": False,
    "brand_colour": "navbar-primary",
    "accent": "accent-primary",
    "navbar": "navbar-dark",
    "no_navbar_border": False,
    "navbar_fixed": False,
    "layout_boxed": False,
    "footer_fixed": False,
    "sidebar_fixed": False,
    "sidebar": "sidebar-dark-primary",
    "sidebar_nav_small_text": False,
    "sidebar_disable_expand": False,
    "sidebar_nav_child_indent": False,
    "sidebar_nav_compact_style": False,
    "sidebar_nav_legacy_style": False,
    "sidebar_nav_flat_style": False,
    "theme": "default",
    "dark_mode_theme": None,
    "button_classes": {
        "primary": "btn-primary",
        "secondary": "btn-secondary",
        "info": "btn-info",
        "warning": "btn-warning",
        "danger": "btn-danger",
        "success": "btn-success"
    }
}

# Custom user model
AUTH_USER_MODEL = 'users.User'


REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': (
        'rest_framework_simplejwt.authentication.JWTAuthentication',
    ),
    'DEFAULT_PERMISSION_CLASSES': [
        'rest_framework.permissions.IsAuthenticated',
    ],
    
    'DEFAULT_RENDERER_CLASSES': [
        'rest_framework.renderers.JSONRenderer',
        'rest_framework.renderers.BrowsableAPIRenderer',  # This enables the browsable API forms
    ],
    # Your other REST_FRAMEWORK settings...
}


#JWT settings for long-lived tokens (30 days)
SIMPLE_JWT = {
    'ACCESS_TOKEN_LIFETIME': timedelta(hours=1),
    'REFRESH_TOKEN_LIFETIME': timedelta(days=7),
    'ROTATE_REFRESH_TOKENS': True,
    'BLACKLIST_AFTER_ROTATION': True,
    
}


# CORS_ALLOWED_ORIGINS = [
#     "http://localhost:3000",
#     "http://localhost:8000",
#     "https://wekume.onrender.com",  #
# ]

# Allow all origins for CORS (development only)
CORS_ALLOW_ALL_ORIGINS = True
CORS_ALLOW_CREDENTIALS = True  # If you need to support credentials


MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'corsheaders.middleware.CorsMiddleware', #cors settings
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

# Add Google OAuth settings
GOOGLE_CLIENT_ID = config('GOOGLE_CLIENT_ID')
GOOGLE_CLIENT_SECRET = config('GOOGLE_CLIENT_SECRET')

ROOT_URLCONF = 'wekume.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [os.path.join(BASE_DIR, 'templates')],  # Added templates directory
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'wekume.wsgi.application'


# Database
# https://docs.djangoproject.com/en/5.2/ref/settings/#databases


# Database configuration
# First check if DATABASE_URL is available (Render deployment)
database_url = os.environ.get('DATABASE_URL')
if database_url:
    # If DATABASE_URL exists, use it (Render environment)
    DATABASES = {
        'default': dj_database_url.parse(database_url)
    }
else:
    # Otherwise, use local configuration (development environment)
    DATABASES = {
        'default': {
            'ENGINE': 'django.db.backends.postgresql',
            'NAME': config('DATABASE_NAME', default='wekume'),
            'USER': config('DATABASE_USER', default='postgres'),
            'PASSWORD': config('DATABASE_PASSWORD', default=''),
            'HOST': config('DATABASE_HOST', default='localhost'),
            'PORT': config('DATABASE_PORT', default='5433'),
        }
    }
    
    
# DATABASES = {
#     'default': {
#         'ENGINE': 'django.db.backends.sqlite3',
#         'NAME': BASE_DIR / 'db.sqlite3',
#     }
# }


# Password validation
# https://docs.djangoproject.com/en/5.2/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]


# Internationalization
# https://docs.djangoproject.com/en/5.2/topics/i18n/

LANGUAGE_CODE = 'en-us'

TIME_ZONE = 'UTC'

USE_I18N = True

USE_TZ = True


# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/5.2/howto/static-files/

STATIC_URL = 'static/'
STATIC_ROOT = BASE_DIR / 'staticfiles'  

# Default primary key field type
# https://docs.djangoproject.com/en/5.2/ref/settings/#default-auto-field

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'


# Media files
MEDIA_URL = '/media/'
MEDIA_ROOT = BASE_DIR / 'media'

# Email settings
# Use environment variables for all email settings
EMAIL_BACKEND = config('EMAIL_BACKEND', default='django.core.mail.backends.smtp.EmailBackend')
EMAIL_HOST = config('EMAIL_HOST', default='mail.wekume.app')
EMAIL_PORT = config('EMAIL_PORT', default=465, cast=int)
EMAIL_USE_SSL = config('EMAIL_USE_SSL', default=True, cast=bool)
EMAIL_HOST_USER = config('EMAIL_HOST_USER', default='admin@wekume.app')
EMAIL_HOST_PASSWORD = config('EMAIL_HOST_PASSWORD', default='coconut-landfall-jiffy-varmint-transpose-aim')  # Added default
DEFAULT_FROM_EMAIL = config('DEFAULT_FROM_EMAIL', default='Wekume <admin@wekume.app>')


# Africa's Talking Configuration
AFRICAS_TALKING_USERNAME = config('AFRICAS_TALKING_USERNAME', default='wekume')
AFRICAS_TALKING_API_KEY = config('AFRICAS_TALKING_API_KEY', default='')
AFRICAS_TALKING_SENDER_ID = config('AFRICAS_TALKING_SENDER_ID', default='')
SMS_VERIFICATION_ENABLED = config('SMS_VERIFICATION_ENABLED', default=False, cast=bool)


# Use SITE_URL from environment or default to Render URL
SITE_URL = config('SITE_URL', default='https://wekume-user-api.onrender.com')




LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
        },
    },
    'loggers': {
        'django': {
            'handlers': ['console'],
            'level': 'INFO',
        },
        'users': {  # Your app name
            'handlers': ['console'],
            'level': 'DEBUG',
            'propagate': True,
        },
    },
}