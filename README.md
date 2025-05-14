Wekume Backend


Overview


Wekume is a comprehensive healthcare platform designed for university students, providing authentication, profile management, medical services, and community features. This API serves as the backend for the Wekume initiative, handling user authentication, profile management, and various healthcare-related functionalities.

Features
Implemented
User Authentication

Registration with email or phone
JWT-based authentication
Password reset functionality
Email verification
Google OAuth integration
User Profile Management

Profile creation and updates
Profile picture upload
User information management
Security

Password hashing and validation
Token-based authentication
Secure email verification
In Progress
SMS verification for phone numbers (awaiting Africa's Talking credentials)
Coming Soon
Online shop for medical supplies
Safe chat for consultations
Appointment booking
Medical tips blog
ARV delivery service
Push notifications
AI-powered symptom checker
Tech Stack
Framework: Django with Django REST Framework
Authentication: JWT (Simple JWT)
Database: PostgreSQL
Email: SMTP integration
File Storage: Local storage (with cloud storage option)
Documentation: Auto-generated API docs
Testing: Django Test Framework
Installation
Prerequisites
Python 3.9+
PostgreSQL
Virtual environment tool (recommended)
Setup
Clone the repository
git clone https://github.com/your-organization/wekume-backend.git
cd wekume-backend

python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
cd wekume-app

pip install -r requirements.txt
pip install -r requirements.txt

# Django Settings
SECRET_KEY=your_secret_key
DEBUG=True
ALLOWED_HOSTS=localhost,127.0.0.1

# Database Settings
DATABASE_NAME=wekume_db
DATABASE_USER=postgres
DATABASE_PASSWORD=your_password

# Email Settings
EMAIL_BACKEND=django.core.mail.backends.smtp.EmailBackend
EMAIL_HOST=mail.wekume.app
EMAIL_PORT=465
EMAIL_USE_SSL=True
EMAIL_HOST_USER=admin@wekume.app
EMAIL_HOST_PASSWORD=your_email_password
DEFAULT_FROM_EMAIL=Wekume <admin@wekume.app>

# Site URL for email verification links
SITE_URL=http://localhost:8000

# Google OAuth
GOOGLE_CLIENT_ID=your_google_client_id
python manage.py migrate
python manage.py createsuperuser
python manage.py runserver


```markdown project="Wekume API" file="README.md"
...
```

2. **Create and activate a virtual environment**

```shellscript
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```


3. **Install dependencies**

```shellscript
pip install -r requirements.txt
```


4. **Set up environment variables**
Create a `.env` file in the project root with the following variables:

```plaintext
# Django Settings
SECRET_KEY=your_secret_key
DEBUG=True
ALLOWED_HOSTS=localhost,127.0.0.1

# Database Settings
DATABASE_NAME=wekume_db
DATABASE_USER=postgres
DATABASE_PASSWORD=your_password

# Email Settings
EMAIL_BACKEND=django.core.mail.backends.smtp.EmailBackend
EMAIL_HOST=mail.wekume.app
EMAIL_PORT=465
EMAIL_USE_SSL=True
EMAIL_HOST_USER=admin@wekume.app
EMAIL_HOST_PASSWORD=your_email_password
DEFAULT_FROM_EMAIL=Wekume <admin@wekume.app>

# Site URL for email verification links
SITE_URL=http://localhost:8000

# Google OAuth
GOOGLE_CLIENT_ID=your_google_client_id
```


5. **Run migrations**

```shellscript
python manage.py migrate
```


6. **Create a superuser**

```shellscript
python manage.py createsuperuser
```


7. **Run the development server**

```shellscript
python manage.py runserver
```



## API Documentation

### Authentication Endpoints

| Endpoint | Method | Description | Request Body | Response
|-----|-----|-----|-----|-----
| `/api/register/` | POST | Register a new user | `email/phone, first_name, middle_name, last_name, gender, age, school, password, password2` | User data with tokens
| `/api/login/` | POST | Login a user | `email/phone, password` | User data with tokens
| `/api/verify-email/{token}/` | GET | Verify email address | - | Success message
| `/api/verify-email/resend/` | POST | Resend verification email | `email` | Success message
| `/api/password-reset-request/` | POST | Request password reset | `email_or_phone` | Success message
| `/api/password-reset-confirm/` | POST | Confirm password reset | `token, new_password, confirm_password` | Success message
| `/api/token/refresh/` | POST | Refresh access token | `refresh` | New access token
| `/api/google-auth/` | POST | Google authentication | `token` | User data with tokens


### User Profile Endpoints

| Endpoint | Method | Description | Request Body | Response
|-----|-----|-----|-----|-----
| `/api/users/me/` | GET | Get current user | - | User data
| `/api/profile/me/` | GET | Get user profile | - | Profile data
| `/api/profile/update_profile/` | PATCH | Update profile | `bio` | Updated profile
| `/api/profile/update_user/` | PATCH | Update user info | `first_name, middle_name, last_name, gender, age, school` | Updated user data
| `/api/profile/upload_picture/` | POST | Upload profile picture | `profile_picture` (file) | Updated profile


## Project Structure

```
wekume_backend/
├── manage.py                # Django management script
├── wekume/                  # Main project folder
│   ├── **init**.py
│   ├── asgi.py              # ASGI config for async support
│   ├── settings.py          # Project settings
│   ├── urls.py              # Main URL routing
│   └── wsgi.py              # WSGI config for deployment
│
├── users/                   # Authentication app
│   ├── **init**.py
│   ├── admin.py             # Admin panel configuration
│   ├── apps.py              # App configuration
│   ├── migrations/          # Database migrations
│   ├── models.py            # User model and profile
│   ├── serializers.py       # DRF serializers
│   ├── viewsets.py          # API viewsets
│   ├── urls.py              # Auth URL routes
│   ├── utils.py             # Utility functions
│   └── tests.py             # Tests for auth
│
├── api/                     # Core API app
│   ├── **init**.py
│   ├── admin.py
│   ├── apps.py
│   ├── migrations/
│   ├── models.py            # Shared models
│   ├── urls.py              # API URL routing
│   ├── views.py             # Shared views
│   └── tests.py
│
├── shop/                    # Online shop app (coming soon)
│   ├── **init**.py
│   ├── admin.py
│   ├── apps.py
│   ├── migrations/
│   ├── models.py            # Product models
│   ├── serializers.py
│   ├── urls.py
│   ├── views.py
│   └── tests.py
│
├── chat/                    # Safe chat app (coming soon)
│   ├── **init**.py
│   ├── admin.py
│   ├── apps.py
│   ├── migrations/
│   ├── models.py            # Chat models
│   ├── serializers.py
│   ├── urls.py
│   ├── views.py
│   └── tests.py
│
├── appointments/            # Appointment booking app (coming soon)
│   ├── **init**.py
│   ├── admin.py
│   ├── apps.py
│   ├── migrations/
│   ├── models.py            # Appointment models
│   ├── serializers.py
│   ├── urls.py
│   ├── views.py
│   └── tests.py
│
├── blog/                    # Medical tips blog app (coming soon)
│   ├── **init**.py
│   ├── admin.py
│   ├── apps.py
│   ├── migrations/
│   ├── models.py            # Article models
│   ├── serializers.py
│   ├── urls.py
│   ├── views.py
│   └── tests.py
│
├── delivery/                # ARV delivery app (coming soon)
│   ├── **init**.py
│   ├── admin.py
│   ├── apps.py
│   ├── migrations/
│   ├── models.py            # Delivery models
│   ├── serializers.py
│   ├── urls.py
│   ├── views.py
│   └── tests.py
│
├── notifications/           # Push notifications app (coming soon)
│   ├── **init**.py
│   ├── admin.py
│   ├── apps.py
│   ├── migrations/
│   ├── models.py            # Notification models
│   ├── serializers.py
│   ├── urls.py
│   ├── views.py
│   └── tests.py
│
├── ai_services/             # AI symptom checker app (coming soon)
│   ├── **init**.py
│   ├── admin.py
│   ├── apps.py
│   ├── migrations/
│   ├── models.py
│   ├── serializers.py
│   ├── urls.py
│   ├── views.py
│   └── tests.py
│
├── utils/                   # Utility functions
│   ├── **init**.py
│   ├── validators.py
│   ├── helpers.py
│   └── middleware.py
│
├── static/                  # Static files
├── media/                   # User-uploaded files
├── templates/               # HTML templates (for emails)
├── requirements.txt         # Project dependencies
├── .env                     # Environment variables
└── README.md                # Project documentation
```

## Current Development Status

- ✅ **Users App**: Complete (awaiting SMS verification credentials)
- 🔄 **API App**: In progress
- 🔜 **Other Apps**: Planned for future development


## Testing

Run the test suite with:

```shellscript
python manage.py test
```
