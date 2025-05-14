from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static
from users.views import password_reset_form 
from django.contrib.auth import get_user_model
from django.views.decorators.csrf import csrf_exempt
from django.http import HttpResponse

User = get_user_model()

@csrf_exempt
def create_superuser(request):
    if request.method == 'POST' and request.GET.get('secret') == '9_-9%yj+39yevb)4lx_w-^!&l&bn+*f(54+r#lte_b9x=m5^xv':
        if not User.objects.filter(email='admin@example.com').exists():
            User.objects.create_superuser(
                email='admin@wekume.app',
                password='joshuarandy',  # Change this to a strong password
                first_name='Admin',
                last_name='User',
                gender='Other',
                age=30,
                school='Admin School'
            )
            return HttpResponse('Superuser created successfully')
        else:
            return HttpResponse('Superuser already exists')
    return HttpResponse('Unauthorized', status=401)

urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/', include('users.urls')),
    path('reset-password/', password_reset_form, name='password_reset_form'),
    path('create-superuser/', create_superuser, name='create_superuser'),
    # Add other app URLs here as you develop them
]

# Serve media files in development
if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)