from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static
from users.views import password_reset_form 

urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/', include('users.urls')),
    path('reset-password/', password_reset_form, name='password_reset_form'),
    # Add other app URLs here as you develop them
]

# Serve media files in development
if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)