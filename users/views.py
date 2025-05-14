from django.shortcuts import render

def password_reset_form(request):
    """
    View to render the password reset form
    """
    token = request.GET.get('token', '')
    return render(request, 'password_reset_form.html', {'token': token})