# models.py

from django.db import models
from django.contrib.auth.models import AbstractUser

class CustomUser(AbstractUser):
    address = models.CharField(max_length=255)
    phone_number = models.CharField(max_length=20)

class FinancialInfo(models.Model):
    user = models.OneToOneField(CustomUser, on_delete=models.CASCADE)
    credit_card_number = models.CharField(max_length=16)
    expiration_month = models.IntegerField()
    expiration_year = models.IntegerField()
    cvv = models.CharField(max_length=4)

    def __str__(self):
        return self.user.username
views.py
from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login
from django.contrib.auth.forms import AuthenticationForm, UserCreationForm
from django.contrib.auth.decorators import login_required
from .forms import FinancialInfoForm
from .models import CustomUser, FinancialInfo
import requests

def login_view(request):
    if request.method == 'POST':
        form = AuthenticationForm(request, data=request.POST)
        if form.is_valid():
            username = form.cleaned_data.get('username')
            password = form.cleaned_data.get('password')
            user = authenticate(username=username, password=password)
            if user is not None:
                login(request, user)
                return redirect('account')
    else:
        form = AuthenticationForm()
    return render(request, 'login.html', {'form': form})

@login_required
def account_view(request):
    user = request.user
    financial_info = FinancialInfo.objects.get(user=user)
    return render(request, 'account.html', {'user': user, 'financial_info': financial_info})

def register_view(request):
    if request.method == 'POST':
        user_form = UserCreationForm(request.POST)
        financial_form = FinancialInfoForm(request.POST)
        if user_form.is_valid() and financial_form.is_valid():
            user = user_form.save()
            financial_info = financial_form.save(commit=False)
            financial_info.user = user
            financial_info.save()

            # Payment integration with Visa
            amount = 100.0  # Example amount in USD
            currency = 'USD'
            card_number = financial_form.cleaned_data['credit_card_number']
            expiration_month = financial_form.cleaned_data['expiration_month']
            expiration_year = financial_form.cleaned_data['expiration_year']
            cvv = financial_form.cleaned_data['cvv']

            # Construct the API request payload
            payload = {
                'amount': amount,
                'currency': currency,
                'card_number': card_number,
                'expiration_month': expiration_month,
                'expiration_year': expiration_year,
                'cvv': cvv,
            }

            # Make a POST request to the Visa Direct API
            response = requests.post('https://api.visa.com/payments/v1/authorize', json=payload, headers={
                'Content-Type': 'application/json',
                'Authorization': 'Bearer YOUR_API_KEY',  # Replace with your API key
            })

            # Process the API response
            if response.status_code == 200:
                # Payment was successful
                transaction_id = response.json().get('transaction_id')
                # Save the transaction ID and complete the user registration
                # ...
                return render(request, 'registration_complete.html', {'transaction_id': transaction_id})
            else:
                # Payment failed
                error_message = response.json().get('error_message')
                return render(request, 'payment_error.html', {'error_message': error_message})

    else:
        user_form = UserCreationForm()
        financial_form = FinancialInfoForm()

    return render(request, 'register.html', {'user_form': user_form, 'financial_form': financial_form})

<!-- register.html -->

<!DOCTYPE html>
<html>
<head>
    <title>User Registration</title>
</head>
<body>
    <h1>User Registration</h1>
    <form method="POST">
        {% csrf_token %}
        
        {{ user_form.as_p }}

        <h2>Financial Information</h2>
        {{ financial_form.as_p }}

        <button type="submit">Register</button>
    </form>
</body>
</html>

# models.py

from django.db import models
from django.contrib.auth.models import AbstractUser

class CustomUser(AbstractUser):
    address = models.CharField(max_length=255)
    phone_number = models.CharField(max_length=20)

class FinancialInfo(models.Model):
    user = models.OneToOneField(CustomUser, on_delete=models.CASCADE)
    credit_card_number = models.CharField(max_length=16)
    expiration_month = models.IntegerField()
    expiration_year = models.IntegerField()
    cvv = models.CharField(max_length=4)

    def __str__(self):
        return self.user.username

# urls.py

from django.urls import path
from . import views

urlpatterns = [
    path('login/', views.login_view, name='login'),
    path('register/', views.register_view, name='register'),
    path('scan-ip/', views.scan_ip, name='scan_ip'),
    # ... other URLs
]
scan_ip

# views.py

from django.shortcuts import render, redirect
from django.contrib.auth.forms import AuthenticationForm, UserCreationForm
from django.contrib.auth.decorators import login_required
from django.contrib.auth import login, logout

@login_required(login_url='login')
def scan_ip(request):
    if request.method == 'POST':
        form = IPAddressForm(request.POST)
        if form.is_valid():
            ip_address = form.cleaned_data['ip_address']
            smb_scan = form.cleaned_data['smb_scan']
            smtp_scan = form.cleaned_data['smtp_scan']
            ssh_scan = form.cleaned_data['ssh_scan']
            http_scan = form.cleaned_data['http_scan']

            scan_output = ''

            if smb_scan:
                smb_result = subprocess.run(['bash', 'path/to/smb_scan_script.sh', ip_address],
                                            capture_output=True, text=True)
                scan_output += 'SMB Scan:\n' + smb_result.stdout + '\n\n'

            if smtp_scan:
                smtp_result = subprocess.run(['bash', 'path/to/smtp_scan_script.sh', ip_address],
                                             capture_output=True, text=True)
                scan_output += 'SMTP Scan:\n' + smtp_result.stdout + '\n\n'

            if ssh_scan:
                ssh_result = subprocess.run(['bash', 'path/to/ssh_scan_script.sh', ip_address],
                                            capture_output=True, text=True)
                scan_output += 'SSH Scan:\n' + ssh_result.stdout + '\n\n'

            if http_scan:
                http_result = subprocess.run(['bash', 'path/to/http_scan_script.sh', ip_address],
                                             capture_output=True, text=True)
                scan_output += 'HTTP Scan:\n' + http_result.stdout + '\n\n'

            return render(request, 'scan_result.html', {'scan_output': scan_output})
    else:
        form = IPAddressForm()

    return render(request, 'scan_ip.html', {'form': form})
<!-- base.html -->

<!DOCTYPE html>
<html>
<head>
    <title>IT Security System</title>
</head>
<body>
    {% if user.is_authenticated %}
        <p>Welcome, {{ user.username }}! <a href="{% url 'logout' %}">Logout</a></p>
    {% else %}
        <p><a href="{% url 'login' %}">Login</a> | <a href="{% url 'register' %}">Register</a></p>
    {% endif %}

    {% block content %}{% endblock %}
</body>
</html>


<!-- login.html -->

<!DOCTYPE html>
<html>
<head>
    <title>Login</title>
</head>
<body>
    <h1>Login</h1>
    <form method="POST">
        {% csrf_token %}
        
        {{ form.as_p }}
        
        <button type="submit">Login</button>
    </form>
</body>
</html>

<!-- account.html -->

<!DOCTYPE html>
<html>
<head>
    <title>Account</title>
</head>
<body>
    <h1>Welcome, {{ user.username }}</h1>
    <h2>Financial Information</h2>
    <p>Credit Card Number: {{ financial_info.credit_card_number }}</p>
    <p>Expiration Month: {{ financial_info.expiration_month }}</p>
    <p>Expiration Year: {{ financial_info.expiration_year }}</p>
    <p>CVV: {{ financial_info.cvv }}</p>
</body>
</html>

<!-- registration_complete.html -->

<!DOCTYPE html>
<html>
<head>
    <title>Registration Complete</title>
</head>
<body>
    <h1>Registration Complete</h1>
    <p>Thank you for registering!</p>
    <p>Transaction ID: {{ transaction_id }}</p>
</body>
</html>

<!-- payment_error.html -->

<!DOCTYPE html>
<html>
<head>
    <title>Payment Error</title>
</head>
<body>
    <h1>Payment Error</h1>
    <p>An error occurred during payment processing:</p>
    <p>{{ error_message }}</p>
</body>
</html>

<!-- scan_ip.html -->

<!DOCTYPE html>
<html>
<head>
    <title>IT Security System</title>
</head>
<body>
    <h1>Scan IP Address</h1>
    <form method="post">
        {% csrf_token %}
        {{ form }}
        <br>
        <label><input type="checkbox" name="smb_scan"> SMB</label><br>
        <label><input type="checkbox" name="smtp_scan"> SMTP</label><br>
        <label><input type="checkbox" name="ssh_scan"> SSH</label><br>
        <label><input type="checkbox" name="http_scan"> HTTP</label><br>
        <br>
        <button type="submit">Scan</button>
    </form>
</body>
</html>
# forms.py

from django import forms

class IPAddressForm(forms.Form):
    ip_address = forms.GenericIPAddressField()
    smb_scan = forms.BooleanField(required=False)
    smtp_scan = forms.BooleanField(required=False)
    ssh_scan = forms.BooleanField(required=False)
    http_scan = forms.BooleanField(required=False)
<!-- scan_result.html -->

<!DOCTYPE html>
<html>
<head>
    <title>IT Security System - Scan Result</title>
</head>
<body>
    <h1>Scan Result</h1>
    <pre>{{ scan_output }}</pre>
</body>
</html>
