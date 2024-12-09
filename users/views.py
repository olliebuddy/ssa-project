from django.shortcuts import render, redirect
from django.http import HttpResponseRedirect
from django.urls import reverse
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from .forms import UserRegistrationForm,TopUpForm
from .models import Transaction
import requests
from django.conf import settings

def login_view(request):
    if request.method == "POST":
        username = request.POST.get("username")
        password = request.POST.get("password")
        recaptcha_response = request.POST.get("recaptcha-token")  # Updated
        # Verify reCAPTCHA
        data = {
            'secret': settings.RECAPTCHA_SECRET_KEY,
            'response': recaptcha_response,
            'remoteip': request.META.get('REMOTE_ADDR'),
        }
        recaptcha_verification = requests.post(
            "https://www.google.com/recaptcha/api/siteverify",
            data=data
        )
        result = recaptcha_verification.json()
        # Check reCAPTCHA response
        if not result.get("success"):
            messages.error(request, "reCAPTCHA validation failed. Please try again.")
            return redirect("users:login")  # Redirect back to the login page
        # Authenticate user if reCAPTCHA is valid
        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)
            # Redirect to the next URL if provided, else default to user profile
            next_url = request.GET.get('next', reverse("users:user"))  # Simplified fallback
            return redirect(next_url)
        else:
            messages.error(request, "Invalid username or password.")
    return render(request, "users/login.html")

def register(request):
    if request.method == "POST":
        form = UserRegistrationForm(request.POST)
        if form.is_valid():
            user = form.save()
            messages.success(request, "Your account has been created!  Please set up multi-factor authentication.")
            return redirect('users:login')
    else:
        form = UserRegistrationForm()
    return render(request, 'users/register.html', {'form': form})

def user_view(request):
    profile = request.user.profile  # Get the logged-in user's profile
    return render(request, 'users/user.html', {'balance': profile.balance})

@login_required(login_url='users:login')
def user(request):
    profile = request.user.profile
    transactions = Transaction.objects.all().filter(user=request.user).order_by('-created_at')
    return render(request, 'users/user.html', {
        'user': request.user,
        'balance': profile.balance,
        'transactions': transactions
    })

def login_view(request):
    if request.method == "POST":
        username = request.POST["username"]
        password = request.POST["password"]
        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)
            next_url = request.GET.get('next', reverse("users:user"))
            return HttpResponseRedirect(next_url)
        else:
            messages.error(request, "Invalid Credentials.")
    return render(request, "users/login.html")

def logout_view(request):
    logout(request)
    messages.success(request, "Successfully logged out.")
    return redirect('users:login')

@login_required
def top_up(request):
    profile = request.user.profile 

    if request.method == 'POST':
        form = TopUpForm(request.POST)
        if form.is_valid():
            amount = form.cleaned_data['amount']
            profile.balance +=amount #add valid transaction money to account
            profile.save()
            Transaction.objects.create(user=request.user, amount=amount) # transaction record
            messages.success(request, f"Your balance has been topped up by ${amount}.")
            return redirect('users:user') # redirect to user page
    else:
        form = TopUpForm()
    context = {
        'form': form,
        'user_balance': request.user.profile.balance,
        'welcome_message': f"Welcome back, {request.user.first_name}!",
    }
    return render(request, 'users/top_up.html', context)
