from django.shortcuts import render, redirect
from .forms import RegistrationForm
from .models import CustomUser
from django.http import HttpResponse
from django.contrib import messages, auth
from django.contrib.sites.shortcuts import get_current_site  
from django.utils.encoding import force_bytes 
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode  
from django.template.loader import render_to_string  
from django.contrib.auth.tokens import default_token_generator
from django.contrib.auth.models import User  
from django.core.mail import EmailMessage  

# Create your views here.
def register(request):
    if request.method == 'POST':
        form = RegistrationForm(request.POST)
        if form.is_valid():
            frist_name = form.cleaned_data['first_name']
            last_name = form.cleaned_data['last_name']
            email = form.cleaned_data['email']
            phone = form.cleaned_data['phone']
            passwors = form.cleaned_data['password']
            username = email.split("@")[0]
            user = CustomUser.objects.create_user(email = email, first_name = frist_name, last_name = last_name, username=username)
            user.phone = phone
            user.save()
            
            #ACCOUNT VARIFICATION
            current_site = get_current_site(request)
            mail_subject = 'Activation link has been sent to your email id'  
            message = render_to_string('accounts/acc_active_email.html', {  
                'user': user,  
                'domain': current_site, 
                'uid':urlsafe_base64_encode(force_bytes(user.pk)),  
                'token':default_token_generator.make_token(user),  
            })  
            to_email = email 
            email = EmailMessage(mail_subject, message, to=[to_email])  
            email.send()
            return redirect('/account/login/?command=verification&email='+(str(email)))
    else:
        form = RegistrationForm()
    context = {
        'form':form
    }
    return render(request, 'accounts/register.html', context)

def login(request):
    if request.method == 'POST':
        email = request.POST['email']
        password = request.POST['password']
        user = auth.authenticate(email=email, password=password)
        if user is not None:
            auth.login(request, user)
            return redirect('home')
        else:
            messages.error(request, 'email or password is incorrect')
    return render(request, 'accounts/login.html')
def logout(request):
    auth.logout(request)
    messages.success(request, 'You are logged out')
    return redirect('login')
def activate(request, uidb64, token):
    try:  
        uid = urlsafe_base64_decode(uidb64).decode()
        user = CustomUser._default_manager.get(pk=uid)
    
    except(TabError, ValueError, OverflowError, CustomUser.DoesNotExist):
        user=None
    if user is not None and default_token_generator.check_token(user, token):
        user.is_active = True
        user.save()
        messages.success(request, "Congratulaions! Your account is activated.")
        return redirect('login')
    else:
        messages.error(request, "Inavlid Activation Link")
        return redirect('register')
    
def dashboard(request):
    return render(request, 'accounts/dashboard.html')

def forgotPassword(request):
    if request.method == 'POST':
        email = request.POST['email']
        if CustomUser.objects.filter(email=email).exists():
            user = CustomUser.objects.get(email__exact = email)
            
            #reset password
            current_site = get_current_site(request)
            mail_subject = 'Password reset link has been sent to your email id'  
            message = render_to_string('accounts/reset_password_email.html', {  
                'user': user,  
                'domain': current_site, 
                'uid':urlsafe_base64_encode(force_bytes(user.pk)),  
                'token':default_token_generator.make_token(user),  
            })  
            to_email = email 
            email = EmailMessage(mail_subject, message, to=[to_email])  
            email.send()
            messages.success(request, "Password reset email has been sent to your email ")
            return redirect('login')
        else:
            messages.error(request, "Account doesn't exist")
            
    return render(request, "accounts/forgotPassword.html")

def resetpassword_validate(request):
    try:  
        uid = urlsafe_base64_decode(uidb64).decode()
        user = CustomUser._default_manager.get(pk=uid)
    
    except(TabError, ValueError, OverflowError, CustomUser.DoesNotExist):
        user=None
    if user is not None and default_token_generator.check_token(user, token):
        request.session['uid']=uid
        messages.success(request,'Please reset your password')
        return redirect('resetPassword')
    else:
        messages.error(request, 'The link has been expaired! Try again.')
        return redirect('login')
    
def resetPassword(request, uidb64, token):
    password = request.POST['password']
    confirm_password = request.POST['confirm_password']
    if password == confirm_password:
        uid = request.session.get('uid')
        user = CustomUser.objects.get(pk=uid)
        user.set_password(password)
        user.save()
        messages.success(request, "Your Password is reseted")
        return redirect('login')
    else:
        messages.error(request,"Password doesn't match")
        return redirect('resetPassword')
    return render(request, 'accounts/resetPassword.html')