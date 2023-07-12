from django import forms
from .models import CustomUser

class RegistrationForm(forms.ModelForm):   
    password = forms.CharField(widget=forms.PasswordInput(attrs={
        'placeholder' : 'Enter password'
    }))
    confirm_password = forms.CharField(widget=forms.PasswordInput(attrs={
        'placeholder' : 'Confirm password'
    }))
    class Meta:
        model = CustomUser
        fields = ('first_name', 'last_name', 'email', 'phone',  'password')
    
    def clean(self):
        cleaned_data =super(RegistrationForm, self).clean()
        password = cleaned_data.get('password')
        confirm_password = cleaned_data.get('confirm_password')
        if password != confirm_password:
            raise forms.ValidationError(
                'Password does not match'
            )
        
    def __init__(self, *args, **kwargs):
        super(RegistrationForm, self).__init__(*args, **kwargs)
        self.fields['first_name'].widget.attrs['placeholder'] = 'Enter First Name'
        self.fields['last_name'].widget.attrs['placeholder'] = 'Enter Last Name'
        self.fields['email'].widget.attrs['placeholder'] = 'abc@example.com'
        self.fields['phone'].widget.attrs['placeholder'] = '+88017XXXXXXXX'
        for field in self.fields:
            self.fields[field].widget.attrs['class'] = 'form-control'
    
