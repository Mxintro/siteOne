from django import forms
from django.contrib import auth
from django.contrib.auth.models import User

class LoginForm(forms.Form):
    username = forms.CharField(label='用户名',
                                widget=forms.TextInput(attrs={'class':'form-control', 'placeholder':'请输入用户名'}))
    password = forms.CharField(label='密码',
                                widget=forms.PasswordInput(attrs={'class':'form-control', 'placeholder':'请输入密码'}))

    def clean(self):
        username = self.cleaned_data['username']#clean_data
        password = self.cleaned_data['password']

        user = auth.authenticate(username=username, password=password)
        if user is None:
            raise forms.ValidationError('用户名或密码不正确')
        else:
            self.cleaned_data['user'] = user
        return self.cleaned_data

class RegForm(forms.Form):
    username = forms.CharField(
        label='用户名',
        widget=forms.TextInput(
            attrs={'class':'form-control', 'placeholder':'请输入用户名'}
            )
        )
    email = forms.EmailField(
        label='邮箱',
        widget=forms.EmailInput(
            attrs={'class':'form-control', 'placeholder':'请输入邮箱'}
            )
        )
    verification_code = forms.CharField(
        label = '验证码',
        required=False,
        widget=forms.TextInput(
            attrs = {'class':'form-control','placeholder':'点击"发送验证码"获取验证码'}
            )

        )
    password = forms.CharField(
        label='密码',
        widget=forms.PasswordInput(
            attrs={'class':'form-control', 'placeholder':'请输入密码'}
            )
        )
    password_again = forms.CharField(
        label='密码',
        widget=forms.PasswordInput(
            attrs={'class':'form-control', 'placeholder':'请输入密码'}
            )
        )

    def __init__(self, *args, **kwargs):
        if 'request' in kwargs:
            self.request = kwargs.pop('request')
        super(RegForm,self).__init__(*args,**kwargs)


    def clean_username(self):
        username = self.cleaned_data['username']
        if User.objects.filter(username=username).exists():
            raise forms.ValidationError('用户已存在')
        return username

    def clean_email(self):
        email = self.cleaned_data['email']
        if User.objects.filter(email=email).exists():
            raise forms.ValidationError('邮箱已存在')
        return email

    def clean_password_again(self):
        password = self.cleaned_data['password']
        password_again = self.cleaned_data['password_again']
        if password != password_again:
            raise forms.ValidationError('两次输入的密码不一致')
        return password_again

    def clean_verification_code(self):
        verification_code = self.cleaned_data.get('verification_code','').strip()
        if verification_code == '':
            raise forms.ValidationError("验证码不能为空")
        code = self.request.session.get('register_code','')#
        if not (code != '' and code == verification_code):
            raise forms.ValidationError("验证码不正确")

        return verification_code

class ChangeNicknameForm(forms.Form):
    nickname_new = forms.CharField(
        label='新的昵称',
        max_length=20,
        widget=forms.TextInput(
            attrs={'class':'form-control', 'placeholder':'请输入新的昵称'}
            )
        )
    def __init__(self,*args, **kwargs):
        if 'user' in kwargs:
            self.user = kwargs.pop('user')
        super(ChangeNicknameForm, self).__init__(*args, **kwargs)

    def clean(self):
        if self.user.is_authenticated:
            self.cleaned_data['user'] = self.user
        else:
            raise forms.ValidationError("用户尚未登录")
        return self.cleaned_data

    def clean_nickname_new(self):
        nickname_new = self.cleaned_data.get('nickname_new', '').strip()
        if nickname_new == '':
            raise ValidationError("新的昵称不能为空")
        return nickname_new

class BindEmailForm(forms.Form):
    email = forms.EmailField(
        label = '邮箱',
        widget=forms.EmailInput(
            attrs={'class':'form-control','placeholder':'请输入邮箱'}
            )
        )

    verification_code = forms.CharField(
        label = '验证码',
        required=False,
        widget=forms.TextInput(
            attrs = {'class':'form-control','placeholder':"点击发送验证码"}
            )

        )

    def __init__(self, *args, **kwargs):
        if 'request' in kwargs:
            self.request = kwargs.pop('request')
        super(BindEmailForm,self).__init__(*args,**kwargs)

    def clean(self):
        if self.request.user.is_authenticated:
            self.cleaned_data['user'] = self.request
        else:
            raise forms.ValidationError("用户尚未登录")

        if self.request.user.email != '':
            raise forms.ValidationError("你已绑定邮箱")
        
        #获取网页验证码，判断是否正确
        code = self.request.session.get('bind_email_code','')#
        verification_code = self.cleaned_data.get('verification_code','')
        if not (code != '' and code == verification_code):
            raise forms.ValidationError("验证码不正确")

        return self.cleaned_data

    def clean_email(self):
        email = self.cleaned_data['email']
        if User.objects.filter(email=email).exists():
            raise forms.ValidationError("邮箱已被绑定")
        return email

    def clean_verification_code(self):
        verification_code = self.cleaned_data.get('verification_code','').strip()
        if verification_code == '':
            raise forms.ValidationError("验证码不能为空")

        return verification_code

class ChangePasswordForm(forms.Form):
    old_password = forms.CharField(
        label='输入就旧密码',
        widget=forms.PasswordInput(
            attrs={'class':'form-control', 'placeholder':'请输入密码'}
            )
        )
    new_password = forms.CharField(
        label='请输入新密码',
        widget=forms.PasswordInput(
            attrs={'class':'form-control', 'placeholder':'请输入新密码'}
            )
        )
    new_password_again = forms.CharField(
        label='请再次输入新密码',
        widget=forms.PasswordInput(
            attrs={'class':'form-control', 'placeholder':'请再次输入新密码密码'}
            )
        )
    def __init__(self, *args, **kwargs):
        if 'user' in kwargs:
            self.user = kwargs.pop('user')
        super(ChangePasswordForm,self).__init__(*args, **kwargs)

    #新密码是否一致
    def clean(self):
        new_password = self.cleaned_data.get('new_password','')
        new_password_again = self.cleaned_data.get('new_password_again','')
        if new_password != new_password_again or new_password == '':
            raise forms.ValidationError("两次输入的密码不一致")
        return self.cleaned_data

    def clean_old_password(self):
        old_password = self.cleaned_data.get('old_password','')
        if not self.user.check_password(old_password):
            raise forms.ValidationError("就密码错误")
        return old_password
               

class ForgotPasswordForm(forms.Form):
    email = forms.EmailField(
        label = '邮箱',
        widget=forms.EmailInput(
            attrs={'class':'form-control','placeholder':'请输入邮箱'}
            )
        )
    verification_code = forms.CharField(
        label = '验证码',
        required=False,
        widget=forms.TextInput(
            attrs = {'class':'form-control','placeholder':'点击"发送验证码"获取验证码'}
            )

        )
    new_password = forms.CharField(
        label='请输入新密码',
        widget=forms.PasswordInput(
            attrs={'class':'form-control', 'placeholder':'请输入新密码'}
            )
        )
    new_password_again = forms.CharField(
        label='请再次输入新密码',
        widget=forms.PasswordInput(
            attrs={'class':'form-control', 'placeholder':'请再次输入新密码'}
            )
        )
    def __init__(self, *args, **kwargs):
        if 'request' in kwargs:
            self.request = kwargs.pop('request')
        super(ForgotPasswordForm,self).__init__(*args, **kwargs)


    def clean_email(self):
        email = self.cleaned_data['email']
        if not User.objects.filter(email=email).exists():
            raise forms.ValidationError("不存在")
        return email

    #新密码是否一致
    def clean(self):
        new_password = self.cleaned_data.get('new_password','')
        new_password_again = self.cleaned_data.get('new_password_again','')
        if new_password != new_password_again or new_password == '':
            raise forms.ValidationError("两次输入的密码不一致")
        return self.cleaned_data

    def clean_verification_code(self):
        verification_code = self.cleaned_data.get('verification_code','').strip()
        if verification_code == '':
            raise forms.ValidationError("验证码不能为空")
        code = self.request.session.get('forgot_password_code','')#
        if not (code != '' and code == verification_code):
            raise forms.ValidationError("验证码不正确")

        return verification_code



