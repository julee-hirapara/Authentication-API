from rest_framework import serializers
from django.contrib.auth.models import User
from django.utils.encoding import smart_str,force_bytes,DjangoUnicodeDecodeError
from xml.dom import ValidationErr
from django.utils.http import urlsafe_base64_decode,urlsafe_base64_encode
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from .utils import Util
from  auth import settings
from rest_framework_simplejwt.tokens import RefreshToken, TokenError

# user register serializer 
class UserRegisterSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['username', 'email', 'password']
        extra_kwargs = {'password': {'write_only': True}}

    def create(self, validated_data):
        user = User.objects.create_user(**validated_data)
        return user

# user login serializer
class UserLoginSerializer(serializers.Serializer):
    username = serializers.CharField(write_only=True)
    password = serializers.CharField(write_only=True)

# user profile serializer
class UserProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id','username','email','password']
    
# user logout serializer
class UserLogoutSerializer(serializers.Serializer):
    refresh = serializers.CharField()
    default_error_messages = {
        'bad_token':('Token is expired or invalid')
    }
    def validate(self, attrs):
        self.token = attrs['refresh']
        return attrs
    def save(self, **kwargs):
        try:
            RefreshToken(self.token).blacklist()
        except TokenError:
            self.fail('bad_token')

# user changepassword serializer 
class UserChangepasswordSerialiser(serializers.Serializer):
    old_password = serializers.CharField(max_length=10)
    new_password = serializers.CharField(max_length=10)

    def validate(self, attrs):
        old_password = attrs.get('old_password')
        new_password = attrs.get('new_password')
        user = self.context.get('user')
        if not user.check_password(old_password):
            raise serializers.ValidationError("Incorrect old password.")
        user.set_password(new_password)
        user.save()
        return attrs

# send reset password email serializer 
class SendPasswordResetEmailSerializer(serializers.Serializer):
    email = serializers.EmailField(max_length = 200)
    class Meta:
        fields = ['email']

    def validate(self, attrs):
        email = attrs.get('email')
        if User.objects.filter(email=email).exists:
            user = User.objects.get(email=email)
            uid = urlsafe_base64_encode(force_bytes(user.id))
            print('Encodeed UID:', uid)
            token = PasswordResetTokenGenerator().make_token(user)
            print('password reset token:',token)
            link = 'http://127.0.0.1:8000/rest-password/'+uid+'/'+token
            print('password reset link:', link)
            #send email
            body = 'click following link to reset your password ' + link
            data={
                'subject':'Reset Your Password',
                'body':body,
                'to_email': user.email
            }
            print(f'Using username: {settings.EMAIL_HOST_USER}')
            print(f'Using password: {settings.EMAIL_HOST_PASSWORD}')
            Util.send_email(data)
            print(data)
            return attrs
        else:
            raise ValidationErr("You are not register")

# password reset serializer  
class UserPasswordResetSerializer(serializers.Serializer):
    password = serializers.CharField(max_length=10)
    confirm_password= serializers.CharField(max_length=10)
    class Meta:
        fields = ['password','confirm_password']

    def validate(self, attrs):
        try:
            password = attrs.get('password')
            confirm_password = attrs.get('confirm_password')
            uid = self.context.get('uid')
            token = self.context.get('token')
            if password != confirm_password:
                raise serializers.ValidationError("password and confirm_password doesn't match")
            id = smart_str(urlsafe_base64_decode(uid))
            user = User.objects.get(id=id)
            if not PasswordResetTokenGenerator().check_token(user, token):
                raise ValidationErr('Token is not valid or expired')
            user.set_password(password)
            user.save()
            return attrs
        except DjangoUnicodeDecodeError :
            PasswordResetTokenGenerator().check_token(uid, token)
            raise ValidationErr('Token is not valid or expired')