from django.shortcuts import render,redirect
from taskapp.serializers import CustomUserSerializer,PasswordResetSerializer
from  rest_framework.views import APIView
from rest_framework.exceptions import AuthenticationFailed
from  taskapp.models import customusers

from django.contrib.auth import get_user_model
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.encoding import force_text, force_bytes
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from rest_framework.generics import GenericAPIView
from rest_framework.response import Response
from rest_framework import status
from django.core.mail import send_mail
from django.contrib.auth.password_validation import validate_password
from  Task import settings
# Create your views here.

class Registerview(APIView):
    def post(self,re):
        obj=CustomUserSerializer(data=re.data)
        obj.is_valid(raise_exception=True)
        obj.save()
        subject = f"You have successfully registered"
        message = f"Please login to your Account"
        from_mail = settings.EMAIL_HOST_USER
        to_list = [re.data['email']]
        send_mail(subject, message, from_mail, to_list, fail_silently=True)
        return redirect(log)


class Loginview(APIView):
    def post(self,request):
        email=request.data['email']
        password=request.data['password']
        x=customusers.objects.filter(email=email).first()
        if x is None:
            raise AuthenticationFailed('User Not found....!')
        if not x.check_password(password):
            raise AuthenticationFailed('Password doesnt match')
        return Response({
            'message':'success'
        })

class PasswordResetRequestView(GenericAPIView):
    serializer_class = PasswordResetSerializer
    def post(self, request):
        email = request.data.get('email')
        User = get_user_model()
        user = User.objects.filter(email=email).first()

        if user:
            # Generate a token for password reset
            token_generator = PasswordResetTokenGenerator()
            token = token_generator.make_token(user)

            # Send the reset link to the user's email
            subject = 'Password Reset'
            reset_link = f'http://http://127.0.0.1:8000//reset/?uidb64={urlsafe_base64_encode(force_bytes(user.pk))}&token={token}'
            message = f'Click the link to reset your password: {reset_link}'
            from_email = 'king.slayerzzzs@gmail.com'
            recipient_list = [user.email]
            send_mail(subject, message, from_email, recipient_list, fail_silently=False)

            return Response({'message': 'Password reset email sent.'}, status=status.HTTP_200_OK)
        else:
            return Response({'error': 'User not found.'}, status=status.HTTP_404_NOT_FOUND)

class PasswordResetConfirmView(GenericAPIView):
    def post(self, request):
        uidb64 = request.data.get('uidb64')
        token = request.data.get('token')
        password = request.data.get('password')

        print(f"uidb64: {uidb64}")
        print(f"token: {token}")
        print(f"password: {password}")

        try:
            uid = force_text(urlsafe_base64_decode(uidb64))
            User = get_user_model()
            user = User.objects.get(pk=uid)

            print(f"user: {user}")

            # Check if the token is valid
            token_generator = PasswordResetTokenGenerator()
            if not token_generator.check_token(user, token):
                print("Invalid token")
                return Response({'error': 'Invalid token.'}, status=status.HTTP_400_BAD_REQUEST)

            # Validate the new password
            validate_password(password, user)

            # Set the new password
            user.set_password(password)
            user.save()

            return Response({'message': 'Password reset successful.'}, status=status.HTTP_200_OK)
        except (TypeError, ValueError, OverflowError, get_user_model().DoesNotExist) as e:
            print(f"Error: {e}")
            return Response({'error': 'Invalid user ID.'}, status=status.HTTP_400_BAD_REQUEST)

def userregister(re):
    return render(re,"loginpage.html")

def log(re):
    return render(re,"userlogin.html")
def fpsd(re):
    return render(re,"forgetpswd.html")
def reset(re):
    return redirect(re,"pswdchange.html")