from django.conf import settings
from jwt import InvalidTokenError
from rest_framework import generics, permissions
from rest_framework.response import Response
from django.http import JsonResponse
from django.contrib.auth import get_user_model
from .serializers import  PasswordResetSerializer, UserSerializer, RegisterSerializer, AdminSerializer
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework_simplejwt.exceptions import TokenError, InvalidToken
from.models import CustomUser
from rest_framework.parsers import MultiPartParser, FormParser
from rest_framework.exceptions import PermissionDenied
from rest_framework_simplejwt.authentication import JWTAuthentication
from .models import CustomUser
from django.contrib.auth import authenticate
from rest_framework.exceptions import AuthenticationFailed
from rest_framework import status
from rest_framework.views import APIView
from django.shortcuts import get_object_or_404
from django.template.loader import render_to_string
from .utils import email_verification_token
from rest_framework.permissions import AllowAny
import logging
from google.oauth2 import id_token
from google.auth.transport import requests
from django.contrib.auth import authenticate, login
from rest_framework_simplejwt.tokens import RefreshToken
from .serializers import GoogleLoginSerializer
from rest_framework.views import APIView
from rest_framework.response import Response
from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from rest_framework import status
logger = logging.getLogger(__name__)
User = get_user_model()
from rest_framework.decorators import api_view
from django.utils.encoding import force_bytes,force_str

from django.core.mail import send_mail
class RegisterView(generics.CreateAPIView):
    queryset = CustomUser.objects.all()
    serializer_class = RegisterSerializer
    permission_classes = [permissions.AllowAny]
    parser_classes = [MultiPartParser, FormParser]

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            self.perform_create(serializer)
            headers = self.get_success_headers(serializer.data)
            return Response(serializer.data, status=status.HTTP_201_CREATED, headers=headers)
        # Log detailed errors
        print("Validation errors:", serializer.errors)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class UserListView(generics.ListCreateAPIView):
    queryset = CustomUser.objects.all()
    serializer_class = UserSerializer
    permission_classes = [permissions.IsAuthenticated]
    parser_classes = [MultiPartParser] 

    def get_queryset(self):
        # Exclude users with admin status
        return CustomUser.objects.filter(is_superuser=False)
    

class UserDetailView(generics.RetrieveUpdateDestroyAPIView):
    queryset = User.objects.all()
    serializer_class = AdminSerializer
    permission_classes = [permissions.IsAdminUser]
    

class UserProfileView(generics.RetrieveUpdateAPIView):
    queryset = CustomUser.objects.all()
    serializer_class = UserSerializer
    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.IsAuthenticated]


class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
    ...
    def validate(self, attrs):
        print("Validating user credentials...")
        data = super().validate(attrs)
        request = self.context['request']
        user = self.user

        print("User is_active:", user.is_active)
        print("User is_superuser:", user.is_superuser)

        if not user.is_active:
            raise InvalidToken('No active account found with the given credentials')

        if user.is_superuser and not request.path.endswith('/admin/token/'):
            raise InvalidToken('Superuser credentials are not allowed for regular user login.')
        elif not user.is_superuser and request.path.endswith('/admin/token/'):
            raise InvalidToken('Regular user credentials are not allowed for admin login.')

        data.update({
            'userId': user.id
        })
        return data

class CustomTokenObtainPairView(TokenObtainPairView):
    serializer_class = CustomTokenObtainPairSerializer

class AdminTokenObtainPairView(CustomTokenObtainPairView):
    pass

class VerifyEmailView(APIView):
    permission_classes = [AllowAny]

    def get(self, request, user_id, token, *args, **kwargs):
        user = get_object_or_404(User, pk=user_id)
        if email_verification_token.check_token(user, token):
            user.is_active = True
            user.is_email_verified = True
            user.save()
            return Response({"message": "Email verified successfully!"}, status=status.HTTP_200_OK)
        else:
            return Response({"error": "Invalid or expired token."}, status=status.HTTP_400_BAD_REQUEST)

# class GoogleLoginView(APIView):
#     def post(self, request, *args, **kwargs):
#         id_token_str = request.data.get('idToken')
#         if not id_token_str:
#             return Response({'error': 'ID token is required'}, status=status.HTTP_400_BAD_REQUEST)

#         try:
#             # Verify the ID token with Google's server
#             id_info = id_token.verify_oauth2_token(id_token_str, requests.Request(), settings.GOOGLE_CLIENT_ID)

#             # Use the id_info['sub'] or email to find or create a user in your database
#             email = id_info['email']
#             try:
#                 user = CustomUser.objects.get(email=email)
#             except CustomUser.DoesNotExist:
#                 # Create a new user if not already present
#                 user = CustomUser.objects.create(
#                     email=email,
#                     first_name=id_info.get('given_name', ''),
#                     last_name=id_info.get('family_name', ''),
#                     is_active=True
#                 )

#             # Generate tokens or login session (depending on your authentication mechanism)
#             serializer = UserSerializer(user)
#             return Response({'message': 'Login successful', 'user': serializer.data}, status=status.HTTP_200_OK)

#         except ValueError as e:
#             return Response({'error': f'Token verification failed: {e}'}, status=status.HTTP_400_BAD_REQUEST)
# def google_login(id_token_str):
#     try:
#         id_info = id_token.verify_oauth2_token(id_token_str, requests.Request(), settings.GOOGLE_CLIENT_ID)
#         return id_info
#     except ValueError as e:
#         # Token verification failed
#         print(f"Token verification failed: {e}")
#         return None
def google_login(request):
    if request.method == 'POST':
        data = json.loads(request.body)
        id_token_str = data.get('idToken')
        if not id_token_str:
            return JsonResponse({'error': 'ID token missing'}, status=400)

        try:
            id_info = id_token.verify_oauth2_token(id_token_str, requests.Request(), settings.GOOGLE_CLIENT_ID)
            logger.info(f"Google ID token verified successfully: {id_info}")
            return JsonResponse({'data': id_info})
        except ValueError as e:
            logger.error(f"Token verification failed: {e}")
            return JsonResponse({'error': str(e)}, status=400)
    return JsonResponse({'error': 'Invalid method'}, status=405)

class PasswordResetRequestView(APIView):
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        email = request.data.get('email')
        user = get_object_or_404(CustomUser, email=email)

        token = default_token_generator.make_token(user)
        user_id = user.id  # Use user.id directly

        # Link should redirect to the frontend URL
        reset_link = request.build_absolute_uri(f'http://localhost:3000/reset-password/{user_id}/{token}/')

        subject = 'Password Reset Request'
        message = f'Hi {user.first_name},\n\n' \
                  f'We received a request to reset your password. Click the link below to reset your password:\n' \
                  f'{reset_link}\n\n' \
                  f'If you did not request this change, please ignore this email.\n\n' \
                  f'Thank you!'

        send_mail(
            subject,
            message,
            'no-reply@yourdomain.com',
            [user.email],
            fail_silently=False,
        )

        return Response({"message": "Password reset email sent!"}, status=status.HTTP_200_OK)

class PasswordResetView(APIView):
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        serializer = PasswordResetSerializer(data=request.data)
        if serializer.is_valid():
            token = serializer.validated_data['token']
            password = serializer.validated_data['password']

            user = self.get_user_from_token(token)
            if user and default_token_generator.check_token(user, token):
                user.set_password(password)
                user.save()
                return Response({"message": "Password reset successful!"}, status=status.HTTP_200_OK)
            else:
                return Response({"error": "Invalid or expired token"}, status=status.HTTP_400_BAD_REQUEST)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def get_user_from_token(self, token):
        # Since token doesn't contain user info directly, return None if token validation fails
        for user in CustomUser.objects.all():
            if default_token_generator.check_token(user, token):
                return user
        return None