from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.contrib.auth import authenticate
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework import generics, permissions
from .serializers import UserRegisterSerializer, UserLoginSerializer,UserProfileSerializer,UserChangepasswordSerialiser,SendPasswordResetEmailSerializer,UserPasswordResetSerializer,UserLogoutSerializer
from django.contrib.auth import login
from rest_framework_simplejwt.tokens import RefreshToken

# user register API
class UserRegisterAPI(generics.CreateAPIView):
    permission_classes = [permissions.AllowAny]
    serializer_class = UserRegisterSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            refresh = RefreshToken.for_user(user)
            return Response({'refresh': str(refresh), 'access': str(refresh.access_token)}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

# user login API
class UserLoginAPI(generics.CreateAPIView):
    permission_classes = [permissions.AllowAny]
    serializer_class = UserLoginSerializer
    
    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)
        print(serializer)
        if serializer.is_valid(raise_exception=True):
            username = serializer.validated_data.get('username')
            password = serializer.validated_data.get('password')
            user = authenticate(request, username=username, password=password)
            print("Authenticated user:", user)
            if user is not None:
                login(request, user)
                refresh = RefreshToken.for_user(user)
                print("Access Token Contents:", refresh.access_token.payload)
                print("Request user:", request.user) 
                return Response({'refresh': str(refresh), 'access': str(refresh.access_token)}, status=status.HTTP_200_OK)
            else:
                return Response({'error': 'Invalid credentials or user does not exist'}, status=status.HTTP_401_UNAUTHORIZED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

# user profile API
class UserProfileAPI(APIView):
    permission_classes = [permissions.IsAuthenticated]
    def get(self, request, format = None):
        serializer = UserProfileSerializer(request.user)
        return Response(serializer.data, status=status.HTTP_200_OK)

class UserLogoutAPI(APIView):
    serializer_class = UserLogoutSerializer
    permission_classes = (permissions.IsAuthenticated, )

    def post(self, request, *args):
        serializer= self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response({"msg":"logout successfully"},status=status.HTTP_204_NO_CONTENT)

# change password API
class UserChangePassAPI(APIView):
    permission_classes = [permissions.IsAuthenticated]
    def post(self, request, format = None): 
        serializer = UserChangepasswordSerialiser(data=request.data, context = {'user':request.user})
        if serializer.is_valid(raise_exception=True):
            return Response({'msg':'password change successfully'}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

# send link in email for reset password API
class SendPasswordResetEmailAPI(APIView):
    def post(self, request,format = None):
        serializer = SendPasswordResetEmailSerializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            return Response({'msg':'password reset link send. Please check your email.'}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

# user password reset API
class UserPasswordResetAPI(APIView):
    def post(self, request,uid, token, format = None):
        serializer = UserPasswordResetSerializer(data=request.data, context = {'uid':uid, 'token':token})
        if serializer.is_valid(raise_exception=True):
            return Response({'msg':'password reset successfully'},status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        