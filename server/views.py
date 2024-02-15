from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response 
from rest_framework import status 
from rest_framework.permissions import IsAuthenticated
from rest_framework.authtoken.models import Token
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.models import User
from .serializers import UserSerializer
from django.middleware import security
from django.core.mail import send_mail

# Enable Django Security Middleware
@security.middleware_classes
@api_view(['POST'])
def login_view(request):
    username = request.data.get('username')
    password = request.data.get('password')

    # Authenticate user
    user = authenticate(username=username, password=password)

    if user is not None:
        # User is authenticated, create or retrieve token
        token, created = Token.objects.get_or_create(user=user)
        login(request, user)
        return Response({"token": token.key, "user": UserSerializer(user).data})
    else:
        # Authentication failed
        return Response({"error": "Invalid credentials"}, status=status.HTTP_401_UNAUTHORIZED)

@api_view(['POST'])
def signup_view(request):
    serializer = UserSerializer(data=request.data)
    if serializer.is_valid():
        user = serializer.save()

        # Send user registration confirmation email with the user's email as the sender
        send_registration_confirmation_email(user.email, user.username)

        return Response({"message": "User registered successfully. Confirmation email sent."}, status=status.HTTP_201_CREATED)
    
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def update_user(request):
    user = request.user
    serializer = UserSerializer(user, data=request.data, partial=True)

    if serializer.is_valid():
        serializer.save()
        return Response({"message": "User information updated successfully"})
    
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def custom_logout(request):
    # Retrieve the user and token associated with the request
    user = request.user
    token = Token.objects.get(user=user)

    # Delete the token from the database
    token.delete()

    # Logout the user
    logout(request)

    return Response({"message": "Logout successful"}, status=status.HTTP_200_OK)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def test_token(request):
    return Response({"message": "Token is valid"})

def send_registration_confirmation_email(to_email, username):
    subject = 'Account Registration Confirmation'
    message = f'Thank you for registering, {username}! Your account is now active.'
    from_email = to_email
    recipient_list = [to_email]

    send_mail(subject, message, from_email, recipient_list)
