# serializers.py
from rest_framework import serializers
from django.contrib.auth.models import User
from django.core.mail import send_mail

class UserSerializer(serializers.ModelSerializer):
    password_confirmation = serializers.CharField(write_only=True)

    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'password', 'password_confirmation']
        extra_kwargs = {'password': {'write_only': True}}

    def validate(self, data):
        if data.get('password') != data.get('password_confirmation'):
            raise serializers.ValidationError("Passwords do not match.")
        return data

    def create(self, validated_data):
        password_confirmation = validated_data.pop('password_confirmation', None)
        user = super().create(validated_data)
        user.set_password(validated_data['password'])
        user.save()

        # Send user registration confirmation email
        self.send_registration_confirmation_email(user.email, user.username)

        return user

    def send_registration_confirmation_email(self, to_email, username):
        subject = 'Account Registration Confirmation'
        message = f'Thank you for registering, {username}! Your account is now active.'
        from_email = 'your_email@example.com'  # Replace with your email address
        recipient_list = [to_email]

        send_mail(subject, message, from_email, recipient_list)
