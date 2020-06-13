from demo.models import User
from rest_framework import serializers
import pyotp

class UserSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)

    class Meta:
        model = User
        fields = ('first_name', 'last_name', 'email', 'password', 'mfa_hash')

    def create(self, validated_data):
        user = User.objects.create(**validated_data)
        user.set_password(validated_data['password'])
        user.mfa_hash = pyotp.random_base32()
        user.save()
        return user
