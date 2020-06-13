# Create your views here.
from django.contrib.auth.models import User
from rest_framework.views import APIView
from rest_framework import status
from .serializers import UserSerializer
from rest_framework.response import Response
from django.contrib.auth import authenticate, login
import pyotp

class Register(APIView):
	def post(self, request):
		serialized = UserSerializer(data=request.data)
		if serialized.is_valid():
			serialized.save()
			uri = pyotp.totp.TOTP(serialized.data['mfa_hash']).provisioning_uri(serialized.data['email'], 
																			issuer_name="SecureApp")
			qrcode_uri = "https://www.google.com/chart?chs=200x200&chld=M|0&cht=qr&chl={}".format(uri)
			

			return Response({'message':'User Created Successfully',
				'qrcode': qrcode_uri}, status=status.HTTP_201_CREATED)
		else:
			return Response(serialized._errors, status=status.HTTP_400_BAD_REQUEST)


class Login(APIView):
    def post(self, request):
        data = request.data
        email = data.get('email', None)
        password = data.get('password', None)
        otp = data.get('otp', None)
        user = authenticate(username=email, password=password)
       	if user:
            totp = pyotp.TOTP(user.mfa_hash)
            if totp.verify(otp, valid_window=3):
                return Response({'message':'User authenticated Successfully'}, status=200)
            else:
                return Response({'message':'Invalid OTP'}, status=401)

        else:
            return Response({'message':'Invalid email/password'}, status=401)