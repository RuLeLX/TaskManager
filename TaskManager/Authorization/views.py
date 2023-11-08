from django.shortcuts import render
from django.http import JsonResponse
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from Authorization.serializer import LoginSerializer, RefreshSerializer

class LoginView(APIView):

    def post(self, request, format=None):
        serializer = LoginSerializer(data=request.data)
        if serializer.is_valid():
            response_data = serializer.save()
            return Response(response_data)

        return Response(data=serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class RefreshView(APIView):

    def post(self, request, format=None):
        serializer = RefreshSerializer(data=request.data)
        if serializer.is_valid():
            response_data = serializer.save()
            return Response(response_data)

        return Response(data=serializer.errors, status=status.HTTP_400_BAD_REQUEST)