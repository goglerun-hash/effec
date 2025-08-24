from rest_framework import status, permissions
from rest_framework.response import Response
from rest_framework.views import APIView
from django.utils import timezone
from datetime import timedelta
from django.contrib.auth import authenticate

from .models import User, Role, Resource, Permission, RolePermission, Session
from .serializers import (
    UserSerializer, UserRegisterSerializer, UserUpdateSerializer,
    RoleSerializer, ResourceSerializer, PermissionSerializer,
    RolePermissionSerializer
)
from .permissions import HasPermission


# 🔹 Регистрация
class RegisterView(APIView):
    authentication_classes = []
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        serializer = UserRegisterSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            user_role, _ = Role.objects.get_or_create(name="user")
            user.roles.add(user_role)
            return Response(UserSerializer(user).data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


# 🔹 Логин
class LoginView(APIView):
    authentication_classes = []
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        email = request.data.get("email")
        password = request.data.get("password")

        user = authenticate(request, username=email, password=password)
        if not user or not user.is_active:
            return Response({"error": "Invalid credentials"}, status=status.HTTP_401_UNAUTHORIZED)

        # Генерация токена
        raw_token, token_hash = Session.generate_token()
        session, _ = Session.objects.update_or_create(
            user=user,
            defaults={"token_hash": token_hash, "expires_at": timezone.now() + timedelta(days=7)}
        )

        return Response({
            "user": UserSerializer(user).data,
            "token": raw_token,  # отдаём сырой токен только клиенту
            "expires_at": session.expires_at
        })


# 🔹 Логаут
class LogoutView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        Session.objects.filter(user=request.user).delete()
        return Response({"message": "Logged out successfully"})


# 🔹 Профиль
class ProfileView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        serializer = UserSerializer(request.user)
        return Response(serializer.data)

    def patch(self, request):
        serializer = UserUpdateSerializer(request.user, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request):
        request.user.delete()
        Session.objects.filter(user=request.user).delete()
        return Response({"message": "Account deleted successfully"})


# 🔹 Управление ролями
class RoleView(APIView):
    permission_classes = [HasPermission]
    required_resource = "roles"

    def get(self, request):
        self.required_permission = "read"
        roles = Role.objects.all()
        return Response(RoleSerializer(roles, many=True).data)

    def post(self, request):
        self.required_permission = "create"
        serializer = RoleSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


# 🔹 Назначение/удаление роли пользователю
class UserRoleView(APIView):
    permission_classes = [HasPermission]
    required_resource = "users"
    required_permission = "update"

    def post(self, request, user_id):
        try:
            user = User.objects.get(id=user_id)
            role_id = request.data.get("role_id")
            role = Role.objects.get(id=role_id)
            user.roles.add(role)
            return Response({"message": "Role added successfully"})
        except User.DoesNotExist:
            return Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)
        except Role.DoesNotExist:
            return Response({"error": "Role not found"}, status=status.HTTP_404_NOT_FOUND)

    def delete(self, request, user_id, role_id):
        try:
            user = User.objects.get(id=user_id)
            role = Role.objects.get(id=role_id)
            user.roles.remove(role)
            return Response({"message": "Role removed successfully"})
        except User.DoesNotExist:
            return Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)
        except Role.DoesNotExist:
            return Response({"error": "Role not found"}, status=status.HTTP_404_NOT_FOUND)


# 🔹 Управление правами ролей
class RolePermissionView(APIView):
    permission_classes = [HasPermission]
    required_resource = "roles"
    required_permission = "update"

    def post(self, request, role_id):
        serializer = RolePermissionSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save(role_id=role_id)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, role_id, permission_id, resource_id):
        try:
            role_permission = RolePermission.objects.get(
                role_id=role_id,
                permission_id=permission_id,
                resource_id=resource_id
            )
            role_permission.delete()
            return Response({"message": "Permission removed successfully"})
        except RolePermission.DoesNotExist:
            return Response({"error": "Permission not found"}, status=status.HTTP_404_NOT_FOUND)


# 🔹 Бизнес-мок "Продукты"
class ProductView(APIView):
    permission_classes = [HasPermission]
    required_resource = "products"

    def get(self, request):
        self.required_permission = "read"
        products = [
            {"id": 1, "name": "Product 1", "price": 100},
            {"id": 2, "name": "Product 2", "price": 200},
        ]
        return Response(products)

    def post(self, request):
        self.required_permission = "create"
        return Response(
            {"id": 3, "name": request.data.get("name"), "price": request.data.get("price")},
            status=status.HTTP_201_CREATED
        )
