from rest_framework.permissions import BasePermission
from .models import RolePermission, Resource, Permission

class HasPermission(BasePermission):
    """
    Проверка доступа по таблицам RolePermission.
    Используется через required_permission + required_resource во вьюхах.
    """
    def has_permission(self, request, view):
        if not request.user or not request.user.is_authenticated:
            return False

        required_perm = getattr(view, "required_permission", None)
        required_res = getattr(view, "required_resource", None)

        if not required_perm or not required_res:
            return True

        return RolePermission.objects.filter(
            role__users=request.user,
            permission__name=required_perm,
            resource__name=required_res
        ).exists()
