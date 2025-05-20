# coding=utf-8
"""
    @project: qabot
    @Author：虎
    @file： user.py
    @date：2023/9/4 10:57
    @desc:
"""
from django.core import cache
from django.utils.translation import gettext_lazy as _
from drf_yasg import openapi
from drf_yasg.utils import swagger_auto_schema
from rest_framework.decorators import action
from rest_framework.decorators import permission_classes
from rest_framework.permissions import AllowAny
from rest_framework.views import APIView
from rest_framework.views import Request

from common.auth.authenticate import TokenAuth
from common.auth.authentication import has_permissions
from common.constants.permission_constants import PermissionConstants, CompareConstants, ViewPermission, RoleConstants
from common.log.log import log
from common.response import result
from common.util.common import encryption
from smartdoc.settings import JWT_AUTH
from users.serializers.user_serializers import RegisterSerializer, LoginSerializer, CheckCodeSerializer, \
    RePasswordSerializer, \
    SendEmailSerializer, UserProfile, UserSerializer, UserManageSerializer, UserInstanceSerializer, SystemSerializer, \
    SwitchLanguageSerializer
from users.views.common import get_user_operation_object, get_re_password_details

user_cache = cache.caches['user_cache']
token_cache = cache.caches['token_cache']


class Profile(APIView):
    @action(methods=['GET'], detail=False)
    @swagger_auto_schema(operation_summary=_("Get MaxKB related information"),
                         operation_id=_("Get MaxKB related information"),
                         responses=result.get_api_response(SystemSerializer.get_response_body_api()),
                         tags=[_('System parameters')])
    def get(self, request: Request):
        return result.success(SystemSerializer.get_profile())


class User(APIView):
    authentication_classes = [TokenAuth]

    @action(methods=['GET'], detail=False)
    @swagger_auto_schema(operation_summary=_("Get current user information"),
                         operation_id=_("Get current user information"),
                         responses=result.get_api_response(UserProfile.get_response_body_api()),
                         tags=[])
    @has_permissions(PermissionConstants.USER_READ)
    def get(self, request: Request):
        return result.success(UserProfile.get_user_profile(request.user))

    class Query(APIView):
        authentication_classes = [TokenAuth]

        @action(methods=['GET'], detail=False)
        @swagger_auto_schema(operation_summary=_("Get user list"),
                             operation_id=_("Get user list"),
                             manual_parameters=UserSerializer.Query.get_request_params_api(),
                             responses=result.get_api_array_response(UserSerializer.Query.get_response_body_api()),
                             tags=[_("User management")])
        @has_permissions(PermissionConstants.USER_READ)
        def get(self, request: Request):
            return result.success(
                UserSerializer.Query(data={'email_or_username': request.query_params.get('email_or_username')}).list())


class SwitchUserLanguageView(APIView):
    authentication_classes = [TokenAuth]

    @action(methods=['POST'], detail=False)
    @swagger_auto_schema(operation_summary=_("Switch Language"),
                         operation_id=_("Switch Language"),
                         request_body=openapi.Schema(
                             type=openapi.TYPE_OBJECT,
                             required=['language'],
                             properties={
                                 'language': openapi.Schema(type=openapi.TYPE_STRING, title=_("language"),
                                                            description=_("language")),
                             }
                         ),
                         responses=RePasswordSerializer().get_response_body_api(),
                         tags=[_("User management")])
    @log(menu='User management', operate='Switch Language',
         get_operation_object=lambda r, k: {'name': r.user.username})
    def post(self, request: Request):
        data = {**request.data, 'user_id': request.user.id}
        return result.success(SwitchLanguageSerializer(data=data).switch())


class ResetCurrentUserPasswordView(APIView):
    authentication_classes = [TokenAuth]

    @action(methods=['POST'], detail=False)
    @swagger_auto_schema(operation_summary=_("Modify current user password"),
                         operation_id=_("Modify current user password"),
                         request_body=openapi.Schema(
                             type=openapi.TYPE_OBJECT,
                             required=['email', 'code', "password", 're_password'],
                             properties={
                                 'code': openapi.Schema(type=openapi.TYPE_STRING, title=_("Verification code"),
                                                        description=_("Verification code")),
                                 'password': openapi.Schema(type=openapi.TYPE_STRING, title=_("Password"),
                                                            description=_("Password")),
                                 're_password': openapi.Schema(type=openapi.TYPE_STRING, title=_("Password"),
                                                               description=_("Password"))
                             }
                         ),
                         responses=RePasswordSerializer().get_response_body_api(),
                         tags=[_("User management")])
    @log(menu='User management', operate='Modify current user password',
         get_operation_object=lambda r, k: {'name': r.user.username},
         get_details=get_re_password_details)
    def post(self, request: Request):
        data = {'email': request.user.email}
        data.update(request.data)
        serializer_obj = RePasswordSerializer(data=data)
        if serializer_obj.reset_password():
            token_cache.delete(request.META.get('HTTP_AUTHORIZATION'))
            return result.success(True)
        return result.error(_("Failed to change password"))


class SendEmailToCurrentUserView(APIView):
    authentication_classes = [TokenAuth]

    @action(methods=['POST'], detail=False)
    @permission_classes((AllowAny,))
    @swagger_auto_schema(operation_summary=_("Send email to current user"),
                         operation_id=_("Send email to current user"),
                         responses=SendEmailSerializer().get_response_body_api(),
                         tags=[_("User management")])
    @log(menu='User management', operate='Send email to current user',
         get_operation_object=lambda r, k: {'name': r.user.username})
    def post(self, request: Request):
        serializer_obj = SendEmailSerializer(data={'email': request.user.email, 'type': "reset_password"})
        if serializer_obj.is_valid(raise_exception=True):
            return result.success(serializer_obj.send())


class Logout(APIView):
    authentication_classes = [TokenAuth]

    @action(methods=['POST'], detail=False)
    @permission_classes((AllowAny,))
    @swagger_auto_schema(operation_summary=_("Sign out"),
                         operation_id=_("Sign out"),
                         responses=SendEmailSerializer().get_response_body_api(),
                         tags=[_("User management")])
    @log(menu='User management', operate='Sign out',
         get_operation_object=lambda r, k: {'name': r.user.username})
    def post(self, request: Request):
        token_cache.delete(request.META.get('HTTP_AUTHORIZATION'))
        return result.success(True)


def _get_details(request):
    path = request.path
    body = request.data
    query = request.query_params
    return {
        'path': path,
        'body': {**body, 'password': encryption(body.get('password', ''))},
        'query': query
    }


class Login(APIView):

    @action(methods=['POST'], detail=False)
    @swagger_auto_schema(operation_summary=_("Log in"),
                         operation_id=_("Log in"),
                         request_body=LoginSerializer().get_request_body_api(),
                         responses=LoginSerializer().get_response_body_api(),
                         security=[],
                         tags=[_("User management")])
    @log(menu='User management', operate='Log in', get_user=lambda r: {'username': r.data.get('username', None)},
         get_details=_get_details,
         get_operation_object=lambda r, k: {'name': r.data.get('username')})
    def post(self, request: Request):
        """首次登录的时候创建一个匿名用户"""
        # from users.models import User
        # from django.db.models import QuerySet
        # import uuid
        # from django.utils import timezone
        # from django.contrib.auth.hashers import make_password
        # # 检查是否存在匿名用户
        # if QuerySet(User).filter(username='anonymous').count() == 0:
        #     User.objects.create(
        #         id='10000000-0000-0000-0000-000000000001',
        #         email=' ',
        #         phone=' ',
        #         username='anonymous',
        #         nick_name='系统管理员',
        #         password='e10adc3949ba59abbe56e057f20f883e',
        #         role='ADMIN',
        #         is_active=True,
        #         create_time=timezone.now(),
        #         update_time=timezone.now(),
        #         source='LOCAL',
        #         language='zh-CN'
        #     )

        login_request = LoginSerializer(data=request.data)
        # 校验请求参数
        user = login_request.is_valid(raise_exception=True)
        token = login_request.get_user_token()
        token_cache.set(token, user, timeout=JWT_AUTH['JWT_EXPIRATION_DELTA'])
        return result.success(token)

class getToken(APIView):

    @action(methods=['GET'], detail=False)
    def get(self, request: Request):
        import sqlite3
        import base64
        import json
        import os
        from smartdoc.conf import PROJECT_DIR
        db_path = os.path.join(PROJECT_DIR, 'data', 'cache', 'token_cache', 'cache.db')

        tokens = {}
        try:
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            cursor.execute("SELECT key FROM Cache")
            rows = cursor.fetchall()

            for row in rows:
                key = row[0]
                # 解析 key，提取用户名
                # key 的格式为 default:<token_payload>:<random_string>
                token_payload = key.split(':')[1]
                decoded_bytes = base64.urlsafe_b64decode(token_payload + '==')
                decoded_str = decoded_bytes.decode('utf-8')
                user_info = json.loads(decoded_str)

                username = user_info.get('username')
                if username:
                    tokens[username] = key.split(':', 1)[1]

        except Exception as e:
            return {}

        finally:
            if cursor:
                cursor.close()
            if conn:
                conn.close()

        return result.success(tokens)

class getHost(APIView):
    @action(methods=['GET'], detail=False)
    def get(self, request: Request):
        try:
            host = request.META.get('HTTP_HOST', '')
            if not host:
                return {}
            return result.success(host)
        except Exception as e:
            return {}

class Register(APIView):

    @action(methods=['POST'], detail=False)
    @permission_classes((AllowAny,))
    @swagger_auto_schema(operation_summary=_("User registration"),
                         operation_id=_("User registration"),
                         request_body=RegisterSerializer().get_request_body_api(),
                         responses=RegisterSerializer().get_response_body_api(),
                         security=[],
                         tags=[_("User management")])
    @log(menu='User management', operate='User registration',
         get_operation_object=lambda r, k: {'name': r.data.get('username', None)},
         get_user=lambda r: {'user_name': r.data.get('username', None)})
    def post(self, request: Request):
        serializer_obj = RegisterSerializer(data=request.data)
        if serializer_obj.is_valid(raise_exception=True):
            serializer_obj.save()
            return result.success(_("Registration successful"))


class RePasswordView(APIView):

    @action(methods=['POST'], detail=False)
    @permission_classes((AllowAny,))
    @swagger_auto_schema(operation_summary=_("Change password"),
                         operation_id=_("Change password"),
                         request_body=RePasswordSerializer().get_request_body_api(),
                         responses=RePasswordSerializer().get_response_body_api(),
                         security=[],
                         tags=[_("User management")])
    @log(menu='User management', operate='Change password',
         get_operation_object=lambda r, k: {'name': r.data.get('email', None)},
         get_user=lambda r: {'user_name': None, 'email': r.data.get('email', None)},
         get_details=get_re_password_details)
    def post(self, request: Request):
        serializer_obj = RePasswordSerializer(data=request.data)
        return result.success(serializer_obj.reset_password())


class CheckCode(APIView):

    @action(methods=['POST'], detail=False)
    @permission_classes((AllowAny,))
    @swagger_auto_schema(operation_summary=_("Check whether the verification code is correct"),
                         operation_id=_("Check whether the verification code is correct"),
                         request_body=CheckCodeSerializer().get_request_body_api(),
                         responses=CheckCodeSerializer().get_response_body_api(),
                         security=[],
                         tags=[_("User management")])
    @log(menu='User management', operate='Check whether the verification code is correct',
         get_operation_object=lambda r, k: {'name': r.data.get('email', None)},
         get_user=lambda r: {'user_name': None, 'email': r.data.get('email', None)})
    def post(self, request: Request):
        return result.success(CheckCodeSerializer(data=request.data).is_valid(raise_exception=True))


class SendEmail(APIView):

    @action(methods=['POST'], detail=False)
    @swagger_auto_schema(operation_summary=_("Send email"),
                         operation_id=_("Send email"),
                         request_body=SendEmailSerializer().get_request_body_api(),
                         responses=SendEmailSerializer().get_response_body_api(),
                         security=[],
                         tags=[_("User management")])
    @log(menu='User management', operate='Send email',
         get_operation_object=lambda r, k: {'name': r.data.get('email', None)},
         get_user=lambda r: {'user_name': None, 'email': r.data.get('email', None)})
    def post(self, request: Request):
        serializer_obj = SendEmailSerializer(data=request.data)
        if serializer_obj.is_valid(raise_exception=True):
            return result.success(serializer_obj.send())


class UserManage(APIView):
    authentication_classes = [TokenAuth]

    @action(methods=['POST'], detail=False)
    @swagger_auto_schema(operation_summary=_("Add user"),
                         operation_id=_("Add user"),
                         request_body=UserManageSerializer.UserInstance.get_request_body_api(),
                         responses=result.get_api_response(UserInstanceSerializer.get_response_body_api()),
                         tags=[_("User management")]
                         )
    @has_permissions(ViewPermission(
        [RoleConstants.ADMIN],
        [PermissionConstants.USER_READ],
        compare=CompareConstants.AND))
    @log(menu='User management', operate='Add user',
         get_operation_object=lambda r, k: {'name': r.data.get('username', None)})
    def post(self, request: Request):
        return result.success(UserManageSerializer().save(request.data))

    class Page(APIView):
        authentication_classes = [TokenAuth]

        @action(methods=['GET'], detail=False)
        @swagger_auto_schema(operation_summary=_("Get user paginated list"),
                             operation_id=_("Get user paginated list"),
                             tags=[_("User management")],
                             manual_parameters=UserManageSerializer.Query.get_request_params_api(),
                             responses=result.get_page_api_response(UserInstanceSerializer.get_response_body_api()),
                             )
        @has_permissions(ViewPermission(
            [RoleConstants.ADMIN],
            [PermissionConstants.USER_READ],
            compare=CompareConstants.AND))
        def get(self, request: Request, current_page, page_size):
            d = UserManageSerializer.Query(
                data={'email_or_username': request.query_params.get('email_or_username', None),
                      'user_id': str(request.user.id)})
            return result.success(d.page(current_page, page_size))

    class RePassword(APIView):
        authentication_classes = [TokenAuth]

        @action(methods=['PUT'], detail=False)
        @swagger_auto_schema(operation_summary=_("Change password"),
                             operation_id=_("Change password"),
                             manual_parameters=UserInstanceSerializer.get_request_params_api(),
                             request_body=UserManageSerializer.RePasswordInstance.get_request_body_api(),
                             responses=result.get_default_response(),
                             tags=[_("User management")])
        @has_permissions(ViewPermission(
            [RoleConstants.ADMIN],
            [PermissionConstants.USER_READ],
            compare=CompareConstants.AND))
        @log(menu='User management', operate='Change password',
             get_operation_object=lambda r, k: get_user_operation_object(k.get('user_id')),
             get_details=get_re_password_details)
        def put(self, request: Request, user_id):
            return result.success(
                UserManageSerializer.Operate(data={'id': user_id}).re_password(request.data, with_valid=True))

    class Operate(APIView):
        authentication_classes = [TokenAuth]

        @action(methods=['DELETE'], detail=False)
        @swagger_auto_schema(operation_summary=_("Delete user"),
                             operation_id=_("Delete user"),
                             manual_parameters=UserInstanceSerializer.get_request_params_api(),
                             responses=result.get_default_response(),
                             tags=[_("User management")])
        @has_permissions(ViewPermission(
            [RoleConstants.ADMIN],
            [PermissionConstants.USER_READ],
            compare=CompareConstants.AND))
        @log(menu='User management', operate='Delete user',
             get_operation_object=lambda r, k: get_user_operation_object(k.get('user_id')))
        def delete(self, request: Request, user_id):
            return result.success(UserManageSerializer.Operate(data={'id': user_id}).delete(with_valid=True))

        @action(methods=['GET'], detail=False)
        @swagger_auto_schema(operation_summary=_("Get user information"),
                             operation_id=_("Get user information"),
                             manual_parameters=UserInstanceSerializer.get_request_params_api(),
                             responses=result.get_api_response(UserInstanceSerializer.get_response_body_api()),
                             tags=[_("User management")]
                             )
        @has_permissions(ViewPermission(
            [RoleConstants.ADMIN],
            [PermissionConstants.USER_READ],
            compare=CompareConstants.AND))
        def get(self, request: Request, user_id):
            return result.success(UserManageSerializer.Operate(data={'id': user_id}).one(with_valid=True))

        @action(methods=['PUT'], detail=False)
        @swagger_auto_schema(operation_summary=_("Update user information"),
                             operation_id=_("Update user information"),
                             manual_parameters=UserInstanceSerializer.get_request_params_api(),
                             request_body=UserManageSerializer.UserEditInstance.get_request_body_api(),
                             responses=result.get_api_response(UserInstanceSerializer.get_response_body_api()),
                             tags=[_("User management")]
                             )
        @has_permissions(ViewPermission(
            [RoleConstants.ADMIN],
            [PermissionConstants.USER_READ],
            compare=CompareConstants.AND))
        @log(menu='User management', operate='Update user information',
             get_operation_object=lambda r, k: get_user_operation_object(k.get('user_id')))
        def put(self, request: Request, user_id):
            return result.success(
                UserManageSerializer.Operate(data={'id': user_id}).edit(request.data, with_valid=True))


class UserListView(APIView):
    authentication_classes = [TokenAuth]

    @swagger_auto_schema(operation_summary=_("Get user list by type"),
                         operation_id=_("Get user list by type"),
                         manual_parameters=UserSerializer.Query.get_request_params_api(),
                         responses=result.get_api_array_response(UserSerializer.Query.get_response_body_api()),
                         tags=[_("User management")])
    @has_permissions(PermissionConstants.USER_READ)
    def get(self, request: Request, type):
        return result.success(UserSerializer().listByType(type, request.user.id))
