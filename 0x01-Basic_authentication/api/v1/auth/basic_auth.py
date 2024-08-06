#!/usr/bin/env python3
""" BasicAuth module """
from flask import request
from typing import List, TypeVar
import binascii
import base64
from api.v1.auth.auth import Auth


class BasicAuth(Auth):
    """ BasicAuth class """
    def extract_base64_authorization_header(self,
                                            authorization_header: str) -> str:
        """ extract_base64_authorization_header method """
        if authorization_header is None:
            return None
        if type(authorization_header) is not str:
            return None
        if not authorization_header.startswith("Basic "):
            return None
        return authorization_header[6:]

    def decode_base64_authorization_header(
            self, base64_authorization_header: str) -> str:
        """
        returns the decoded value of a Base64 string
        """
        b64_header = base64_authorization_header
        if b64_header and isinstance(b64_header, str):
            try:
                encode = b64_header.encode('utf-8')
                base = base64.b64decode(encode)
                return base.decode('utf-8')
            except binascii.Error:
                return None

    def extract_user_credentials(self, decoded_base64_authorization_header: str) -> (str, str):
        """ extract_user_credentials method """
        if decoded_base64_authorization_header is None:
            return (None, None)
        if type(decoded_base64_authorization_header) is not str:
            return (None, None)
        if ":" not in decoded_base64_authorization_header:
            return (None, None)
        return tuple(decoded_base64_authorization_header.split(':', 1))

    def user_object_from_credentials(self, user_email: str, user_pwd: str) -> TypeVar('User'):
        """ user_object_from_credentials method """
        if user_email is None or type(user_email) is not str:
            return None
        if user_pwd is None or type(user_pwd) is not str:
            return None
        try:
            users = User.search({"email": user_email})
        except Exception:
            return None
        for user in users:
            if user.is_valid_password(user_pwd):
                return user
        return None

    def current_user(self, request=None) -> TypeVar('User'):
        """ current_user method """
        auth_header = self.authorization_header(request)
        b64_header = self.extract_base64_authorization_header(auth_header)
        decoded_header = self.decode_base64_authorization_header(b64_header)
        user, pwd = self.extract_user_credentials(decoded_header)
        return self.user_object_from_credentials(user, pwd)
