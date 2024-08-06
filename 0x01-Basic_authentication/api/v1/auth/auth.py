#!/usr/bin/env python3
""" Auth module """
from flask import request
from typing import List, TypeVar


class Auth:
    """ Auth class """
    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """
        returns False - path and excluded_paths
        """
        check = path
        if path is None or excluded_paths is None or len(excluded_paths) == 0:
            return True
        if path[-1] != "/":
            check += "/"
        if check in excluded_paths or path in excluded_paths:
            return False
        return True

    def authorization_header(self, request=None) -> str:
        """ Returns None """
        if request is None or "Authorization" not in request.headers:
            return None
        return request.headers["Authorization"]

    def current_user(self, request=None) -> TypeVar('User'):
        """ Returns None """
        return None
