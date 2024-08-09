#!/usr/bin/env python3
""" Base class for all auth instances """
from flask import request
from typing import List, TypeVar
import os


class Auth:
    """ Class Auth """

    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """ Returns true if a path is not among excluded paths """
        if path is None or excluded_paths is None:
            return True

        stripped_routes_list = list(map(lambda x: x.rstrip('/'),
                                        excluded_paths))
        # - Implement wildcard matching -
        for p in stripped_routes_list:
            if p.endswith('*'):
                if path.startswith(p.rstrip('*')):
                    return False
        # - ----------- END ----------- -

        if path.rstrip('/') not in stripped_routes_list:
            return True
        return False

    def authorization_header(self, request=None) -> str:
        """ Retreives authorization header if available """
        if request:
            if request.headers.get('Authorization'):
                return request.headers.get('Authorization')
        return None

    def current_user(self, request=None) -> TypeVar('User'):
        """ Does nothing """
        return None

    def session_cookie(self, request=None):
        """ A method that returns a cookie value from a request """
        if request:
            SESSION_NAME = os.getenv('SESSION_NAME')
            if SESSION_NAME:
                return request.cookies.get(SESSION_NAME)
        return None
