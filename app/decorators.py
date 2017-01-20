#!/usr/bin/env python
# -*- coding: utf-8 -*-
from functools import wraps
from werkzeug.exceptions import Forbidden
from .models import *


def import_user():
    try:
        from flask_jwt import current_identity
        return current_identity
    except ImportError:
        raise ImportError(
            'User argument not passed and Flask-Login current_identity could not be imported.')


def user_has(ability, get_user=import_user):
    """
    Takes an ability (a string name of either a role or an ability) and returns the function if the user has that ability
    """
    def wrapper(func):
        @wraps(func)
        def inner(*args, **kwargs):
            desired_ability = Ability.query.filter_by(
                name=ability).first()
            user_abilities = []
            current_identity = get_user()
            for role in current_identity._roles:
                user_abilities += role.abilities
            if desired_ability.id in user_abilities:
                return func(*args, **kwargs)
            else:
                raise Forbidden("You do not have access")
        return inner
    return wrapper


# def user_is(role, get_user=import_user):
#     """
#     Takes an role (a string name of either a role or an ability) and returns the function if the user has that role
#     """
#     def wrapper(func):
#         @wraps(func)
#         def inner(*args, **kwargs):
#             current_identity = get_user()
#             if role in current_identity.roles:
#                 return func(*args, **kwargs)
#             raise Forbidden("You do not have access")
#         return inner
#     return wrapper
