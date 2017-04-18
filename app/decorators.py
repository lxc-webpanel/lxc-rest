#!/usr/bin/env python
# -*- coding: utf-8 -*-
from functools import wraps
from werkzeug.exceptions import Forbidden
from .models import *


def import_user():
    try:
        from flask_jwt_extended import get_jwt_identity
        current_identity = User.query.get(int(get_jwt_identity()))
        return current_identity
    except ImportError:
        raise ImportError(
            'User argument not passed')


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
            for group in current_identity._groups:
                user_abilities += group.abilities
            if desired_ability.id in user_abilities or current_identity.admin:
                return func(*args, **kwargs)
            else:
                raise Forbidden("You do not have access")
        return inner
    return wrapper
