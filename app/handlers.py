#!/usr/bin/env python
# -*- coding: utf-8 -*-
from app import app, jwt, db
from .models import User, Container
import lxc


# @jwt.error_handler
# def error_handler(e):
#     return "Something bad happened", 400


@jwt.authentication_handler
def authenticate(username, password):
    user = User.query.filter_by(username=username).first()

    if not user or not user.verify_password(password):
        return False

    return user


@jwt.identity_handler
def identity(payload):
    print(payload)
    return User.query.get(payload['identity'])

@app.before_request
def populate_containers_table():
    current_containers_list = lxc.list_containers()
    database_containers_list = [str(i) for i in Container.query.all()]

    # Removing old containers from database
    for ct in database_containers_list:
        if not ct in current_containers_list:
            container = Container.query.filter_by(name=ct).first()
            db.session.delete(container)

    # Adding new containers to database
    for ct in current_containers_list:
        if not ct in database_containers_list:
            container = Container(name=ct)
            db.session.add(container)

    db.session.commit()