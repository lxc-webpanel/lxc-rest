#!/usr/bin/env python
# -*- coding: utf-8 -*-
from flask import jsonify
from app import app, jwt, db, api
from .models import User, Container
from .decorators import import_user
import lxc


@jwt.user_identity_loader
def user_identity_lookup(user):
    return user.id

@app.before_request
def populate_containers_table():
    current_containers_list = lxc.list_containers()
    database_containers_list = [str(i.name) for i in Container.query.all()]

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
