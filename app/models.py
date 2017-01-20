#!/usr/bin/env python
# -*- coding: utf-8 -*-
from app import db
from app.exceptions import *
from passlib.apps import custom_app_context as pwd_context
from sqlalchemy.ext.associationproxy import association_proxy


def _role_find(r):
    role = Role.query.get(r)
    if not(role):
        raise RoleDoesntExist(r)
    return role


def _ability_find(a):
    ability = Ability.query.get(a)
    if not(ability):
        raise AbilityDoesntExist(a)
    return ability


def _container_find(c):
    container = Container.query.get(c)
    if not(container):
        raise ContainerDoesntExist(c)
    return container


user_role_table = db.Table(
    'user_role',
    db.Column(
        'user_id',
        db.Integer,
        db.ForeignKey('users.id')
    ),
    db.Column(
        'role_id',
        db.Integer,
        db.ForeignKey('roles.id')
    )
)

role_ability_table = db.Table(
    'role_ability',
    db.Column(
        'role_id',
        db.Integer,
        db.ForeignKey('roles.id')
    ),
    db.Column(
        'ability_id',
        db.Integer,
        db.ForeignKey('abilities.id')
    )
)

user_container_table = db.Table(
    'user_container',
    db.Column(
        'user_id',
        db.Integer,
        db.ForeignKey('users.id')
    ),
    db.Column(
        'container_id',
        db.Integer,
        db.ForeignKey('containers.id')
    )
)


class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255))
    username = db.Column(db.String(60), unique=True)
    email = db.Column(db.String(120))
    password = db.Column(db.String(100))
    _roles = db.relationship(
        'Role',
        secondary=user_role_table,
    )
    roles = association_proxy(
        '_roles',
        'id',
        creator=_role_find
    )
    _containers = db.relationship(
        'Container',
        secondary=user_container_table,
    )
    containers = association_proxy(
        '_containers',
        'id',
        creator=_container_find
    )

    def __init__(
        self,
        name=None,
        username=None,
        email=None,
        password=None,
        roles=None,
        containers=None
    ):

        self.name = name
        self.username = username
        self.email = email
        self.password = password

        if roles and isinstance(roles, list):
            self.roles = [role for role in roles]
        elif roles and isinstance(roles, int):
            self.roles = [roles]
        if containers and isinstance(containers, list):
            self.containers = [container for container in containers]
        elif containers and isinstance(containers, int):
            self.containers = [containers]

    def hash_password(self, password):
        self.password = pwd_context.encrypt(password)

    def verify_password(self, password):
        return pwd_context.verify(password, self.password)

    def add_roles(self, *roles):
        self.roles.extend([role for role in roles if role not in self.roles])

    def remove_roles(self, *roles):
        self.roles = [role for role in self.roles if role not in roles]

    def add_containers(self, *containers):
        self.containers.extend(
            [container for container in containers if container not in self.containers])

    def remove_containers(self, *containers):
        self.containers = [
            container for container in self.containers if container not in containers]


    def __repr__(self):
        return '<User %r>' % self.id


class Role(db.Model):
    __tablename__ = 'roles'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), unique=True)
    _abilities = db.relationship(
        'Ability',
        secondary=role_ability_table
    )
    abilities = association_proxy(
        '_abilities',
        'id',
        creator=_ability_find
    )

    def __init__(
        self,
        name=None,
        abilities=None
    ):

        self.name = name

        if abilities and isinstance(abilities, list):
            self.abilities = [ability for ability in abilities]
        elif abilities and isinstance(abilities, int):
            self.abilities = [abilities]

    def add_abilities(self, *abilities):
        self.abilities.extend(
            [ability for ability in abilities if ability not in self.abilities])

    def remove_abilities(self, *abilities):
        self.abilities = [
            ability for ability in self.abilities if ability not in abilities]

    def __repr__(self):
        return '<Role %r>' % self.id


class Ability(db.Model):
    __tablename__ = 'abilities'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(30), unique=True)

    def __init__(
        self,
        name=None
    ):

        self.name = name

    def __repr__(self):
        return '<Ability %r>' % self.id


class Container(db.Model):
    __tablename__ = 'containers'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), unique=True)

    def __init__(
        self,
        name=None
    ):

        self.name = name

    def __repr__(self):
        return '<Container %r>' % self.id
