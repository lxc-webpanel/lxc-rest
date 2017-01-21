#!/usr/bin/env python
# -*- coding: utf-8 -*-
from app import db
from app.exceptions import *
from passlib.apps import custom_app_context as pwd_context
from sqlalchemy.ext.associationproxy import association_proxy

def _user_find(u):
    user = User.query.get(u)
    if not(user):
        raise UserDoesntExist(u)
    return user

def _group_find(g):
    group = Group.query.get(g)
    if not(group):
        raise GroupDoesntExist(g)
    return group


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


user_group_table = db.Table(
    'user_group',
    db.Column(
        'user_id',
        db.Integer,
        db.ForeignKey('users.id')
    ),
    db.Column(
        'group_id',
        db.Integer,
        db.ForeignKey('groups.id')
    )
)

group_ability_table = db.Table(
    'group_ability',
    db.Column(
        'group_id',
        db.Integer,
        db.ForeignKey('groups.id')
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
    _groups = db.relationship(
        'Group',
        secondary=user_group_table,
    )
    groups = association_proxy(
        '_groups',
        'id',
        creator=_group_find
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
        groups=None,
        containers=None
    ):

        self.name = name
        self.username = username
        self.email = email
        self.password = password

        if groups and isinstance(groups, list):
            self.groups = [group for group in groups]
        elif groups and isinstance(groups, int):
            self.groups = [groups]
        if containers and isinstance(containers, list):
            self.containers = [container for container in containers]
        elif containers and isinstance(containers, int):
            self.containers = [containers]

    def hash_password(self, password):
        self.password = pwd_context.encrypt(password)

    def verify_password(self, password):
        return pwd_context.verify(password, self.password)

    def add_containers(self, *containers):
        self.containers.extend(
            [container for container in containers if container not in self.containers])

    def remove_containers(self, *containers):
        self.containers = [
            container for container in self.containers if container not in containers]


    def __repr__(self):
        return '<User %r>' % self.id


class Group(db.Model):
    __tablename__ = 'groups'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), unique=True)
    _abilities = db.relationship(
        'Ability',
        secondary=group_ability_table
    )
    abilities = association_proxy(
        '_abilities',
        'id',
        creator=_ability_find
    )
    _users = db.relationship(
        'User',
        secondary=user_group_table,
    )
    users = association_proxy(
        '_users',
        'id',
        creator=_user_find
    )


    def __init__(
        self,
        name=None,
        abilities=None,
        users=None
    ):

        self.name = name

        if abilities and isinstance(abilities, list):
            self.abilities = [ability for ability in abilities]
        elif abilities and isinstance(abilities, int):
            self.abilities = [abilities]

        if users and isinstance(users, list):
            self.users = [user for user in users]
        elif users and isinstance(users, int):
            self.users = [users]

    def __repr__(self):
        return '<Group %r>' % self.id


class Ability(db.Model):
    __tablename__ = 'abilities'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(30), unique=True)
    _groups = db.relationship(
        'Group',
        secondary=group_ability_table
    )
    groups = association_proxy(
        '_groups',
        'id',
        creator=_group_find
    )

    def __init__(
        self,
        name=None,
        groups=None
    ):

        self.name = name

        if groups and isinstance(groups, list):
            self.groups = [group for group in groups]
        elif groups and isinstance(groups, int):
            self.groups = [groups]

    def __repr__(self):
        return '<Ability %r>' % self.id


class Container(db.Model):
    __tablename__ = 'containers'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), unique=True)
    _users = db.relationship(
        'User',
        secondary=user_container_table,
    )
    users = association_proxy(
        '_users',
        'id',
        creator=_user_find
    )

    def __init__(
        self,
        name=None,
        users=None
    ):

        self.name = name

        if users and isinstance(users, list):
            self.users = [user for user in users]
        elif users and isinstance(users, int):
            self.users = [users]

    def __repr__(self):
        return '<Container %r>' % self.id
