#!/usr/bin/env python
# -*- coding: utf-8 -*-
import sys
import os
sys.path.append(
    os.path.abspath(os.path.join(os.path.dirname(__file__), os.path.pardir)))

from app.models import *


def _run():
    ability = Ability(name='users_infos_all')
    db.session.add(ability)
    ability = Ability(name='users_create')
    db.session.add(ability)
    ability = Ability(name='users_infos')
    db.session.add(ability)
    ability = Ability(name='users_update')
    db.session.add(ability)
    ability = Ability(name='users_delete')
    db.session.add(ability)
    ability = Ability(name='groups_infos_all')
    db.session.add(ability)
    ability = Ability(name='groups_create')
    db.session.add(ability)
    ability = Ability(name='groups_infos')
    db.session.add(ability)
    ability = Ability(name='groups_update')
    db.session.add(ability)
    ability = Ability(name='groups_delete')
    db.session.add(ability)
    ability = Ability(name='abilities_infos_all')
    db.session.add(ability)
    ability = Ability(name='abilities_infos')
    db.session.add(ability)
    ability = Ability(name='abilities_update')
    db.session.add(ability)
    ability = Ability(name='ct_infos')
    db.session.add(ability)
    ability = Ability(name='ct_create')
    db.session.add(ability)
    ability = Ability(name='ct_update')
    db.session.add(ability)
    ability = Ability(name='ct_delete')
    db.session.add(ability)
    ability = Ability(name='ct_start')
    db.session.add(ability)
    ability = Ability(name='ct_freeze')
    db.session.add(ability)
    ability = Ability(name='ct_unfreeze')
    db.session.add(ability)
    ability = Ability(name='ct_stop')
    db.session.add(ability)
    ability = Ability(name='ct_restart')
    db.session.add(ability)
    ability = Ability(name='lxc_infos')
    db.session.add(ability)
    ability = Ability(name='host_stats')
    db.session.add(ability)
    ability = Ability(name='host_reboot')
    db.session.add(ability)
    ability = Ability(name='me_edit')
    db.session.add(ability)

    db.session.commit()

    role = Group(
        name='admin',
        abilities=[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12,
                   13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26]
    )

    role2 = Group(
        name='test'
    )

    db.session.add(role)
    db.session.add(role2)
    db.session.commit()

    user = User(
        name='John Doe',
        username='admin',
        groups=[1, 2]
    )

    user.hash_password('admin')

    db.session.add(user)
    db.session.commit()

    # Test
    user = User.query.get(1)
    user.groups = [1]
    db.session.commit()

if __name__ == '__main__':
    _run()
