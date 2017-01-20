#!/usr/bin/env python
# -*- coding: utf-8 -*-
import sys
import os
sys.path.append(
    os.path.abspath(os.path.join(os.path.dirname(__file__), os.path.pardir)))

from app.models import *


def _run():
    ability1 = Ability(name='users_infos_all')
    ability2 = Ability(name='users_create')
    ability3 = Ability(name='users_infos')
    ability4 = Ability(name='users_update')
    ability5 = Ability(name='users_delete')
    ability6 = Ability(name='groups_infos_all')
    ability7 = Ability(name='groups_create')
    ability8 = Ability(name='groups_infos')
    ability9 = Ability(name='groups_update')
    ability10 = Ability(name='groups_delete')
    ability11 = Ability(name='ct_infos')
    ability12 = Ability(name='ct_create')
    ability13 = Ability(name='ct_update')
    ability14 = Ability(name='ct_delete')
    ability15 = Ability(name='ct_start')
    ability16 = Ability(name='ct_freeze')
    ability17 = Ability(name='ct_unfreeze')
    ability18 = Ability(name='ct_stop')
    ability19 = Ability(name='ct_restart')
    ability20 = Ability(name='lxc_infos')
    ability21 = Ability(name='host_stats')
    ability22 = Ability(name='host_reboot')
    ability23 = Ability(name='me_edit')

    db.session.add(ability1)
    db.session.add(ability2)
    db.session.add(ability3)
    db.session.add(ability4)
    db.session.add(ability5)
    db.session.add(ability6)
    db.session.add(ability7)
    db.session.add(ability8)
    db.session.add(ability9)
    db.session.add(ability10)
    db.session.add(ability11)
    db.session.add(ability12)
    db.session.add(ability13)
    db.session.add(ability14)
    db.session.add(ability15)
    db.session.add(ability16)
    db.session.add(ability17)
    db.session.add(ability18)
    db.session.add(ability19)
    db.session.add(ability20)
    db.session.add(ability21)
    db.session.add(ability22)
    db.session.add(ability23)
    db.session.commit()

    role = Role(
        name='admin'
    )

    role.add_abilities(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12,
                        13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23)

    role2 = Role(
        name='test'
    )

    db.session.add(role)
    db.session.add(role2)
    db.session.commit()

    user = User(
        name='John Doe',
        username='admin',
        roles=[1, 2]
    )

    user.hash_password('admin')

    db.session.add(user)
    db.session.commit()

    # Test
    user = User.query.get(1)
    user.roles = [1]
    db.session.commit()

if __name__ == '__main__':
    _run()
