#!/usr/bin/env python -W ignore
# -*- coding: utf-8 -*-
import sys
sys.path.append('../')
import os

from app import app, db
from install import populate_db

import unittest
import tempfile
import json
import time


class AppTestCase(unittest.TestCase):
    token = None

    def setUp(self):
        self.db_fd, app.config['DATABASE'] = tempfile.mkstemp()
        app.config[
            'SQLALCHEMY_DATABASE_URI'] = 'sqlite:///%s \
            ' % app.config['DATABASE']
        app.testing = True
        self.app = app.test_client()
        with app.app_context():
            db.create_all()
            populate_db._run()

    def tearDown(self):
        os.close(self.db_fd)
        os.unlink(app.config['DATABASE'])

    def test_001_get_auth(self):
        rv = self.app.post('/api/v1/auth', data=json.dumps({
            'username': 'admin',
            'password': 'admin'
        }), content_type='application/json')
        rj = json.loads(rv.get_data(as_text=True))

        self.assertEqual(rv.status_code, 200)
        self.assertIn('access_token', rj)
        self.__class__.token = rj['access_token']

    def test_002_get_auth_refresh(self):
        rv = self.app.post(
            '/api/v1/auth/refresh', headers={
                'Authorization': 'Bearer %s' % self.__class__.token
            })
        rj = json.loads(rv.get_data(as_text=True))

        self.assertEqual(rv.status_code, 200)
        self.assertIn('access_token', rj)

    def test_003_get_auth_check(self):
        rv = self.app.get(
            '/api/v1/auth/check', headers={
                'Authorization': 'Bearer %s' % self.__class__.token
            })
        rj = json.loads(rv.get_data(as_text=True))

        self.assertEqual(rv.status_code, 200)
        self.assertEqual(rj, {})

    def test_004_get_auth_check_wrong_token(self):
        rv = self.app.get(
            '/api/v1/auth/check', headers={
                'Authorization': 'Bearer ODAZHIJDIOAZN'
            })
        rj = json.loads(rv.get_data(as_text=True))

        self.assertEqual(rv.status_code, 422)

    def test_005_get_lwp_users(self):
        rv = self.app.get(
            '/api/v1/lwp/users', headers={
                'Authorization': 'Bearer %s' % self.__class__.token
            })
        rj = json.loads(rv.get_data(as_text=True))

        self.assertEqual(rv.status_code, 200)
        self.assertEqual(len(rj['data']), 1)
        self.assertEqual(rj['data'][0]['id'], 1)
        self.assertEqual(rj['data'][0]['type'], 'users')

    def test_006_get_lwp_users_1(self):
        rv = self.app.get(
            '/api/v1/lwp/users/1', headers={
                'Authorization': 'Bearer %s' % self.__class__.token
            })
        rj = json.loads(rv.get_data(as_text=True))

        self.assertEqual(rv.status_code, 200)
        self.assertEqual(rj['data']['id'], 1)
        self.assertTrue(rj['data']['attributes']['admin'])
        self.assertEqual(rj['data']['attributes']['username'], 'admin')
        self.assertEqual(rj['data']['attributes']['name'], 'John Doe')
        self.assertIsNone(rj['data']['attributes']['email'])
        self.assertEqual(rj['data']['type'], 'users')

    def test_901_put_lwp_users_1(self):
        rv = self.app.put(
            '/api/v1/lwp/users/1',
            data=json.dumps({
                "data": {
                    "relationships": {
                        "groups": {
                            "data": []
                        }
                    },
                    "attributes": {
                        "admin": False,
                        "email": "elie@deloumeau.fr",
                        "name": "Élie Deloumeau",
                        "password": "elie",
                    },
                    "type": "users"
                }
            }),
            content_type='application/json',
            headers={
                'Authorization': 'Bearer %s' % self.__class__.token
            })
        rj = json.loads(rv.get_data(as_text=True))

        self.assertEqual(rv.status_code, 200)
        self.assertEqual(rj['data']['id'], 1)
        self.assertFalse(rj['data']['attributes']['admin'])
        self.assertEqual(rj['data']['attributes']['username'], 'admin')
        self.assertEqual(rj['data']['attributes']['name'], 'Élie Deloumeau')
        self.assertEqual(rj['data']['attributes'][
                         'email'], 'elie@deloumeau.fr')
        self.assertEqual(rj['data']['type'], 'users')

    # def test_801_delete_lwp_users_1(self):
    #     rv = self.app.delete(
    #         '/api/v1/lwp/users/1',
    #         headers={
    #             'Authorization': 'Bearer %s' % self.__class__.token
    #         })
    #     print(rv.get_data(as_text=True))
    #     rj = json.loads(rv.get_data(as_text=True))

    #     # Assert token error : Not enough segments
    #     self.assertEqual(rv.status_code, 422)
    #     self.assertEqual(rj['msg'], 'Not enough segments')

    def test_007_post_lwp_users(self):
        rv = self.app.post(
            '/api/v1/lwp/users',
            data=json.dumps({
                "data": {
                    "relationships": {
                        "groups": {
                            "data": [
                                {
                                    "id": 1,
                                    "type": "groups"
                                }
                            ]
                        }
                    },
                    "attributes": {
                        "admin": False,
                        "email": "test@test.test",
                        "name": "test",
                        "password": "test",
                        "username": "test"
                    },
                    "type": "users"
                }
            }),
            content_type='application/json',
            headers={
                'Authorization': 'Bearer %s' % self.__class__.token
            })
        rj = json.loads(rv.get_data(as_text=True))

        self.assertEqual(rv.status_code, 201)
        self.assertEqual(rj['data']['id'], 2)
        self.assertFalse(rj['data']['attributes']['admin'])
        self.assertEqual(rj['data']['attributes']['username'], 'test')
        self.assertEqual(rj['data']['attributes']['name'], 'test')
        self.assertEqual(rj['data']['attributes']['email'], 'test@test.test')
        self.assertEqual(rj['data']['type'], 'users')

    def test_008_get_lwp_me(self):
        rv = self.app.get(
            '/api/v1/lwp/me', headers={
                'Authorization': 'Bearer %s' % self.__class__.token
            })
        rj = json.loads(rv.get_data(as_text=True))

        self.assertEqual(rv.status_code, 200)
        self.assertEqual(rj['data']['id'], 1)
        self.assertTrue(rj['data']['attributes']['admin'])
        self.assertEqual(rj['data']['attributes']['username'], 'admin')
        self.assertEqual(rj['data']['attributes']['name'], 'John Doe')
        self.assertIsNone(rj['data']['attributes']['email'])
        self.assertEqual(rj['data']['type'], 'users')

    def test_902_put_lwp_me(self):
        rv = self.app.put(
            '/api/v1/lwp/me',
            data=json.dumps({
                "data": {
                    "attributes": {
                        "admin": False,
                        "email": "elie@deloumeau.fr",
                        "name": "Élie Deloumeau",
                        "password": "elie",
                    },
                    "type": "users"
                }
            }),
            content_type='application/json',
            headers={
                'Authorization': 'Bearer %s' % self.__class__.token
            })
        rj = json.loads(rv.get_data(as_text=True))

        self.assertEqual(rv.status_code, 200)
        self.assertEqual(rj['data']['id'], 1)
        self.assertFalse(rj['data']['attributes']['admin'])
        self.assertEqual(rj['data']['attributes']['username'], 'admin')
        self.assertEqual(rj['data']['attributes']['name'], 'Élie Deloumeau')
        self.assertEqual(rj['data']['attributes'][
                         'email'], 'elie@deloumeau.fr')
        self.assertEqual(rj['data']['type'], 'users')

    # def test_802_delete_me(self):
    #     rv = self.app.delete(
    #         '/api/v1/lwp/me',
    #         headers={
    #             'Authorization': 'Bearer %s' % self.__class__.token
    #         })
    #     rj = json.loads(rv.get_data(as_text=True))

    #     self.assertEqual(rv.status_code, 422)
    #     self.assertEqual(rj['msg'], 'Not enough segments')

    def test_009_get_lwp_groups(self):
        rv = self.app.get(
            '/api/v1/lwp/groups', headers={
                'Authorization': 'Bearer %s' % self.__class__.token
            })
        rj = json.loads(rv.get_data(as_text=True))

        self.assertEqual(rv.status_code, 200)
        self.assertEqual(len(rj['data']), 1)
        self.assertEqual(rj['data'][0]['id'], 1)
        self.assertEqual(rj['data'][0]['type'], 'groups')

    def test_010_get_lwp_groups_1(self):
        rv = self.app.get(
            '/api/v1/lwp/groups/1', headers={
                'Authorization': 'Bearer %s' % self.__class__.token
            })
        rj = json.loads(rv.get_data(as_text=True))

        self.assertEqual(rv.status_code, 200)
        self.assertEqual(rj['data']['id'], 1)
        self.assertEqual(rj['data']['attributes']['name'], 'admin')
        self.assertEqual(rj['data']['type'], 'groups')

    def test_903_put_lwp_groups_1(self):
        rv = self.app.put(
            '/api/v1/lwp/groups/1',
            data=json.dumps({
                "data": {
                    "relationships": {
                        "abilities": {
                            "data": [
                                {
                                    "id": 1,
                                    "type": "abilities"
                                },
                                {
                                    "id": 5,
                                    "type": "abilities"
                                }
                            ]
                        },
                        "users": {
                            "data": [
                                {
                                    "id": 1,
                                    "type": "users"
                                }
                            ]
                        }
                    },
                    "attributes": {
                        "name": "admin-test",
                    },
                    "type": "groups"
                }
            }),
            content_type='application/json',
            headers={
                'Authorization': 'Bearer %s' % self.__class__.token
            })
        rj = json.loads(rv.get_data(as_text=True))

        self.assertEqual(rv.status_code, 200)
        self.assertEqual(rj['data']['id'], 1)
        self.assertEqual(rj['data']['attributes']['name'], 'admin-test')
        self.assertEqual(rj['data']['type'], 'groups')

    # def test_802_delete_lwp_groups_1(self):
    #     rv = self.app.delete(
    #         '/api/v1/lwp/groups/1',
    #         headers={
    #             'Authorization': 'Bearer %s' % self.__class__.token
    #         })
    #     print(rv.get_data(as_text=True))
    #     rj = json.loads(rv.get_data(as_text=True))

    #     self.assertEqual(rv.status_code, 422)
    #     self.assertEqual(rj['msg'], 'Not enough segments')

    def test_011_post_lwp_groups(self):
        rv = self.app.post(
            '/api/v1/lwp/groups',
            data=json.dumps({
                "data": {
                    "relationships": {
                        "abilities": {
                            "data": [
                                {
                                    "id": 1,
                                    "type": "abilities"
                                },
                                {
                                    "id": 5,
                                    "type": "abilities"
                                }
                            ]
                        },
                        "users": {
                            "data": [
                                {
                                    "id": 1,
                                    "type": "users"
                                }
                            ]
                        }
                    },
                    "attributes": {
                        "name": "test"
                    },
                    "type": "groups"
                }
            }),
            content_type='application/json',
            headers={
                'Authorization': 'Bearer %s' % self.__class__.token
            })
        rj = json.loads(rv.get_data(as_text=True))

        self.assertEqual(rv.status_code, 201)
        self.assertEqual(rj['data']['id'], 2)
        self.assertEqual(rj['data']['attributes']['name'], 'test')
        self.assertEqual(rj['data']['type'], 'groups')

    def test_012_get_lwp_abilities(self):
        rv = self.app.get(
            '/api/v1/lwp/abilities', headers={
                'Authorization': 'Bearer %s' % self.__class__.token
            })
        rj = json.loads(rv.get_data(as_text=True))

        self.assertEqual(rv.status_code, 200)
        self.assertEqual(len(rj['data']), 27)
        self.assertEqual(rj['data'][0]['id'], 1)
        self.assertEqual(rj['data'][0]['type'], 'abilities')

    def test_013_get_lwp_abilities_1(self):
        rv = self.app.get(
            '/api/v1/lwp/abilities/1', headers={
                'Authorization': 'Bearer %s' % self.__class__.token
            })
        rj = json.loads(rv.get_data(as_text=True))

        self.assertEqual(rv.status_code, 200)
        self.assertEqual(rj['data']['id'], 1)
        self.assertEqual(rj['data']['attributes']['name'], 'users_infos_all')
        self.assertEqual(rj['data']['type'], 'abilities')

    def test_904_put_lwp_abilities_1(self):
        rv = self.app.put(
            '/api/v1/lwp/abilities/1',
            data=json.dumps({
                "data": {
                    "relationships": {
                        "groups": {
                            "data": [
                                {
                                    "id": 1,
                                    "type": "groups"
                                }
                            ]
                        }
                    },
                    "type": "abilities"
                }
            }),
            content_type='application/json',
            headers={
                'Authorization': 'Bearer %s' % self.__class__.token
            })
        rj = json.loads(rv.get_data(as_text=True))

        self.assertEqual(rv.status_code, 200)
        self.assertEqual(rj['data']['id'], 1)
        self.assertEqual(rj['data']['attributes']['name'], 'users_infos_all')
        self.assertEqual(rj['data']['type'], 'abilities')

    def test_014_get_lwp_host(self):
        rv = self.app.get(
            '/api/v1/lwp/host', headers={
                'Authorization': 'Bearer %s' % self.__class__.token
            })
        rj = json.loads(rv.get_data(as_text=True))

        self.assertEqual(rv.status_code, 200)
        self.assertEqual(rj['data']['id'], 1)
        self.assertIn('Ubuntu', rj['data']['attributes']['distrib'])
        self.assertEqual(rj['data']['type'], 'stats')

    def test_201_get_lxc_containers(self):
        rv = self.app.get(
            '/api/v1/lxc/containers', headers={
                'Authorization': 'Bearer %s' % self.__class__.token
            })
        rj = json.loads(rv.get_data(as_text=True))

        self.assertEqual(rv.status_code, 200)
        self.assertEqual(len(rj['data']), 0)

    def test_202_post_lxc_containers(self):
        rv = self.app.post(
            '/api/v1/lxc/containers',
            data=json.dumps({
                "data": {
                    "relationships": {
                        "users": {
                            "data": [
                                {
                                    "id": 1,
                                    "type": "users"
                                }
                            ]
                        }
                    },
                    "attributes": {
                        "lxc": {
                            "cgroup": {
                                "cpuset": {
                                    "cpus": [
                                        "0"
                                    ]
                                },
                                "memory": {
                                    "limit_in_bytes": [
                                        "100000000"
                                    ]
                                }
                            },
                            "environment": [
                                "TEST=env"
                            ],
                            "group": [
                                "test1"
                            ],
                            "network": [
                                {
                                    "ipv4": {
                                        "_": [
                                            "10.0.0.1/24",
                                            "10.0.0.2/24"
                                        ],
                                        "gateway": "10.0.0.254"
                                    }
                                }
                            ],
                            "start": {
                                "auto": "1",
                                "delay": "2",
                                "order": "0"
                            }
                        },
                        "name": "test1",
                        "template": {
                            "name": "ubuntu"
                        }
                    },
                    "type": "containers"
                }
            }),
            content_type='application/json',
            headers={
                'Authorization': 'Bearer %s' % self.__class__.token
            })
        rj = json.loads(rv.get_data(as_text=True))

        self.assertEqual(rv.status_code, 201)
        self.assertEqual(rj['data']['id'], 1)
        self.assertEqual(
            rj['data']['relationships']['users']['data'][0]['id'], 1
        )
        self.assertEqual(
            rj['data']['attributes']['lxc']['cgroup']['cpuset']['cpus'][0], '0'
        )
        self.assertEqual(
            rj['data']['attributes']['lxc']['cgroup'][
                'memory']['limit_in_bytes'], ['100000000']
        )
        self.assertEqual(
            rj['data']['attributes']['lxc']['environment'][0], 'TEST=env'
        )
        self.assertEqual(
            rj['data']['attributes']['lxc']['group'][0], 'test1'
        )
        self.assertEqual(
            rj['data']['attributes']['lxc']['network'][0]['ipv4']['_'],
            [
                "10.0.0.1/24",
                "10.0.0.2/24"
            ]
        )
        self.assertEqual(
            rj['data']['attributes']['lxc']['start'],
            {
                "auto": "1",
                "delay": "2",
                "order": "0"
            }
        )
        self.assertEqual(
            rj['data']['attributes']['lxc']['utsname'], 'test1'
        )
        self.assertEqual(
            rj['data']['attributes']['name'], 'test1'
        )
        self.assertEqual(rj['data']['type'], 'containers')

    def test_203_post_lxc_containers_1_start(self):
        rv = self.app.post(
            '/api/v1/lxc/containers/1/start',
            headers={
                'Authorization': 'Bearer %s' % self.__class__.token
            })

        self.assertEqual(rv.status_code, 204)

    def test_204_post_lxc_containers_1_freeze(self):
        rv = self.app.post(
            '/api/v1/lxc/containers/1/freeze',
            headers={
                'Authorization': 'Bearer %s' % self.__class__.token
            })

        self.assertEqual(rv.status_code, 204)

    def test_205_post_lxc_containers_1_unfreeze(self):
        rv = self.app.post(
            '/api/v1/lxc/containers/1/unfreeze',
            headers={
                'Authorization': 'Bearer %s' % self.__class__.token
            })

        self.assertEqual(rv.status_code, 204)

    def test_206_post_lxc_containers_1_shutdown(self):
        rv = self.app.post(
            '/api/v1/lxc/containers/1/shutdown',
            headers={
                'Authorization': 'Bearer %s' % self.__class__.token
            })

        self.assertEqual(rv.status_code, 204)

    def test_207_post_lxc_containers_1_clone(self):
        rv = self.app.post(
            '/api/v1/lxc/containers/1/clone',
            data=json.dumps({
                "data": {
                    "attributes": {
                        "name": "test2"
                    },
                    "type": "containers"
                }
            }),
            content_type='application/json',
            headers={
                'Authorization': 'Bearer %s' % self.__class__.token
            })
        rj = json.loads(rv.get_data(as_text=True))

        self.assertEqual(rv.status_code, 201)
        self.assertEqual(rj['data']['id'], 2)
        self.assertEqual(
            rj['data']['relationships']['users']['data'][0]['id'], 1
        )
        self.assertEqual(
            rj['data']['attributes']['lxc']['cgroup']['cpuset']['cpus'][0], '0'
        )
        self.assertEqual(
            rj['data']['attributes']['lxc']['cgroup'][
                'memory']['limit_in_bytes'], ['100000000']
        )
        self.assertEqual(
            rj['data']['attributes']['lxc']['environment'][0], 'TEST=env'
        )
        self.assertEqual(
            rj['data']['attributes']['lxc']['group'][0], 'test1'
        )
        self.assertEqual(
            rj['data']['attributes']['lxc']['network'][0]['ipv4']['_'],
            [
                "10.0.0.1/24",
                "10.0.0.2/24"
            ]
        )
        self.assertEqual(
            rj['data']['attributes']['lxc']['start'],
            {
                "auto": "1",
                "delay": "2",
                "order": "0"
            }
        )
        self.assertEqual(
            rj['data']['attributes']['lxc']['utsname'], 'test2'
        )
        self.assertEqual(
            rj['data']['attributes']['name'], 'test2'
        )
        self.assertEqual(rj['data']['type'], 'containers')

    def test_208_delete_lxc_containers_1(self):
        rv = self.app.delete(
            '/api/v1/lxc/containers/1',
            headers={
                'Authorization': 'Bearer %s' % self.__class__.token
            })

        self.assertEqual(rv.status_code, 204)

    def test_209_delete_lxc_containers_2(self):
        # Now id 1
        rv = self.app.delete(
            '/api/v1/lxc/containers/1',
            headers={
                'Authorization': 'Bearer %s' % self.__class__.token
            })

        self.assertEqual(rv.status_code, 204)


if __name__ == '__main__':
    unittest.main()
