#!/usr/bin/env python
# -*- coding: utf-8 -*-
from app import app

try:
    host = app.config['HOST']
except KeyError:
    host = '127.0.0.1'
    

try:
    port = app.config['PORT']
except KeyError:
    port = 5000

app.run(host=host, port=port, threaded=True)
