![LXC Web Panel](https://raw.githubusercontent.com/lxc-webpanel/lxc-webpanel.github.com/master/img/logo-2016-readme.png)

RESTful API for LXC and LXC WEB PANEL

[![Build Status](https://travis-ci.org/lxc-webpanel/lxc-rest.svg?branch=master)](https://travis-ci.org/lxc-webpanel/lxc-rest)
[![Python version](https://img.shields.io/badge/Python-3.5-blue.svg)](https://www.python.org/downloads/release/python-350/)


## Installation
```
apt install python3-lxc

git clone --recursive https://github.com/lxc-webpanel/lxc-rest.git

cd lxc-rest

pip install -r requirements.txt

python3 install/setup.py

python3 run.py
```

## Usage
#### Auth

**POST** /api/v1/auth
```json
{
	"username": string,
	"password": string
}
```

#### Doc
From your browser, get the swagger doc at [http://localhost:5000/doc/](http://localhost:5000/doc/)

## Documentation

* [Swagger](http://petstore.swagger.io/?url=http://lxc-webpanel.github.io/doc/swagger.json)


## Configuration
You can store instance configuration in `instance/config.py`

or

Set your own env var :

`export LWP_CONFIG_FILE='/path/to/config/production.py'`
