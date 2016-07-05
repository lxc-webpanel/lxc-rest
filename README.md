![LXC Web Panel](https://raw.githubusercontent.com/lxc-webpanel/lxc-webpanel.github.com/master/img/logo-2016-readme.png)

RESTful API for LXC and LXC WEB PANEL

## Requirements
```
apt install python3-lxc
pip install flask==0.10
pip install Flask-SQLAlchemy
```

## Run
```
python3 server.py
```

## Auth 
> **POST** /api/v1/auth
>> Headers: `Content-Type: application/json`

>> Body:
```
{
  "username" : "admin",
  "password" : "admin"
}
```

## Usage
> **GET/POST/PUT/DELETE** /api/v1/\<route\>
>> Headers:
```
Content-Type: application/json
Authorization: Bearer <auth key>
```

>> Body:
```
{
  "foo" : "bar"
}
```
