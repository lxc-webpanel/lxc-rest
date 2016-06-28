# LXC RESTful API
REST API for LXC and LXC WEB PANEL

## Install
```
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
