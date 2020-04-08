# Secure-FStorage: Web Application
Written in Golang, the web app allows users to securely store and retrieve their files from the server.

Author: Suleman Ahmad  
https://www.linkedin.com/in/sulemanahmadd/

**NOTE: Under Development Phase. Code is NOT recommended to be used in production**

## Description
Anyone can use and deploy this web app to provide an interface for secure file storage to their clients. Both performance
and security has been the main motivation behind this work. The app allows authenticated users to store and retrieve their
files/notes. All files uploaded by a user are encrypted and are only accessible by an authorized user. Care has been taken to use
best defense practices against [OWASP top 10](https://owasp.org/www-project-top-ten/), although the development is currently over 
HTTP (future version will have integration with [Caddy Server](https://caddyserver.com/) allowing testing over HTTPS).

## Requirements
```
Docker version 19.03.6
Docker-compose version 1.21.0
```

## Installation and Deployment
Open your terminal and clone this repository:
```
git clone https://github.com/SulemanAhmadd/Secure-FStorage.git
```
Go inside the project directory where Docker files are and type in terminal:
```
docker-compose up --build
```

This will start all the docker containers. Wait for the following message to show up on the terminal:\
`** Web Server Started on Port 8080 **`

I hope it was super easy to set up. Open your browser and go to the following url:\
http://localhost:8080


*Note:* For closing and rebuilding the app, please make sure all previous containers have been stopped or removed:
```
docker-compose down
```
This allows rebuilding the database everytime without getting 'table already exists' error for postgres container.

## Future Tasks
- Integrate and configure Caddy reverse proxy for testing over TLS
- Use React for developing front end
- Increasing functionality and adding more features (e.g File delete feature, Forgot password feature, etc)
- Improving file encryption scheme by using RSA private key instead of password derived keys
- Using Amazon S3 buckets to store user files

## Note:
This project is open for contribution and code review.
