# Learn passportjs (using jwt strategy)

- express
- typescript
- mongodb
- express-session
- passpotjs

Guide: https://www.youtube.com/watch?v=xMEOT9J0IvI&list=PLYQSCk-qyTW2ewJ05f_GKHtTIzjynDgjK&index=5&ab_channel=ZachGollwitzer

# Getting started
1. `$ npm install` to install dependencies
2. `$ nodemon run index.ts`

# FAQ
1. How to access mongo db?
MongoDB is setup as a container with no volumes (i.e. any thing inside will be lost when the container shutsdown)
```bash
# To findout which container mongo is running on
docker ps

# To gain shell access
docker exec -it <mongo-container-id> bin/bash

# To enter mongo
mongo --host localhost -u root -p example

# To view all Users in mongo db
show dbs;
use learnPassportjs
show collections
db.User.find();

```

# Directories
[./.env](.env)
<br/>
Environment variables. Need to create, if not exist.

[./config/](./config/)
<br/>
Config file to injest values from [./.env](.env).

[./index.ts](./index.ts) ([Video](https://www.youtube.com/watch?v=xMEOT9J0IvI&list=PLYQSCk-qyTW2ewJ05f_GKHtTIzjynDgjK&index=6&ab_channel=ZachGollwitzer ))
<br/>
All the code required to setup passportjs authentication using jwt strategy
