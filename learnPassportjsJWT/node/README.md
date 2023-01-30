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

# To show collections in mongo db
show dbs;
use learnPassportjs
show collections

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


# Hard lessons
1. `iat` in jwt's payload must be in seconds, NOT milliseconds
```javascript
    const expiresIn = '5s'

    const payload = {
        sub: user._id,
        iat: Date.now() / 1000,  // <--- MUST BE IN SECONDS
    }

    const privateKey = fs.readFileSync(path.join(__dirname, './dummy_private_key.pem'))

    const signedToken = jsonwebtoken.sign(payload, privateKey, { expiresIn: expiresIn, algorithm: 'RS256' })

```

2. `failed to solve with frontend dockerfile.v0: failed to build LLB: executor failed running - runc did not terminate sucessfully`
```bash
# Export these 2 vars into the terminal session before starting container
export DOCKER_BUILDKIT=0
export COMPOSE_DOCKER_CLI_BUILD=0

docker-compose up

```