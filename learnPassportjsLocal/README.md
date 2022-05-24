# Learn passportjs (using local strategy)

- express
- typescript
- mongodb
- express-session
- passpotjs

Guide: https://www.youtube.com/watch?v=xMEOT9J0IvI&list=PLYQSCk-qyTW2ewJ05f_GKHtTIzjynDgjK&index=5&ab_channel=ZachGollwitzer

# Getting started
1. `$ npm install` to install dependencies
2. `$ nodemon run index.ts`

# Directories
[./.env](.env)
<br/>
Environment variables. Need to create, if not exist.

[./config/](./config/)
<br/>
Config file to injest values from [./.env](.env).

[./index.ts](./index.ts) ([Video](https://www.youtube.com/watch?v=xMEOT9J0IvI&list=PLYQSCk-qyTW2ewJ05f_GKHtTIzjynDgjK&index=6&ab_channel=ZachGollwitzer ))
<br/>
All the code required to setup passportjs authentication using local strategy, i.e. session, tokens.