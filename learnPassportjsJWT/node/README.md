# Learn passportjs

- express
- typescript
- mongodb
- express-session
- passpotjs

Guide: https://www.youtube.com/watch?v=xMEOT9J0IvI&list=PLYQSCk-qyTW2ewJ05f_GKHtTIzjynDgjK&index=5&ab_channel=ZachGollwitzer

# Getting started
1. `$ npm install` to install dependencies
2. There are two different examples here - [./localStrategy.ts](./localStrategy.ts) and [./jwt.ts](./jwt.ts). Both are different ways to implement user authentication. 
3. To run either, simply do `$ nodemon run <insert-file-name>`. E.g. `$ nodemon run localStrategy.ts`

# Directories
[./.env](.env)
<br/>
Environment variables. Need to create, if not exist.

[./config/](./config/)
<br/>
Config file to injest values from [./.env](.env).

[./localStrategy.ts](./localStrategy.ts) ([Video](https://www.youtube.com/watch?v=xMEOT9J0IvI&list=PLYQSCk-qyTW2ewJ05f_GKHtTIzjynDgjK&index=6&ab_channel=ZachGollwitzer ))
<br/>
All the code required to setup passportjs authentication using local strategy, i.e. session, tokens.

[./jwt.ts](./jwt.ts).([Video](https://www.youtube.com/watch?v=o6mSdG09yOU&list=PLYQSCk-qyTW2ewJ05f_GKHtTIzjynDgjK&index=9&ab_channel=ZachGollwitzer))
<br/>
All the code required to setup passportjs authentication using jwt.