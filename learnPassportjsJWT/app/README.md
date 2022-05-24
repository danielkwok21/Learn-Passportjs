# Learn passportjs (using jwt strategy)

# General philosophy
1. On login, store jwt in local storage
2. On each route access, validate jwt against api
3. If valid, go to protected routes
4. Else, go to public routes

Guide: https://www.youtube.com/watch?v=xMEOT9J0IvI&list=PLYQSCk-qyTW2ewJ05f_GKHtTIzjynDgjK&index=5&ab_channel=ZachGollwitzer

# Getting started
1. `$ yarn` to install dependencies
2. `$ yarn start`

# Directories
[./src/App.js](./src/App.js)
<br/>
Bread and butter. Use "STEP n" comments to help guide flow.