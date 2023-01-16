# How to setup session based auth with express

Guide: https://youtu.be/F-sFp_AvHc8?t=3904

## Step

### 1. Before login
1. `docker-compose up`
2. Go to http://localhost:8081/db/learnPassportjs/Session. Collection should be empty.
3. Go to http://localhost:4000/
4. Observe there's a `cookie.sid` cookie created at http://localhost:4000/. 
5. Observe there's a session created at http://localhost:8081/db/learnPassportjs/Session
6. There is nothing unique about these cookie or session. It'll be created for every visitor of the site

### 2. Sign up
1. Go to http://localhost:4000/signup to sign up.
2. Observe created session at http://localhost:8081/db/learnPassportjs/Session
```json
{
    _id: '6YqMyeYNpUBm_kGe3ISL4WPb0V0R_1bd',
    expires: ISODate('2023-01-17T13:16:06.435Z'),
    session: '{"cookie":{"originalMaxAge":86399999,"expires":"2023-01-17T13:15:40.148Z","httpOnly":true,"path":"/"}}'
}
```

### 3. Login
1. Login with created account at http://localhost:4000/
2. Observe created session at http://localhost:8081/db/learnPassportjs/Session
```json
{
    _id: 'Xoh7sA1l8hI1ASpAqWZSnZENlKOCnidc',
    expires: ISODate('2023-01-17T14:08:32.509Z'),
    session: '{"cookie":{"originalMaxAge":86400000,"expires":"2023-01-17T14:08:32.493Z","httpOnly":true,"path":"/"},"passport":{"user":"63c54dfc1d168d8b574a17ca"}}'
}
```