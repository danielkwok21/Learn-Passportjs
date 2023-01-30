# Learn passportjs (using jwt strategy)

How to authenticate using jwt
- nodejs
- passportjs
- react

# How to use this guide

1. Start up backend & frontend server
2. Sign up a user
3. Login user
4. Refresh home page before 5s. Notice only `GET /profile` endpoint is called.
5. Refresh home page after 5s. Notice `POST /access-token` endpoint is called. 
- access token is detected to be expired, and a request to get a new one using refresh token is called. 
- a new access token & refresh token will be generated, returned, and use for future purposes
- prev refresh token will no longer be valid

6. Refresh home page after 10 of idling. Notice will be redirected back to `/login` page.
- this is because the refresh token expires after 10s. Once it expires, user *must* go back to home page.
- **HIGHLIGHT** the idea is constant activity in the page, and hence frequent refresh of both access token & refresh token will keep the user's session valid

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

3. Need to turn off React.StrictMode to prevent weird bug where `useEffect` is called twice.
   
```diff
root.render(
-    <React.StrictMode>
        <App />
-    </React.StrictMode>
);

```

4. For the refresh token api in frontend, *do not* use axios instance. Else this will happen.
- initial request's interceptor detected token expired, call refresh token api
- refresh token api's interceptor detected token expired, call refresh toekn api again
- infinite loop