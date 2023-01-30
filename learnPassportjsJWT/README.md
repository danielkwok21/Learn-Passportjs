# Learn passportjs (using jwt strategy)

How to authenticate using jwt
- nodejs
- passportjs
- react

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