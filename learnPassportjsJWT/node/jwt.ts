import bodyParser from 'body-parser';
import MongoStore from 'connect-mongo';
import cookieParser from 'cookie-parser';
import crypto from 'crypto';
import express, { NextFunction, Request, Response } from 'express';
import sessions from 'express-session';
import { MongoClient, ObjectId } from 'mongodb';
import passport from 'passport';
import fs from 'fs'
import path from 'path'
import {
    Strategy as JwtStrategy, ExtractJwt, StrategyOptions
} from 'passport-jwt'
import jsonwebtoken = require('jsonwebtoken')
import config from './config';

const app = express();


/**
 * --------------SETUP DB--------------
 */
const url = `mongodb://${config.database.user}:${config.database.password}@${config.database.host}:${config.database.port}`
const client = new MongoClient(url)

client.connect()
    .then(() => {
        console.log('DB connected')
    })

/**
 * daniel.kwok 12/5/2022
 * For standard db crud 
*/
const db = client.db(config.database.name)

/**
 * daniel.kwok 12/5/2022
 * For session crud, used by express-session and passportjwt
 */
const sessionStore = MongoStore.create({
    mongoUrl: url,
    dbName: config.database.name,
    collectionName: `Session`
})

/**
 * --------------SETUP PASSPORTJWT--------------
 */
/**
 * 18/5/2022 daniel.kwok
 * passportjwt magic, A callback function to call once jwt token is validated
 * unlike local strategy, we don't need to validate it manually. 
 * The moment this callback function is invoked, it's already validated
 * Function name can be custom, but function interface must be constant as shown here
 */
const verifyCallback = async (payload: any, onDone: Function) => {
    try {
        const user = await db.collection("User").findOne({
            username: payload.sub,
        }) as User

        if (!user) return onDone(null, false)

        return onDone(null, user)

    } catch (err) {
        return onDone(err, false)
    }
}

const options: StrategyOptions = {
    jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
    secretOrKey: fs.readFileSync(path.join(__dirname, './dummy_public_key.pem')),
    algorithms: ['RS256'],
}

const strategy = new JwtStrategy(options, verifyCallback)
passport.use(strategy)


/**
 * --------------INJECTING MIDDLEWARE--------------
 */
app.use(bodyParser.urlencoded({ extended: false }))
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(sessions({
    secret: config.sessionSecret,
    saveUninitialized: true,
    cookie: {
        maxAge: 1000 * 60 * 60 * 24 // one day in ms
    },
    resave: false,
    store: sessionStore
}));
app.use(passport.initialize())
app.use(passport.session())



/**
 * --------------TYPE DECLARATIONS--------------
 */
type User = {
    _id?: ObjectId
    username: string,
    salt: string,
    hash: string,
    isAdmin?: boolean,
}


/**
 * --------------API routes--------------
 */
app.post('/login', async (req, res) => {

    const {
        uname, pw
    } = req.body

    try {
        const user = await db.collection("User").findOne({
            username: uname,
        }) as User

        if (!user) throw new Error(`No user found`)
        const hashedPassword = crypto.pbkdf2Sync(pw, user.salt, 10000, 64, 'sha512').toString('hex')
        const isValidPassword = hashedPassword === user.hash

        if (!isValidPassword) throw new Error(`Wrong username or password provided`)

        const {
            token, expires
        } = issueJWT(user)

        res.json({
            success: true,
            user: user,
            token: token,
            expiresIn: expires,
        })

    } catch (err) {
        res.status(401).json({
            success: false,
            message: err.message
        })
    }
})

app.post('/signup', async (req, res) => {
    const body: {
        uname: string,
        pw: string,
        isAdmin: boolean
    } = req.body

    const {
        salt, hash
    } = generatePassword(body.pw)

    const user: User = {
        username: body.uname,
        salt: salt,
        hash: hash,
        isAdmin: body.isAdmin,
    }

    const tx = await db.collection('User').insertOne(user)

    user._id = tx.insertedId

    const {
        token, expires
    } = issueJWT(user)


    res.json({
        success: true,
        user: user,
        token: token,
        expiresIn: expires,
    })

    function generatePassword(passwordPlain: string): { salt: string, hash: string } {
        const salt = crypto.randomBytes(32).toString('hex')
        const hash = crypto.pbkdf2Sync(passwordPlain, salt, 10000, 64, 'sha512').toString('hex')

        return {
            salt,
            hash
        }
    }
})

function issueJWT(user: User): { token: string, expires: string } {
    const payload: {
        sub?: ObjectId,
        iat: number,
    } = {
        sub: user._id,
        iat: Date.now()
    }

    const expiresIn = '1d'

    const privateKey = fs.readFileSync(path.join(__dirname, './dummy_private_key.pem'))

    const signedToken = jsonwebtoken.sign(payload, privateKey, { expiresIn: expiresIn, algorithm: 'RS256' })

    return {
        token: `Bearer ${signedToken}`,
        expires: expiresIn
    }
}

app.post('/logout', async (req, res) => {
    req.logout()
    res.redirect('/')
})

/**
 * --------------View routes--------------
 */

app.get('/', async (req, res) => {

    if (req.isAuthenticated()) {
        res.redirect('/home')
    } else {
        res.send(`
        <h1>Login</h1>
        <form>
    
            <label for="uname"><b>Username</b></label>
            <input type="text" placeholder="Enter Username" name="uname" required>
    
            <label for="pw"><b>Password</b></label>
            <input type="password" placeholder="Enter Password" name="pw" required>
    
            <button type="submit">Login</button>
        </form>
        <a href="/signup">
            Or click here to sign up
        </a>
        <script>
        
            const form = document.getElementsByTagName('form')[0]
        
            form.addEventListener('submit', e => {
                e.preventDefault()
                const formData = new FormData(event.currentTarget)
                const body = Object.fromEntries(formData.entries())
        
                fetch('http://localhost:4000/login', {
                    method: 'POST',
                    headers: {
                        "Content-Type": "application/json",
                        "Accept": "application/json"
                    },
                    body: JSON.stringify(body),
                })
                    .then(res => res.json())
                    .then(res => {
                        if (res.success) {
                            localStorage.setItem('jwt', res.token)
    
                            window.location.pathname = '/'
                        }
                    })
            })
        </script>
        `)

    }
})

app.get('/login-failure', async (req, res) => {
    res.send(`
    <h1>Login failed</h1>
    <a href="/">
        Click here to login again
    </a>`)
})

app.get('/signup', async (req, res) => {
    res.send(`<h1>Sign up</h1>
    <form>
        <label for="uname"><b>Username</b></label>
        <input type="text" placeholder="Enter Username" name="uname" required>
        <br />
    
        <label for="pw"><b>Password</b></label>
        <input type="password" placeholder="Enter Password" name="pw" required>
        <br />
    
        <label for="isAdmin"><b>Admin ?</b></label>
        <input type="checkbox" name="isAdmin">
        <br />
    
        <button type="submit">Sign up</button>
    </form>
    <a href="/">
        Or click here to login
    </a>
    <script>
    
        const form = document.getElementsByTagName('form')[0]
    
        form.addEventListener('submit', e => {
            e.preventDefault()
            const formData = new FormData(event.currentTarget)
            const body = Object.fromEntries(formData.entries())
    
            fetch('http://localhost:4000/signup', {
                method: 'POST',
                headers: {
                    "Content-Type": "application/json",
                    "Accept": "application/json"
                },
                body: JSON.stringify(body),
            })
                .then(res => res.json())
                .then(res => {
                    if (res.success) {
                        localStorage.setItem('jwt', res.token)

                        window.location.pathname = '/'
                    }
                })
        })
    </script>
    `)
})

app.get('/home', passport.authenticate('jwt', { session: false }), async (req: Request, res) => {
    const _user: any = req.user

    const user = await db.collection('User').findOne({
        _id: new ObjectId(_user._id)
    }) as User

    res.send(`
    <h1>Home</h1>
    <p>Welcome, ${user.username}.</p>

    <a href='/admin'>Click here to go to admin panel</a>

    <form action="/logout" method="post">
        <button type="submit">Logout</button>
    </form>
    `)
})

app.get('/admin', isAuthMiddleware, isAdminMiddleware, async (req: Request, res) => {

    res.send(`
    <h1>Admin</h1>
    <a href="javascript:history.back()">Go Back</a>

    <form action="/logout" method="post">
        <button type="submit">Logout</button>
    </form>
    `)
})

/**
 * --------------CUSTOM MIDDLEWARES--------------
 */
function isAuthMiddleware(req: Request, res: Response, next: NextFunction) {
    if (req.isAuthenticated()) {
        next()
    } else {
        res.redirect('/')
    }
}
function isAdminMiddleware(req: Request, res: Response, next: NextFunction) {
    const user: any = req.user

    if (user?.isAdmin) {
        next()
    } else {
        res.send(`
        <h1>Forbidden route</h1>
        <a href="javascript:history.back()">Go Back</a>
        `)
    }
}


app.listen(config.port, () => {
    console.log(`learnPassportjs is running on port ${config.port}.`)
});