import bodyParser from 'body-parser';
import MongoStore from 'connect-mongo';
import cookieParser from 'cookie-parser';
import crypto from 'crypto';
import express, { NextFunction, Request, Response } from 'express';
import sessions from 'express-session';
import { MongoClient, ObjectId } from 'mongodb';
import passport from 'passport';
import { Strategy as LocalStrategy } from 'passport-local';
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
 * For session crud, used by express-session and passportjs
 */
const sessionStore = MongoStore.create({
    mongoUrl: url,
    dbName: config.database.name,
    collectionName: `Session`
})

/**
 * --------------SETUP PASSPORTJS--------------
 */
/**
 * 18/5/2022 daniel.kwok
 * passportjs magic. Allows us to specify custom field names
 * Must be tallied with html input field's "name" property
 */
const CUSTOM_FIELDS = {
    usernameField: 'uname',
    passwordField: 'pw'
}

/**
 * 18/5/2022 daniel.kwok
 * passportjs magic, A callback function to validate password etc
 * Function name can be custom, but function interface must be constant as shown here
 */
const verifyCallback = async (username: string, password: string, onDone: Function) => {
    try {
        const user = await db.collection("User").findOne({
            username: username,
        }) as User

        if (!user) return onDone(null, false)
        const hashedPassword = crypto.pbkdf2Sync(password, user.salt, 10000, 64, 'sha512').toString('hex')
        const isValidPassword = hashedPassword === user.hash

        if (!isValidPassword) return onDone(null, false)

        return onDone(null, user)
    } catch (err) {
        return onDone(err, false)
    }

}

const strategy = new LocalStrategy(CUSTOM_FIELDS, verifyCallback)
passport.use(strategy)

/**18/5/2022 daniel.kwok How passportjs writes session into mongodb */
passport.serializeUser((user: User, onDone: Function) => {
    onDone(null, user._id)
})

/**18/5/2022 daniel.kwok How passportjs read and remove session from mongodb */
passport.deserializeUser((userId: string, onDone: Function) => {
    db.collection("User").findOne({
        _id: new ObjectId(userId)
    })
        .then(user => {
            onDone(null, user)
        })
        .catch(err => {
            onDone(err, null)
        })

})


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
app.post('/login', passport.authenticate('local', { failureRedirect: '/login-failure' }), (req, res) => {
    res.redirect('/home')
})

app.post('/signup', async (req, res) => {
    const body: {
        uname: string,
        pw: string,
        isAdmin: boolean
    } = req.body

    console.log({
        body
    })

    const {
        salt, hash
    } = generatePassword(body.pw)

    const _user: User = {
        username: body.uname,
        salt: salt,
        hash: hash,
        isAdmin: body.isAdmin,
    }

    const user = await db.collection('User').insertOne(_user)

    res.redirect('/')

    function generatePassword(passwordPlain: string): { salt: string, hash: string } {
        const salt = crypto.randomBytes(32).toString('hex')
        const hash = crypto.pbkdf2Sync(passwordPlain, salt, 10000, 64, 'sha512').toString('hex')

        return {
            salt,
            hash
        }
    }
})

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
        <form action="/login" method="post">
    
            <label for="uname"><b>Username</b></label>
            <input type="text" placeholder="Enter Username" name="uname" required>
    
            <label for="pw"><b>Password</b></label>
            <input type="password" placeholder="Enter Password" name="pw" required>
    
            <button type="submit">Login</button>
        </form>
        <a href="/signup">
            Or click here to sign up
        </a>
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
    res.send(`
    <h1>Sign up</h1>
    <form action="/signup" method="post">
        <label for="uname"><b>Username</b></label>
        <input type="text" placeholder="Enter Username" name="uname" required>
        <br />

        <label for="pw"><b>Password</b></label>
        <input type="password" placeholder="Enter Password" name="pw" required>
        <br />

        <label for="isAdmin"><b>Admin ?</b></label>
        <input type="checkbox" name="isAdmin" required>
        <br />

        <button type="submit">Sign up</button>
    </form>
    <a href="/">
        Or click here to login
    </a>
    `)
})

app.get('/home', isAuthMiddleware, async (req: Request, res) => {
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