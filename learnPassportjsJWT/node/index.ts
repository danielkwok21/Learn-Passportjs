import bodyParser from 'body-parser';
import MongoStore from 'connect-mongo';
import cookieParser from 'cookie-parser';
import crypto from 'crypto';
import express from 'express';
import fs from 'fs';
import { MongoClient, ObjectId } from 'mongodb';
import passport from 'passport';
import { ExtractJwt, Strategy as JwtStrategy, StrategyOptions } from 'passport-jwt';
import path from 'path';
import config from './config';
import jsonwebtoken = require('jsonwebtoken')
import cors from 'cors'

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


const authMiddleware = passport.authenticate(`jwt`, { session: false })

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

        const now = Math.floor(Date.now() / 1000)
        if (payload.exp <= now) {
            return onDone(null, false)
        }

        const user = await db.collection("User").findOne({
            _id: new ObjectId(payload.sub),
        }) as User

        if (!user) return onDone(null, false)

        return onDone(null, user)

    } catch (err) {
        return onDone(err, false)
    }
}

const options: StrategyOptions = {
    jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
    secretOrKey: fs.readFileSync(path.join(__dirname, './access_token_public_key.pem')),
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
app.use(passport.initialize())
app.use(cors())



/**
 * --------------TYPE DECLARATIONS--------------
 */
type User = {
    _id?: ObjectId
    username: string,
    salt: string,
    hash: string,
}
type RefreshToken = {
    _id?: ObjectId
    refreshToken: string,
    userId: ObjectId,
    exp: number,
}

/**
 * --------------API ROUTES--------------
 */
app.post('/login', async (req, res) => {

    const {
        uname, pw
    } = req.body

    try {
        if (!uname) throw new Error('Missing uname')
        if (!pw) throw new Error('Missing pw')

        const user = await db.collection("User").findOne({
            username: uname,
        }) as User

        if (!user) throw new Error(`No user found`)
        const hashedPassword = crypto.pbkdf2Sync(pw, user.salt, 10000, 64, 'sha512').toString('hex')
        const isValidPassword = hashedPassword === user.hash

        if (!isValidPassword) throw new Error(`Wrong username or password provided`)

        /**
         * Remove sensitive data
         */
        delete user.salt
        delete user.hash

        const {
            accessToken, refreshToken
        } = await issueJWT(user._id)

        res.json({
            success: true,
            user: user,
            accessToken: accessToken,
            refreshToken: refreshToken,
        })

    } catch (err) {
        res.status(400).json({
            success: false,
            message: err.message
        })
    }
})

app.post('/signup', async (req, res) => {

    try {
        const body: {
            uname: string,
            pw: string,
        } = req.body

        if (!body.uname) throw new Error('Missing uname')
        if (!body.pw) throw new Error('Missing pw')

        const {
            salt, hash
        } = generatePassword(body.pw)

        const user: User = {
            username: body.uname,
            salt: salt,
            hash: hash,
        }

        const tx = await db.collection('User').insertOne(user)

        user._id = tx.insertedId

        const {
            accessToken, refreshToken,
        } = await issueJWT(user._id)

        res.json({
            success: true,
            user: user,
            accessToken: accessToken,
            refreshToken: refreshToken,
        })

        function generatePassword(passwordPlain: string): { salt: string, hash: string } {
            const salt = crypto.randomBytes(32).toString('hex')
            const hash = crypto.pbkdf2Sync(passwordPlain, salt, 10000, 64, 'sha512').toString('hex')

            return {
                salt,
                hash
            }
        }

    } catch (err) {
        res.status(400).send(err.toString())
    }
})

app.delete('/logout', authMiddleware, async (req, res) => {
    req.logout()
    res.json({
        success: false
    })
})

/**
 * Protected route
 */
app.get('/profile', authMiddleware, async (req, res) => {

    let user = req.user as User

    /**delete sensitive fields */
    delete user.hash
    delete user.salt

    res.json({
        user
    })
})

app.post('/access-token', async (req, res) => {

    try {
        const AT = req.headers['x-demo-auth-access-token']
        const RT = req.headers['x-demo-auth-refresh-token'] as string
        const RTwithoutBearer = RT?.replace('Bearer ', '')

        const existingRT = await db.collection("RefreshToken").findOne({
            refreshToken: RTwithoutBearer,
        }) as RefreshToken

        if (!existingRT) {
            throw new Error(`Invalid refresh token`)
        }

        const now = Math.floor(Date.now() / 1000)
        if (existingRT.exp < now) {
            await db.collection("RefreshToken").deleteOne({
                _id: new ObjectId(existingRT._id)
            })
            throw new Error(`Expired refresh token`)
        }

        const {
            accessToken, refreshToken,
        } = await issueJWT(existingRT.userId)

        res.json({
            accessToken,
            refreshToken,
        })
    } catch (err) {
        res.status(400).json({
            success: false,
            message: err?.toString()
        })
    }
})


/**
 * --------------COMMON UTILS--------------
 */

async function issueJWT(userId: ObjectId): Promise<{ accessToken: string, refreshToken: string, }> {

    const now = Math.floor(Date.now() / 1000)

    const ATpayload = {
        sub: userId,
        iat: now,
        exp: now + 5
    }
    const ATPrivateKey = fs.readFileSync(path.join(__dirname, './access_token_private_key.pem'))
    const signedAT = jsonwebtoken.sign(ATpayload, ATPrivateKey, { algorithm: 'RS256' })

    const RTpayload = {
        sub: userId,
        iat: now,
        exp: now + 10
    }
    const RTPrivateKey = fs.readFileSync(path.join(__dirname, './refresh_token_private_key.pem'))
    const signedRT = jsonwebtoken.sign(RTpayload, RTPrivateKey, { algorithm: 'RS256' })


    /**Delete existing refresh token, if exists */
    await db.collection("RefreshToken").deleteOne({
        userId: new ObjectId(userId),
    })

    /**Store newly generated refresh token */
    const newRefreshToken: RefreshToken = {
        refreshToken: signedRT,
        userId: userId,
        exp: RTpayload.exp,
    }

    await db.collection("RefreshToken").insertOne(newRefreshToken)

    return {
        accessToken: `${signedAT}`,
        refreshToken: `${signedRT}`,
    }
}

app.listen(config.port, () => {
    console.log(`learnPassportjs is running on port ${config.port}.`)
});