import dotenv from 'dotenv'

dotenv.config()

const config = {
    port: process.env.PORT,
    sessionSecret: process.env.SESSION_SECRET,
    database: {
        host: process.env.DATABASE_HOST,
        user: process.env.DATABASE_USER,
        password: process.env.DATABASE_PASSWORD,
        name: process.env.DATABASE_NAME,
        port: process.env.DATABASE_PORT,
    },
}

export default config