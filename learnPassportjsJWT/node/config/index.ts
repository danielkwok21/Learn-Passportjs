import dotenv from 'dotenv'

dotenv.config()

const config = {
    port: 4000,
    sessionSecret: 'somerandomsecret123',
    database: {
        host: 'node_mongo_1',
        user: 'root',
        password: 'example',
        name: 'learnPassportjs',
        port: '27017',
    },
}

export default config