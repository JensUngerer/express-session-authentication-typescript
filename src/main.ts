import express, { NextFunction, Request, Response } from 'express';
type ExpressUser = Express.User;
import mongoose from 'mongoose';
import session from 'express-session';
import passport from 'passport';
import passportLocal from 'passport-local';
const LocalStrategy = passportLocal.Strategy;
import connectMongo/*, { MongooseConnectionOptions, MongoUrlOptions, NativeMongoOptions, NativeMongoPromiseOptions }*/ from 'connect-mongo';
const MongoStore = connectMongo(session);
import dotenv from 'dotenv';
import { join } from 'path';
import https from 'https';
import fs from 'fs';
// @ts-ignore
import { ensureAuthenticated } from 'connect-ensure-authenticated';

const relativePathToPublic = './../public';

interface IUser {
    username: string;
    hash: string;
}

// ?
// const { ensureAuthenticated } = require('connect-ensure-authenticated');
// const { ensureScope } = require('connect-ensure-authorization');

// cf. https://github.com/zachgoll/express-session-authentication-starter/tree/final-all-in-one
dotenv.config();

// https://stackoverflow.com/questions/11744975/enabling-https-on-express-js
const relativePathToCerts = './../certs';
const keyFileName = 'selfsigned.key';

const absolutePathToKey = join(__dirname, relativePathToCerts, keyFileName);
// console.log(absolutePathToKey);

const key: string = fs.readFileSync(absolutePathToKey).toString('utf8');
// console.log(key);


const selfSignedCertFileName = 'selfsigned.crt';
const absolutePathToCert = join(__dirname, relativePathToCerts, selfSignedCertFileName);
// console.log(absolutePathToCert);

const cert: string = fs.readFileSync(absolutePathToCert).toString('utf8');
// console.log(cert);

const options: any = {
  key: key,
  cert: cert
};



var app = express();

const absoultePathToCryptJd = join(__dirname, './../node_modules/crypto-js/crypto-js.js');
// DEBUGGING:
// console.log(absoultePathToCryptJd);
app.use('/node_modules/crypto-js/crypto-js.js', express.static(absoultePathToCryptJd));

const absolutePathToPost = join(__dirname, './../public');
const expressStatic = express.static(absolutePathToPost);
app.use('/', expressStatic);

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

if (!process ||
    !process.env ||
    !process.env.DB_STRING) {
    throw new Error('DB_STRING is not defined in .env');
}

const conn: string = process.env.DB_STRING as string;

const connection = mongoose.createConnection(conn, {
    useNewUrlParser: true,
    useUnifiedTopology: true
});

const UserSchema = new mongoose.Schema({
    username: String,
    hash: String
});

const User = connection.model('User', UserSchema);

// helpers
const validPassword = (passwordHash: string, hash: string) => {
    // DEBUGGING:
    // console.log(JSON.stringify({
    //     password,
    //     hash,
    //     salt
    // }, null, 4));

    // const genHash = crypto.SHA512(password).toString();
    return hash === passwordHash;
};

// const genPassword = (password: string) => {
//     // https://github.com/jakubzapletal/crypto-js/blob/master/README.md
//     // https://security.stackexchange.com/questions/29951/salted-hashes-vs-hmac
//     const salt = crypto.lib.WordArray.random(16).toString();
//     const genHash = crypto.PBKDF2(password, salt).toString();

//     // DEBUGGING:
//     // console.log(salt);
//     // console.log(genHash);

//     return {
//       salt: salt,
//       hash: genHash
//     };
// };

const localStrategyHandler = new LocalStrategy(
    (username, password, cb) => {
        User.findOne({ username: username })
            .then((user: IUser) => {

                if (!user) { return cb(null, false) }

                const isValid = validPassword(password, user.hash);

                if (isValid) {
                    return cb(null, user);
                } else {
                    return cb(null, false);
                }
            })
            .catch((err: any) => {
                cb(err);
            });
    }
);
passport.use(localStrategyHandler);

const serializeUserHandler = (user: ExpressUser, done: (err: any, id?: any) => void) => {
    // console.log(JSON.stringify(user, null, 4));
    done(null, (user as any)._id);
};
passport.serializeUser(serializeUserHandler);

const deserializeUser = (id: any, done: (err: any, user?: Express.User) => void) => {
    User.findById(id, (err: any, user: ExpressUser) => {
        if (err) { return done(err); }
        done(null, user);
    });
};
passport.deserializeUser(deserializeUser);

const sessionStore = new MongoStore({ mongooseConnection: connection, collection: 'sessions' })

if (!process ||
    !process.env ||
    !process.env.SECRET) {
    throw new Error('SECRET is not defined in .env');
}

const sessionHandler = session({
    secret: process.env.SECRET as string,
    resave: false,
    saveUninitialized: true,
    store: sessionStore,
    cookie: {
        maxAge: 1000 * 60 * 60 * 24 // Equals 1 day (1 day * 24 hr/1 day * 60 min/1 hr * 60 sec/1 min * 1000 ms / 1 sec)
    }
});
app.use(sessionHandler);

const passportInitializeHandler = passport.initialize();
app.use(passportInitializeHandler);

const passportSessionHanlder = passport.session();
app.use(passportSessionHanlder);

// https://medium.com/javascript-in-plain-english/excluding-routes-from-calling-express-middleware-with-express-unless-3389ab4117ef
app.use(ensureAuthenticated().unless({
    path: ['/login', '/register', '/', '/logout']
}));

app.get('/', (req, res, next) => {
    const absolutePathToIndex = join(__dirname, relativePathToPublic, 'index.html');
    res.sendFile(absolutePathToIndex);
});

// When you visit http://localhost:3000/login, you will see "Login Page"
app.get('/login', (req, res, next) => {
    const absolutePathToLogin = join(__dirname, relativePathToPublic, 'login.html');
    res.sendFile(absolutePathToLogin);
});

// Since we are using the passport.authenticate() method, we should be redirected no matter what 
app.post('/login', passport.authenticate('local', { failureRedirect: '/login-failure', successRedirect: 'login-success' }), (outerReq: Request, outerRes: Response, outerNext: NextFunction) => { });

// When you visit http://localhost:3000/register, you will see "Register Page"
app.get('/register', (req, res, next) => {
    const absolutePathToRegister = join(__dirname, relativePathToPublic, 'register.html');
    res.sendFile(absolutePathToRegister);
});

app.post('/register', (req, res, next) => {
    const password = req.body.password;
    const username = req.body.username;

    // DEBUGGING:
    // console.log(JSON.stringify({
    //     salt,
    //     password,
    //     username
    // }, null, 4));

    const newUser = new User({
        username: username,
        hash: password,
    });

    newUser.save()
        .then((user) => {
            console.log(user);
        });

    res.redirect('/login');
});

/**
 * Lookup how to authenticate users on routes with Local Strategy
 * Google Search: "How to use Express Passport Local Strategy"
 * 
 * Also, look up what behaviour express session has without a maxage set
 */
app.get('/protected-route', (req, res, next) => {
    // This is how you check if a user is authenticated and protect a route.  You could turn this into a custom middleware to make it less redundant
    if (req.isAuthenticated()) {
        res.send('<h1>You are authenticated</h1><p><a href="/logout">Logout and reload</a></p>');
    } else {
        res.send('<h1>You are not authenticated</h1><p><a href="/login">Login</a></p>');
    }
});

// Visiting this route logs the user out
app.get('/logout', (req, res, next) => {
    req.logout();
    res.redirect('/protected-route');
});

app.get('/login-success', (req, res, next) => {
    res.send('<p>You successfully logged in. --> <a href="/protected-route">Go to protected route</a></p>');
});

app.get('/login-failure', (req, res, next) => {
    res.send('You entered the wrong password.');
});

app.get('/login-status', (req, res) => {
    // https://stackoverflow.com/questions/18739725/how-to-know-if-user-is-logged-in-with-passport-js
    // req.user
    // console.log(req.isAuthenticated());
    // console.log(JSON.stringify(req.user));
    // console.log(passport.transformAuthInfo());
    req.isAuthenticated() ? res.status(200).send({ loggedIn: true }) : res.status(200).send({ loggedIn: false });
});

if (!process ||
    !process.env ||
    !process.env.PORT) {
    throw new Error('PORT is not defined in .env');
}

const port = parseInt(process.env.PORT);
// app.listen(port);
const server = https.createServer(options, app);
server.listen(port, () => {
    console.log('listening on port: ' + port);
});
