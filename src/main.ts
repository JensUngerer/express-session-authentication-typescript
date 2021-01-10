import express, { Request, Response} from 'express';
import mongoose from 'mongoose';
import session from 'express-session';
import passport from 'passport';
import crypto from 'crypto';
import passportLocal from 'passport-local';
const LocalStrategy = passportLocal.Strategy;
import connectMongo, { MongooseConnectionOptions, MongoUrlOptions, NativeMongoOptions, NativeMongoPromiseOptions } from 'connect-mongo';
const MongoStore = connectMongo(session);
import dotenv from 'dotenv';

// ?
// const { ensureAuthenticated } = require('connect-ensure-authenticated');
// const { ensureScope } = require('connect-ensure-authorization');

// cf. https://github.com/zachgoll/express-session-authentication-starter/tree/final-all-in-one
dotenv.config();