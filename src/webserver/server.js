import express from "express";
import session from 'express-session';
import cookieParser from 'cookie-parser';
import path from 'path';
const __dirname = path.resolve();
const app = express();

import indexRouter from './routes/index.js';
import authRouter from './routes/auth.js'

const webserver = {};

webserver.start = async () => {

    app.use(session({
        secret: 'dfdfdEWFEWDWEewcewcw5345#%#$fwefewWEEWEntvcdswfwqf%34543543tfweftpfdswffghFDDDdd11!!22344rdsfffrsshtntf3dewdwwedwdw',
        resave: false,
        saveUninitialized: false,
        cookie: {
            secure: false, // set this to true on production
        }
    }));

    // view engine setup
    app.set('views', path.join(__dirname, 'src/webserver/views'));
    app.set('view engine', 'hbs');

    app.use(express.json());
    //app.use(cookieParser());
    app.use(express.urlencoded({ extended: false }));
    app.use(express.static(path.join(__dirname, 'src/webserver/public')));

    app.use('/', indexRouter);
    //app.use('/users', indexRouter);
    app.use('/auth', authRouter);

    // catchAll op 404
    app.use(function (req, res, next) {
        res.status(404).send('!! Geen Toegang !!')
    });

    app.listen(3000)
    logger.info('[WebServer] Starting WebServer on port 80');

};

export default webserver;
