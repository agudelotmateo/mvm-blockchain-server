const express = require('express');
const request = require('request');
const bodyParser = require('body-parser');
const mongoose = require('mongoose');
const passport = require('passport');
const jwt = require('jsonwebtoken');
const JwtStrategy = require('passport-jwt').Strategy;
const ExtractJwt = require('passport-jwt').ExtractJwt;
const User = require('./models/user');
const cors = require('cors');

const frontEndURI = `${process.env.FRONT_END_DOMAIN}:${process.env.FRONT_END_PORT}`;
const blockchainURI = `http://localhost:${process.env.BLOCKCHAIN_PORT}/api`;
const mongoURI = `mongodb://${process.env.DB_USER}:${process.env.DB_PASSWORD}@${process.env.DB_HOST}`;

mongoose.connect(mongoURI, { useNewUrlParser: true });
mongoose.connection.on('connected', () => console.log(`Successfully connected to the DB at ${mongoURI}`));
mongoose.connection.on('error', err => console.log(`Database connection error: ${err}`));
mongoose.set('useCreateIndex', true);

app = express();

app.use(cors({ origin: frontEndURI }));
app.use(bodyParser.json());
app.use(passport.initialize());
app.use(passport.session());
passport.use(new JwtStrategy(
    {
        jwtFromRequest: ExtractJwt.fromAuthHeaderWithScheme('JWT'),
        secretOrKey: process.env.JWT_SECRET
    },
    (jwt_payload, done) => {
        User.findById(jwt_payload._id, (err, user) => {
            if (err)
                return done(err, false);
            if (user)
                return done(null, user);
            else
                return done(null, false);
        });
    })
);

app.post('/authenticate', (req, res) => {
    const username = req.body.username;
    const password = req.body.password;
    User.findOne({ username }, (err, user) => {
        if (err)
            throw err;
        if (!user)
            return res.status(400).json({ success: false, msg: 'User not found' });
        User.comparePasswords(password, user.password, (err, match) => {
            if (err)
                throw err;
            if (match) {
                res.status(200).json({
                    success: true,
                    token: `JWT ${jwt.sign(user.toObject(), process.env.JWT_SECRET, { expiresIn: 604800 })}`,
                    user: {
                        id: user._id,
                        username: user.username,
                        type: user.type
                    }
                });
            } else
                res.status(400).json({ success: false, msg: 'Wrong password' });
        });
    });
});

checkPermissions = (req, res, validUserTypes, next) => {
    if (validUserTypes.includes(req.user.type))
        next();
    else
        res.status(401).json({ success: false, msg: 'Unauthorized' });
}

app.post('/register', passport.authenticate('jwt', { session: false }), (req, res) => {
    checkPermissions(req, res, ['admin'], () => {
        User.findOne({ username: req.body.username }, (err, user) => {
            if (err)
                throw err;
            if (user)
                return res.status(400).json({ success: false, msg: 'Username already in use' });
            User.addUser(
                new User({
                    username: req.body.username,
                    password: req.body.password,
                    type: req.body.type
                }),
                (err, user) => {
                    if (err)
                        res.status(400).json({ success: false, msg: 'Failed to register user' });
                    else
                        res.status(200).json({ success: true, msg: 'User successfully registered', id: user._id });
                });
        });
    });
});

wrapEndpoint = settings => (req, res) => {
    checkPermissions(req, res, settings.validUserTypes, () => {
        if (settings.method === 'post')
            request.post({
                url: settings.originalURI,
                form: req.body
            }, (err, response, body) => {
                res.json(JSON.parse(response.body));
            })
        else
            request(settings.originalURI, (err, response, body) => {
                res.json(JSON.parse(response.body));
            });
    });
}

app.get('/agent', passport.authenticate('jwt', { session: false }),
    wrapEndpoint({ validUserTypes: ['admin'], originalURI: `${blockchainURI}/AgenteMEM` }));
app.post('/agent', passport.authenticate('jwt', { session: false }),
    wrapEndpoint({ validUserTypes: ['admin'], originalURI: `${blockchainURI}/AgenteMEM`, method: 'post' }));

app.get('/regulator', passport.authenticate('jwt', { session: false }),
    wrapEndpoint({ validUserTypes: ['admin'], originalURI: `${blockchainURI}/EntidadReguladora` }));
app.post('/regulator', passport.authenticate('jwt', { session: false }),
    wrapEndpoint({ validUserTypes: ['admin'], originalURI: `${blockchainURI}/EntidadReguladora`, method: 'post' }));

app.get('/condensador', passport.authenticate('jwt', { session: false }),
    wrapEndpoint({ validUserTypes: ['agent', 'regulator'], originalURI: `${blockchainURI}/PublicarDeclaracionCondensador` }));
app.post('/condensador', passport.authenticate('jwt', { session: false }),
    wrapEndpoint({ validUserTypes: ['agent'], originalURI: `${blockchainURI}/PublicarDeclaracionCondensador`, method: 'post' }));

app.listen(process.env.SERVER_PORT, () => console.log(`Server now running listening to port ${process.env.SERVER_PORT}`));
