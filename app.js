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
const util = require('util')

const frontEndURI = `${process.env.FRONT_END_DOMAIN}:${process.env.FRONT_END_PORT}`;
const blockchainURI = `http://localhost:${process.env.BLOCKCHAIN_PORT}/api`;
const mongoURI = `mongodb://${process.env.DB_USER}:${process.env.DB_PASSWORD}@${process.env.DB_HOST}`;
const agenteSeleccionado = 123;

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

app.get('/condenser', passport.authenticate('jwt', { session: false }),
    wrapEndpoint({ validUserTypes: ['agent', 'regulator'], originalURI: `${blockchainURI}/PublicarDeclaracionCondensador` }));
app.post('/condenser', passport.authenticate('jwt', { session: false }),
	 wrapEndpoint({ validUserTypes: ['agent'], originalURI: `${blockchainURI}/PublicarDeclaracionCondensador`, method: 'post' }));

app.get('/linea', passport.authenticate('jwt', { session: false }),
    wrapEndpoint({ validUserTypes: ['agent', 'regulator'], originalURI: `${blockchainURI}/PublicarDeclaracionLinea` }));
app.post('/linea', passport.authenticate('jwt', { session: false }),
	 wrapEndpoint({ validUserTypes: ['agent'], originalURI: `${blockchainURI}/PublicarDeclaracionLinea`, method: 'post' }));

app.get('/reactor', passport.authenticate('jwt', { session: false }),
    wrapEndpoint({ validUserTypes: ['agent', 'regulator'], originalURI: `${blockchainURI}/PublicarDeclaracionReactor` }));
app.post('/reactor', passport.authenticate('jwt', { session: false }),
	 wrapEndpoint({ validUserTypes: ['agent'], originalURI: `${blockchainURI}/PublicarDeclaracionReactor`, method: 'post' }));

app.get('/svc', passport.authenticate('jwt', { session: false }),
    wrapEndpoint({ validUserTypes: ['agent', 'regulator'], originalURI: `${blockchainURI}/PublicarDeclaracionSvc` }));
app.post('/svc', passport.authenticate('jwt', { session: false }),
	 wrapEndpoint({ validUserTypes: ['agent'], originalURI: `${blockchainURI}/PublicarDeclaracionSvc`, method: 'post' }));

app.get('/transformador', passport.authenticate('jwt', { session: false }),
    wrapEndpoint({ validUserTypes: ['agent', 'regulator'], originalURI: `${blockchainURI}/PublicarDeclaracionTransformador` }));
app.post('/transformador', passport.authenticate('jwt', { session: false }),
	 wrapEndpoint({ validUserTypes: ['agent'], originalURI: `${blockchainURI}/PublicarDeclaracionTransformador`, method: 'post' }));

app.get('/unidadesGeneracion', passport.authenticate('jwt', { session: false }),
    wrapEndpoint({ validUserTypes: ['agent', 'regulator'], originalURI: `${blockchainURI}/PublicarDeclaracionUnidadesDeGeneracion` }));
app.post('/unidadesGeneracion', passport.authenticate('jwt', { session: false }),
	 wrapEndpoint({ validUserTypes: ['agent'], originalURI: `${blockchainURI}/PublicarDeclaracionUnidadesDeGeneracion`, method: 'post' }));


//----BEGIN PRIMERA QUERY----

app.get('/condensador', passport.authenticate('jwt', { session: false }),
	wrapEndpoint({ validUserTypes: ['agent', 'regulator'], originalURI: `${blockchainURI}/PublicarDeclaracionCondensador` }));

app.get('/linea', passport.authenticate('jwt', { session: false }),
	wrapEndpoint({ validUserTypes: ['agent', 'regulator'], originalURI: `${blockchainURI}/PublicarDeclaracionLinea` }));

app.get('/reactor', passport.authenticate('jwt', { session: false }),
	wrapEndpoint({ validUserTypes: ['agent', 'regulator'], originalURI: `${blockchainURI}/PublicarDeclaracionReactor` }));

app.get('/svc', passport.authenticate('jwt', { session: false }),
	wrapEndpoint({ validUserTypes: ['agent', 'regulator'], originalURI: `${blockchainURI}/PublicarDeclaracionSvc` }));

app.get('/transformador', passport.authenticate('jwt', { session: false }),
    wrapEndpoint({ validUserTypes: ['agent', 'regulator'], originalURI: `${blockchainURI}/PublicarDeclaracionTransformador` }));

app.get('/unidadesGeneracion', passport.authenticate('jwt', { session: false }),
	wrapEndpoint({ validUserTypes: ['agent', 'regulator'], originalURI: `${blockchainURI}/PublicarDeclaracionUnidadesDeGeneracion` }));

//----END PRIMERA QUERY----

//----BEGIN SEGUNDA QUERY---

app.get('/condensadorPorAgente', passport.authenticate('jwt', { session: false }),
	wrapEndpoint({ validUserTypes: ['agent', 'regulator'], originalURI: `${blockchainURI}/PublicarDeclaracionCondensador?filter=%7B%22where%22%20%3A%20%7B%22declaracionCondensador.agente%22%3A%22resource%3Aco.edu.eafit.mvmblockchain.AgenteMEM%23idAgenteMEM%3A${agenteSeleccionado}%22%7D%7D` }));

app.get('/lineaPorAgente', passport.authenticate('jwt', { session: false }),
	wrapEndpoint({ validUserTypes: ['agent', 'regulator'], originalURI: `${blockchainURI}/PublicarDeclaracionLinea?filter=%7B%22where%22%20%3A%20%7B%22declaracionLinea.agente%22%3A%20%22resource%3Aco.edu.eafit.mvmblockchain.AgenteMEM%23idAgenteMEM%3A${agenteSeleccionado}%22%7D%7D` }));

app.get('/reactorPorAgente', passport.authenticate('jwt', { session: false }),
	wrapEndpoint({ validUserTypes: ['agent', 'regulator'], originalURI: `${blockchainURI}/PublicarDeclaracionReactor?filter=%7B%22where%22%20%3A%20%7B%22declaracionReactor.agente%22%3A%20%22resource%3Aco.edu.eafit.mvmblockchain.AgenteMEM%23idAgenteMEM%3A${agenteSeleccionado}%22%7D%7D` }));

app.get('/svcPorAgente', passport.authenticate('jwt', { session: false }),
	wrapEndpoint({ validUserTypes: ['agent', 'regulator'], originalURI: `${blockchainURI}/PublicarDeclaracionSvc?filter=%7B%22where%22%20%3A%20%7B%22declaracionSvc.agente%22%3A%20%22resource%3Aco.edu.eafit.mvmblockchain.AgenteMEM%23idAgenteMEM%3A${agenteSeleccionado}%22%7D%7D` }));

app.get('/transformadorPorAgente', passport.authenticate('jwt', { session: false }),
	wrapEndpoint({ validUserTypes: ['agent', 'regulator'], originalURI: `${blockchainURI}/PublicarDeclaracionTransformador?filter=%7B%22where%22%20%3A%20%7B%22declaracionTransformador.agente%22%3A%20%22resource%3Aco.edu.eafit.mvmblockchain.AgenteMEM%23idAgenteMEM%3A${agenteSeleccionado}%22%7D%7D` }));

app.get('/unidadesGeneracionPorAgente', passport.authenticate('jwt', { session: false }),
	wrapEndpoint({ validUserTypes: ['agent', 'regulator'], originalURI: `${blockchainURI}/PublicarDeclaracionUnidadesDeGeneracion?filter=%7B%22where%22%20%3A%20%7B%22declaracionUnidadesDeGeneracion.agente%22%3A%20%22resource%3Aco.edu.eafit.mvmblockchain.AgenteMEM%23idAgenteMEM%3A${agenteSeleccionado}%22%7D%7D` }));

//----END SEGUNDA QUERY----
app.listen(process.env.SERVER_PORT, () => console.log(`Server now running listening to port ${process.env.SERVER_PORT}`));
