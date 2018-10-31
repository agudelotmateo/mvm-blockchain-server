const express = require('express');
const request = require('request');
const bodyParser = require('body-parser');

const frontEndURI = `${process.env.FRONT_END_DOMAIN}:${process.env.FRONT_END_PORT}`;
const blockchainURI = `http://localhost:${process.env.BLOCKCHAIN_PORT}/api`;

wrapGet = originalURI => (req, res) => {
    request(originalURI, (err, response, body) => {
        res.json(JSON.parse(response.body));
    });
}

wrapPost = originalURI => (req, res) => {
    request.post({
        url: originalURI,
        form: req.body
    }, (err, response, body) => {
        res.json(JSON.parse(response.body));
    })
}

app = express();

app.use(bodyParser.json());
app.use(function (req, res, next) {
    res.header('Access-Control-Allow-Origin', frontEndURI);
    res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept');
    next();
});

app.get('/agent', wrapGet(`${blockchainURI}/AgenteMEM`));
app.post('/agent', wrapPost(`${blockchainURI}/AgenteMEM`));

app.get('/regulator', wrapGet(`${blockchainURI}/EntidadReguladora`));
app.post('/regulator', wrapPost(`${blockchainURI}/EntidadReguladora`));

app.get('/condensador', wrapGet(`${blockchainURI}/PublicarDeclaracionCondensador`));
app.post('/condensador', wrapPost(`${blockchainURI}/PublicarDeclaracionCondensador`));

app.listen(process.env.SERVER_PORT, () => console.log(`Server now running listening to port ${process.env.SERVER_PORT}`));
