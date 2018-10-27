const express = require('express');
const request = require('request');
const bodyParser = require('body-parser');

const port = 5000;
const frontEndURI = 'http://localhost:4200';
const blockchainURI = 'http://localhost:3000/api';

app = express();
app.use(bodyParser.json());

app.use(function (req, res, next) {
    res.header('Access-Control-Allow-Origin', frontEndURI);
    res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept');
    next();
});

app.get('/agent', (req, res) => {
    request(`${blockchainURI}/AgenteMEM`, (err, response, body) => {
        res.json(JSON.parse(response.body));
    })
});

app.post('/agent', (req, res) => {
    request.post({
        url: `${blockchainURI}/AgenteMEM`,
        form: req.body
    }, (err, response, body) => {
        res.json(JSON.parse(response.body));
    })
});

app.listen(port, () => console.log(`Server now running listening to port ${port}`));
