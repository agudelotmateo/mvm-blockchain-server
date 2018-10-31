const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const UserSchema = mongoose.Schema({
    username: {
        type: String,
        required: true,
        unique: true
    },
    password: {
        type: String,
        required: true
    },
    type: {
        type: String,
        enum: ['admin', 'agent', 'regulator']
    }
}, { collection: 'users' });

const User = module.exports = mongoose.model('User', UserSchema);

module.exports.addUser = (user, callback) => {
    bcrypt.genSalt(10, (err, salt) => {
        bcrypt.hash(user.password, salt, (err, hash) => {
            if (err)
                throw err;
            user.password = hash;
            user.save(callback);
        });
    });
}

module.exports.comparePasswords = (possiblePass, hash, callback) => {
    bcrypt.compare(possiblePass, hash, (err, match) => {
        if (err)
            throw err;
        callback(null, match);
    });
}
