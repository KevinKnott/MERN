const jwt = require('jsonwebtoken');
const config = require('config');

module.exports = function (req, res, next) {
    // Get token from header
    const token = req.header('x-auth-token');

    // Check if there is not a token
    if (!token) {
        return res.status(401).json({ msg: 'Authorization Denied: No Token' });
    }

    //  Verify token 
    try {
        const decode = jwt.verify(token, config.get('jwtSecret'));

        req.user = decode.user;
        next();
    } catch (err) {
        res.status(401).json({ msg: 'Token is not valid' });
    }
}