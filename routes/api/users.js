const express = require('express');
const router = express.Router();
const gravatar = require('gravatar');
const bcrypt = require('bcryptjs')
const { check, validationResult } = require('express-validator/check');

// Add user model
const User = require('../../models/User');

// @route   POST api/users
// @desc    Register user
// @access  Public
router.post('/',
    [
        check('name', 'Name is required')
            .not()
            .isEmpty(),
        check('email', 'Please include a valid email')
            .isEmail(),
        check('password', 'Please enter a password with more than 6 characters')
            .isLength({
                min: 6
            })
    ],
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json(
                {
                    errors: errors.array()
                }
            );
        }

        // get request with req.body
        const { name, email, password } = req.body;

        try {
            let user = await User.findOne({ email });

            // See if user exists
            if (user) {
                return res.status(400).json({ errors: [{ msg: 'User already exists' }] });
            }

            // Get users gravatar
            const avatar = gravatar.url(email, {
                s: '200',
                r: 'pg',
                d: 'mm'
            });

            user = new User({
                name,
                email,
                avatar,
                password
            });

            // Encrypt password with bcrypt
            const salt = await bcrypt.genSalt(10);
            user.password = await bcrypt.hash(password, salt);

            await user.save();

            // Return a JWT

            // console.log(req.body)

            res.send('User registered')
        } catch (err) {
            console.error(err.message);
            res.status(500).send("Internal Server Error");
        }


    });

module.exports = router;