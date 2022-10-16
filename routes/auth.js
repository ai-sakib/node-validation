const express = require('express')

const authController = require('../controllers/auth')
const isAuth = require('../middleware/is-auth')

const { check } = require('express-validator')
const User = require('../models/user')

const router = express.Router()

router.get('/login', authController.getLogin)
router.post('/login', authController.postLogin)

router.post('/logout', isAuth, authController.postLogout)

router.get('/signup', authController.getSignup)
router.post(
    '/signup',
    [
        check('email')
            .isEmail()
            .withMessage('Wrong Email !')
            .custom((value, { req }) => {
                // if (value === 'test@test.com') {
                //     throw new Error('This email is forbidden !')
                // }
                // return true
                return User.findOne({ email: value }).then(userDoc => {
                    if (userDoc) {
                        return Promise.reject('Email already exists !')
                    }
                })
            }),

        check('password')
            .isLength({ min: 5 })
            .withMessage('Password must be at least 5 characters long !')
            .isAlphanumeric()
            .withMessage('Password must be alphanumeric !'),

        check('confirmPassword').custom((value, { req }) => {
            if (value !== req.body.password) {
                throw new Error('Passwords have to match !')
            }
            return true
        }),
    ],
    authController.postSignup
)

router.get('/reset', authController.getReset)
router.post('/reset', authController.postReset)

router.get('/reset/:token', authController.getNewPassword)

router.post('/new-password', authController.postNewPassword)
// router.post('/new-password', authController.postNewPassword)

module.exports = router
