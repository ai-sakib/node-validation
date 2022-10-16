const User = require('../models/user')
const bcrypt = require('bcryptjs')
const nodemailer = require('nodemailer')
const crypto = require('crypto')

const { validationResult } = require('express-validator')

const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: 'sakib2439@gmail.com',
        pass: 'hsfdaralkezlggpe',
    },
})

exports.getLogin = (req, res, next) => {
    const flashMessage = req.flash('error')
    let errorMessage = flashMessage.length > 0 ? flashMessage[0] : null

    res.render('auth/login', {
        path: '/login',
        pageTitle: 'Login',
        errorMessage: errorMessage,
    })
}

exports.postLogin = (req, res, next) => {
    const email = req.body.email
    const password = req.body.password
    const invalidMessage = 'Invalid email or password !'

    User.findOne({ email: email })
        .then(user => {
            if (!user) {
                req.flash('error', invalidMessage)
                return res.redirect('/login')
            }

            return bcrypt.compare(password, user.password).then(doMatch => {
                if (doMatch) {
                    req.session.isLoggedIn = true
                    req.session.user = user
                    return req.session.save(err => {
                        res.redirect('/')
                    })
                } else {
                    throw new Error(invalidMessage)
                }
            })
        })
        .catch(err => {
            console.log(err)
            req.flash('error', invalidMessage)
            res.redirect('/login')
        })
}

exports.getSignup = (req, res, next) => {
    const flashMessage = req.flash('error')
    let errorMessage = flashMessage.length > 0 ? flashMessage[0] : null

    res.render('auth/signup', {
        path: '/signup',
        pageTitle: 'Signup',
        errorMessage: errorMessage,
        oldInput: {
            email: '',
        },
        validationErrors: [],
    })
}

exports.postSignup = (req, res, next) => {
    const email = req.body.email
    const password = req.body.password

    const errors = validationResult(req)
    console.log('signuperror', errors)

    if (!errors.isEmpty()) {
        return res.status(403).render('auth/signup', {
            path: '/signup',
            pageTitle: 'Signup',
            errorMessage: errors.array()[0].msg,
            oldInput: {
                email: email,
            },
            validationErrors: errors.array(),
        })
    }

    bcrypt
        .hash(password, 12)
        .then(hashedPassword => {
            const user = new User({
                email: email,
                password: hashedPassword,
                cart: { items: [] },
            })
            return user.save()
        })
        .then(user => {
            res.redirect('/login')
            return transporter.sendMail({
                from: 'sakib@gmail.com',
                to: user.email,
                subject: 'Sending Email using Node.js',
                text: 'Your account has been created successfully.',
            })
        })
        .then(result => {
            console.log('Mail sent successfully.')
        })
        .catch(err => {
            const error = new Error(err)
            error.httpStatusCode = 500
            return next(error)
        })
}

// exports.postSignup = async (req, res, next) => {
//     const { email, password } = req.body

//     const foundUser = await User.findOne({ email: email })
//     if (foundUser) {
//         req.flash('error', 'Email already exists !')
//         return res.redirect('/signup')
//     }

//     const hashedPassword = await bcrypt.hash(password, 12)
//     const user = await User.create({
//         email: email,
//         password: hashedPassword,
//         cart: { items: [] },
//     })

//     res.redirect('/login')

//     const hasMailSent = await transporter.sendMail({
//         from: 'sakib@gmail.com',
//         to: user.email,
//         subject: 'Sending Email using Node.js',
//         text: 'Your account has been created successfully.',
//     })

//     console.log(hasMailSent)
// }

exports.postLogout = (req, res, next) => {
    req.session.destroy(err => {
        console.log(err)
        res.redirect('/login')
    })
}

exports.getReset = (req, res, next) => {
    const flashMessage = req.flash('error')
    let errorMessage = flashMessage.length > 0 ? flashMessage[0] : null

    res.render('auth/reset', {
        path: '/reset',
        pageTitle: 'Reset Password',
        errorMessage: errorMessage,
    })
}

exports.postReset = (req, res, next) => {
    crypto.randomBytes(32, (err, buffer) => {
        if (err) {
            console.log(err)
            return res.redirect('/reset')
        }
        const token = buffer.toString('hex')
        User.findOne({ email: req.body.email })
            .then(user => {
                if (!user) {
                    req.flash('error', 'No account with that email found !')
                    return res.redirect('/reset')
                }
                user.resetToken = token
                user.resetTokenExpiration = Date.now() + 3600000
                return user.save()
            })
            .then(result => {
                res.redirect('/')
                return transporter.sendMail({
                    from: 'sakib2439@gmail.com',
                    to: req.body.email,
                    subject: 'Password reset',
                    html: `
                        <p>You requested a password reset</p>
                        <p>Click this <a href="http://localhost:3000/reset/${token}">link</a> to set a new password.</p>
                    `,
                })
            })
            .then(result => {
                console.log('Mail sent successfully.')
            })
            .catch(err => {
                const error = new Error(err)
                error.httpStatusCode = 500
                return next(error)
            })
    })
}

exports.getNewPassword = (req, res, next) => {
    const token = req.params.token
    User.findOne({
        resetToken: token,
        resetTokenExpiration: { $gt: Date.now() },
    })
        .then(user => {
            if (!user) {
                req.flash('error', 'Invalid token !')
                return res.redirect('/reset')
            }

            const flashMessage = req.flash('error')
            let errorMessage = flashMessage.length > 0 ? flashMessage[0] : null

            res.render('auth/new-password', {
                path: '/new-password',
                pageTitle: 'New Password',
                errorMessage: errorMessage,
                userId: user._id.toString(),
                passwordToken: token,
            })
        })
        .catch(err => {
            const error = new Error(err)
            error.httpStatusCode = 500
            return next(error)
        })
}

exports.postNewPassword = (req, res, next) => {
    const newPassword = req.body.password
    const userId = req.body.userId
    const passwordToken = req.body.passwordToken

    let resetUser

    User.findOne({
        resetToken: passwordToken,
        resetTokenExpiration: { $gt: Date.now() },
        _id: userId,
    })
        .then(user => {
            resetUser = user
            return bcrypt.hash(newPassword, 12)
        })
        .then(hashedPassword => {
            resetUser.password = hashedPassword
            resetUser.resetToken = undefined
            resetUser.resetTokenExpiration = undefined
            return resetUser.save()
        })
        .then(result => {
            res.redirect('/login')
        })
        .catch(err => {
            const error = new Error(err)
            error.httpStatusCode = 500
            return next(error)
        })
}
