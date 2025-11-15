const { Router } = require("express");
const authMiddelware = require("../Middelwares/authMiddelware");
const { userSignUp, userLogin, getUser, googleCallBack, userLogout, userResetPassword, updateProfile } = require("../Controllers/userController");
const passport = require("passport");
const { checkUsernameAvailabily, refreshToken } = require("../utils/authUtils");
const  rateLimit  = require("express-rate-limit");
const zodValidator = require("../Middelwares/zodMiddlware");
const { userSignUpSchema } = require("../validation/authSchema");
require('../Controllers/passport.config')

const authRoutes = Router()




authRoutes.get('/' , authMiddelware , (req, res) => {res.send('Main get')})
authRoutes.post('/api/signup' ,zodValidator(userSignUpSchema) ,userSignUp)
authRoutes.post('/api/login' , userLogin)
authRoutes.post('/api/update-profile' , authMiddelware , updateProfile)
authRoutes.post('/api/refresh-token' , refreshToken)
authRoutes.get('/api/profile' , authMiddelware , getUser)
authRoutes.post('/api/logout' , authMiddelware , userLogout)
authRoutes.post('/api/reset-password' , authMiddelware , userResetPassword)
authRoutes.get('/auth/google/callback' , passport.authenticate('google', { failureRedirect: '/auth-fail', session: false }), googleCallBack)
authRoutes.get('/auth/google',passport.authenticate('google', { scope: ['profile', 'email'], session: false }));



module.exports = authRoutes