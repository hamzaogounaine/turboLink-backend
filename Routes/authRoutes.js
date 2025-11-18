const { Router } = require("express");
const authMiddelware = require("../Middelwares/authMiddelware");
const { userSignUp, userLogin, getUser, googleCallBack, userLogout, userResetPassword, updateProfile, verifyEmail } = require("../Controllers/userController");
const passport = require("passport");
const { checkUsernameAvailabily, refreshToken, resendEmailVerificationLink, verifyDevice, editAvatar, updateAvatarUrl } = require("../utils/authUtils");
const  rateLimit  = require("express-rate-limit");
const zodValidator = require("../Middelwares/zodMiddlware");
const { userSignUpSchema } = require("../validation/authSchema");
const multer = require("multer");
require('../Controllers/passport.config')

const authRoutes = Router()
const storage = multer.memoryStorage();
const upload = multer({ storage: storage });



authRoutes.get('/' , authMiddelware , (req, res) => {res.send('Main get')})
authRoutes.post('/api/signup' ,zodValidator(userSignUpSchema) ,userSignUp)
authRoutes.post('/api/login' , userLogin)
authRoutes.post('/api/update-profile' , authMiddelware , updateProfile)
authRoutes.post('/api/resend-verification-link' , authMiddelware , resendEmailVerificationLink)
authRoutes.post('/api/upload-avatar' , authMiddelware, upload.single('image') , editAvatar)
authRoutes.post('/api/update-avatart-url' , authMiddelware , updateAvatarUrl)
authRoutes.post('/api/verify-email'  , verifyEmail)
authRoutes.post('/api/verify-device'  , verifyDevice)
authRoutes.post('/api/refresh-token' , refreshToken)
authRoutes.get('/api/profile' , authMiddelware , getUser)
authRoutes.post('/api/logout' , authMiddelware , userLogout)
authRoutes.post('/api/reset-password' , authMiddelware , userResetPassword)
authRoutes.get('/auth/google/callback' , passport.authenticate('google', { failureRedirect: '/auth-fail', session: false }), googleCallBack)
authRoutes.get('/auth/google',passport.authenticate('google', { scope: ['profile', 'email'], session: false }));



module.exports = authRoutes