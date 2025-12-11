const { Router } = require("express");
const authMiddelware = require("../Middelwares/authMiddelware");
const { storeShortUrl, getUserLinks, getUrlDetails, editUrl, getUrlDetailsForRedirecting, verifyUrlPassword } = require("../Controllers/urlController");
const urlsMiddleware = require("../Middelwares/urlsMiddleware");


const urlRoutes = Router()

urlRoutes.use(authMiddelware)

urlRoutes.post('/api/shorten' , storeShortUrl)
urlRoutes.get('/api/url/me' , getUserLinks)
urlRoutes.get('/api/url/:short_url' ,urlsMiddleware, getUrlDetails)
urlRoutes.put('/api/url/:short_url' ,urlsMiddleware, editUrl)
urlRoutes.get('/api/url/details/:short_url' , getUrlDetailsForRedirecting)
urlRoutes.post('/api/url/verify/:short_url' , verifyUrlPassword)



module.exports = urlRoutes