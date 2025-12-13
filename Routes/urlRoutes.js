const { Router } = require("express");
const authMiddelware = require("../Middelwares/authMiddelware");
const { storeShortUrl, getUserLinks, getUrlDetails, editUrl, getUrlDetailsForRedirecting, verifyUrlPassword, saveUrlAnalytics, disableLink } = require("../Controllers/urlController");
const urlsMiddleware = require("../Middelwares/urlsMiddleware");


const urlRoutes = Router()

const protectedRoute = Router()
protectedRoute.use(authMiddelware)

protectedRoute.post('/api/shorten' , storeShortUrl)
protectedRoute.get('/api/url/me' , getUserLinks)
protectedRoute.get('/api/url/:short_url' ,urlsMiddleware, getUrlDetails)
protectedRoute.put('/api/url/:short_url' ,urlsMiddleware, editUrl)
urlRoutes.get('/api/url/details/:short_url' , getUrlDetailsForRedirecting)
urlRoutes.post('/api/url/verify/:short_url' , verifyUrlPassword)
protectedRoute.post('/api/url/analytics/:short_url' , saveUrlAnalytics)
protectedRoute.post('/api/url/disable/:short_url' , urlsMiddleware , disableLink)

urlRoutes.use(protectedRoute)

module.exports = urlRoutes