const { Router } = require("express");
const authMiddelware = require("../Middelwares/authMiddelware");
const { storeShortUrl, getUserLinks } = require("../Controllers/urlController");


const urlRoutes = Router()

urlRoutes.use(authMiddelware)

urlRoutes.post('/api/shorten' , storeShortUrl)
urlRoutes.get('/api/url/me' , getUserLinks)


module.exports = urlRoutes