const { Url } = require("../Models/Urls")

const urlsMiddleware = async (req , res , next) => {
    const {short_url} = req.params
    const userId = req.user.userId

    const fetchedUrl = await Url.findOne({short_url : short_url})
    
    if(fetchedUrl.user_id !== userId ) {
        return res.status(403).json({message : 'Not authorized'})
    }

    req.url = fetchedUrl
    next()
}

module.exports = urlsMiddleware