const { isURL } = require("validator")
const { Url } = require("../Models/Urls")
const crypto = require('crypto')

const checkShortUrlExistence = async (url) => {
    return await Url.findOne({ short_url: url })
}

const createShortUrl = async (customUrl = null) => {
    // If custom URL provided, check if it exists
    if (customUrl) {
        const linkAlreadyExists = await checkShortUrlExistence(customUrl)
        if (linkAlreadyExists) {
            throw new Error('CUSTOM_URL_EXISTS')
        }
        return `${process.env.FRONTEND_URL}/${customUrl}`
    }
    
    // Generate random short URL with collision retry
    let attempts = 0
    const maxAttempts = 10
    
    while (attempts < maxAttempts) {
        const linkEnd = crypto.randomBytes(5).toString('hex').slice(0, 6)
        const exists = await checkShortUrlExistence(linkEnd)
        
        if (!exists) {
            return linkEnd
        }
        attempts++
    }
    
    throw new Error('FAILED_TO_GENERATE_UNIQUE_URL')
}

const storeShortUrl = async (req, res) => {
    try {
        const { url, customShortUrl } = req.body
        const userId = req.user.userId
        
        // Validate input
        if (!url) {
            return res.status(400).json({ message: 'URL is required' })
        }

        if(!isURL(url)) {
            return res.status(400).json({ message: 'invalidUrlFormat' })

        }
        
        // Create short URL (custom or random)
        const shortUrl = await createShortUrl(customShortUrl)
        
        const createdShortLink = await Url.create({
            redirect_url: url,
            short_url: shortUrl,
            user_id: userId,
        })
        
        return res.status(201).json({ 
            message: 'linkCreated',
            shortUrl: `${process.env.FRONTEND_URL}/${shortUrl}`
        })
        
    } catch (error) {
        if (error.message === 'CUSTOM_URL_EXISTS') {
            return res.status(409).json({ message: 'customUrlAlreadyExists' })
        }
        
        console.error('Error creating short URL:', error)
        return res.status(500).json({ message: 'Internal server error' })
    }
}


const getUserLinks = async (req, res) => {
     
    const userId = req.user.userId


    const links = await Url.find({user_id : userId})

    return res.status(200).json(links)

}

module.exports = { storeShortUrl , getUserLinks}