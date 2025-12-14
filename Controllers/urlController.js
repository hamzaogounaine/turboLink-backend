const { isURL } = require("validator");
const { Url, Analytics } = require("../Models/Urls");
const crypto = require("crypto");
const bcrypt = require("bcrypt");
const UAParser = require("ua-parser-js");
const geoip = require("geoip-lite")

const createShortUrl = async (customUrl = null) => {
  // If custom URL provided, check if it exists
  if (customUrl) {
    const linkAlreadyExists = await Url.findOne({ short_url: customUrl });
    if (linkAlreadyExists) {
      throw new Error("CUSTOM_URL_EXISTS");
    }
    return customUrl;
  }

  // Generate random short URL with collision retry
  let attempts = 0;
  const maxAttempts = 10;

  while (attempts < maxAttempts) {
    const linkEnd = crypto.randomBytes(5).toString("hex").slice(0, 6);
    const exists = await await Url.findOne({ short_url: linkEnd });

    if (!exists) {
      return linkEnd;
    }
    attempts++;
  }

  throw new Error("FAILED_TO_GENERATE_UNIQUE_URL");
};

const storeShortUrl = async (req, res) => {
  try {
    const { longUrl, customAlias, password, maxClicks } = req.body;
    const userId = req.user.userId;

    // Validate input
    if (!longUrl) {
      return res.status(400).json({ message: "URL is required" });
    }

    if (!isURL(longUrl)) {
      return res.status(400).json({ message: "invalidUrlFormat" });
    }

    const shortUrl = await createShortUrl(customAlias);

    const createdShortLink = await Url.create({
      redirect_url: longUrl,
      short_url: shortUrl,
      user_id: userId,
      max_clicks: maxClicks,
      password: password,
    });

    return res.status(201).json({
      message: "linkCreated",
      shortUrl: `${process.env.FRONTEND_URL}/${shortUrl}`,
    });
  } catch (error) {
    if (error.message === "CUSTOM_URL_EXISTS") {
      return res.status(409).json({ message: "customUrlAlreadyExists" });
    }

    console.error("Error creating short URL:", error);
    return res.status(500).json({ message: "Internal server error" });
  }
};

const getUrlDetails = async (req, res) => {
  const fetchedUrl = req.url;
  // Assign the field from the lean, projected result

  return res.status(200).json(fetchedUrl);
};

const getUserLinks = async (req, res) => {
  const userId = req.user.userId;

  const links = await Url.find({ user_id: userId });

  return res.status(200).json(links);
};

const editUrl = async (req, res) => {
  // 1. Get the resource ID securely from the path parameter
  const { short_url } = req.params;

  // 2. Extract allowed updates (Do NOT include short_url)
  const { redirect_url, max_clicks, password, disable_password } = req.body;
  console.log(req.body)

  try {
    // 3. Find the URL by its ID AND the current user's ID (Authorization)
    const fetchedUrl = await Url.findOne({
      short_url: short_url,
      user_id: req.user.userId, // Critical: Authorization check in the fetch
    });

    fetchedUrl.is_active = !max_clicks || (max_clicks > fetchedUrl.clicks);

    if (!fetchedUrl) {
      // Document not found OR the authenticated user does not own it.
      return res
        .status(404)
        .json({ message: "URL not found or not owned by you." });
    }

    // 4. Update the fields on the document object
    if (redirect_url !== undefined) fetchedUrl.redirect_url = redirect_url;
    if (max_clicks !== undefined) {
      // Basic validation *before* saving
      if (max_clicks < 0) {
        return res
          .status(400)
          .json({ message: "max_clicks cannot be negative." });
      }
      fetchedUrl.max_clicks = max_clicks;
    }
    if (password !== undefined) fetchedUrl.password = password;
    if ((password === undefined && !fetchedUrl.password) || disable_password)
      fetchedUrl.password = undefined;

    // NOTE: The pre('save') hook should handle the hashing of this new password.

    // 5. Save the document (triggers pre('save') hooks and Mongoose validation)
    const updatedUrl = await fetchedUrl.save();

    // 6. Use correct status code
    return res.status(200).json({ updatedUrl });
  } catch (error) {
    // Handle Mongoose validation errors
    if (error.name === "ValidationError") {
      return res
        .status(400)
        .json({ message: "Validation failed.", details: error.message });
    }
    console.error("URL Save Error:", error);
    return res.status(500).json({ message: "Internal server error." });
  }
};

const disableLink = async (req, res) => {
  const urlShort = req.url.short_url
  const {checked} = req.body

  try{
    const fetchedUrl = await Url.findOneAndUpdate({short_url : urlShort} , {$set : {is_active : checked}})
    
    if(!fetchedUrl) {
      return res.status(401).json({message : 'urlNotFound'})
    }
    return res.status(200).json({message : 'success'})
  }
  catch(err) {
    console.log(err)
  }
  
}

const getUrlDetailsForRedirecting = async (req, res) => {
  const { short_url } = req.params;

  try {
    const fetchedUrl = await Url.findOne({ short_url: short_url });

    if (!fetchedUrl) {
      return res.status(401).json({ message: "linkNotFound" });
    }

    if(!fetchedUrl.is_active) {
        return res.status(401).json({message : 'urlDisabled'})
    }

    if (fetchedUrl.password) {
      return res.status(200).json({ requirePassword: true });
    }

    return res.status(200).json(fetchedUrl);
  } catch (err) {
    console.log(err);
  }
};

const verifyUrlPassword = async (req, res) => {
  const { short_url } = req.params;
  const { password } = req.body;

  try {
    if (!password) {
      return res.status(404).json({ message: "passwordRequired" });
    }
    const fetchedUrl = await Url.findOne({ short_url: short_url });

    if (!fetchedUrl) {
      return res.status(401).json({ message: "linkNotFound" });
    }

    if (!fetchedUrl.password) {
      return res.status(401).json({ message: "linkNotProtected" });
    }

    const pwdIsValid = await bcrypt.compare(password, fetchedUrl.password);

    if (!pwdIsValid) {
      return res.status(401).json({ message: "passwordNotCorrect" });
    }

    return res.status(200).json(fetchedUrl);
  } catch (err) {
    console.log(err);
  }
};

const saveUrlAnalytics = async (req, res) => {
  const { short_url } = req.params;
  const ipAddress = req.headers["x-forwarded-for"]
    ? req.headers["x-forwarded-for"].split(",")[0].trim()
    : req.socket.remoteAddress;

  const ua = new UAParser(req.headers["user-agent"]);
  const parsed = ua.getResult();
  const geo = geoip.lookup(ipAddress);

  const urlAnalyticsArray = {
    ip_address: ipAddress,
    user_agent: req.headers["user-agent"],
    referrer: req.headers["referer"],
    device_type: parsed.device.type,
    browser: parsed.browser.name,
    os: parsed.os.name,
    country : geo?.country || null
  };

  const urlAnalytics = await Analytics.findOneAndUpdate(
    { short_url: short_url },
    {
      $inc: { clicks: 1 },
      $push: { click_details: urlAnalyticsArray },
    },
    {
      upsert: true,
      new: true,
      setDefaultsOnInsert: true, // Ensure 'clicks' starts at 0 if created
    }
  );

  await Url.findOneAndUpdate({short_url : short_url} , {$set : {clicks : urlAnalytics.clicks}}, {runValidators : true})

  Url.recordClick(short_url)

  return res.end()

};

module.exports = {
  storeShortUrl,
  getUserLinks,
  getUrlDetails,
  editUrl,
  getUrlDetailsForRedirecting,
  verifyUrlPassword,
  saveUrlAnalytics,
  disableLink
};
