const mongoose = require("mongoose");
const bcrypt = require('bcrypt');


const analyticsSchema = mongoose.Schema({
  short_url: {
    type: String,
    required: true,
    index: true
  },
  clicks: {
    type: Number,
    default: 0
  },
  click_details: [{
    timestamp: {
      type: Date,
      default: Date.now
    },
    ip_address: String,
    user_agent: String,
    referrer: String,
    country: String,
    city: String,
    device_type: String,
    browser: String,
    os: String
  }],
  created_at: {
    type: Date,
    default: Date.now
  }
});

const urlSchema = mongoose.Schema({
  redirect_url: {
    type: String,
    required: true,
    trim: true
  },
  short_url: {
    type: String,
    required: true,
    unique: true,
    trim: true,
    index: true
  },
  user_id: {
    type: String,
    required: true,
    index: true
  },
  title: String,
  description: String,
  password : String,
  max_clicks : Number,
  current_clicks : Number,
  expires_at: Date,
  is_active: {
    type: Boolean,
    default: true
  },
  custom_alias: String,
  tags: [String],
  qr_code: String
}, {
  timestamps: true
});

// Index for faster queries
urlSchema.index({ user_id: 1, created_at: -1 });
urlSchema.index({ short_url: 1, is_active: 1 });



// Pre-save middleware to update the updated_at field
urlSchema.pre('save', async function(next) {
  this.updated_at = Date.now();

  if (!this.isModified('password')) return next();

  if(this.password) {
    try {
      const salt = await bcrypt.genSalt();
      this.password = await bcrypt.hash(this.password, salt);
      next();
    } catch (err) {
      next(err); // ❗ FIX — do NOT throw inside middleware
    }
  }
  next();
});

const Analytics = mongoose.model("Analytics", analyticsSchema);
const Url = mongoose.model("Url", urlSchema);

module.exports = { Analytics, Url };