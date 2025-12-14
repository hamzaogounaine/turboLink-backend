const mongoose = require("mongoose");
const bcrypt = require('bcrypt');
const { isEmail } = require("validator");

const userSchema = mongoose.Schema(
  
  {
    googleId : {
      type : String
    },
    username: {
      type: String,
      required: [true, "usernameRequired"],
      unique: true,
      trim: true,
    },
    first_name : {
      type : String,
      trim : true
    },
    last_name : {
      type : String,
      trim : true
    },
    email: {
      type: String,
      required: [true, "emailRequired"],
      unique: true,
      lowercase : true,
      validate : [isEmail , 'emailInvalid']
    },
    phone_number : {
      type : String,
      default : null
    },
    is_phone_number_verified : {
      type : Boolean,
      default : false
    },
    password: {
      type: String,
      // required: [true, "passwordRequired"],
      // minLength: [6, "passwordMinLength"],
      select: false
    },
    is_google_user :{
      type : Boolean,
      default : false
    },
    avatar_url  : {
      type : String,
      default : null
    },
    is_email_verified : {
      type : Boolean,
      default : false
    },
    refresh_token : {
      type : String,
    },
    last_login_ip: { 
      type: String, 
      required: false,
    },
    ip_verification_token : {
      type : String,
      default : null
    },
    ip_verification_token_expiration : {
      type : Date,
      default : null
    },
    ip_verification_display_code : Number,
    pending_login_ip : String,
    password_reset_token : {
      type : String
    },
    password_reset_token_expiration : {
      type : Date
    }
  },
  {
    timestamps: true,
  }
);

userSchema.pre('save', async function (next) {
  if (!this.isModified('password')) return next();


  try {
    const salt = await bcrypt.genSalt();
    this.password = await bcrypt.hash(this.password, salt);
    next();
  } catch (err) {
    next(err); // ❗ FIX — do NOT throw inside middleware
  }
});



userSchema.statics.login = async function (email, password) {
  const user = await this.findOne({ email }).select('+password'); 
  if (!user) {
    throw Error('invalidCredentials');
  }
  const pwisvalid = await bcrypt.compare(password, user.password);

  if (pwisvalid) {
    user.password = undefined;
    return user;
  }

  throw Error('invalidCredentials');
}

module.exports = mongoose.model('User', userSchema);
