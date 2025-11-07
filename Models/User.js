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
    email: {
      type: String,
      required: [true, "emailRequired"],
      unique: true,
      lowercase : true,
      validate : [isEmail , 'emailInvalid']
    },
    password: {
      type: String,
      // required: [true, "passwordRequired"],
      // minLength: [6, "passwordMinLength"],
      selected : false
    },
    isGoogleUser :{
      type : Boolean,
      default : false
    },
    refresh_token : {
      type : String,
    }
  },
  {
    timestamps: true,
  }
);

userSchema.pre('save' , async function(next)  {
    if (!this.isModified('password')) return next();

    try {
        const salt = await bcrypt.genSalt()
        this.password = await bcrypt.hash(this.password , salt)
        next()
    }
    catch (err) {
      throw err;
    }
})


userSchema.statics.login = async function (email, password) {
  const user = await this.findOne({email}); 

  if(user) {
    const pwisvalid = await bcrypt.compare(password , user.password)

    if(pwisvalid) {
      user.password = undefined; 
      return user
    }

    throw Error('invalidCredentials')
  }

  throw Error('invalidCredentials')
}

module.exports = mongoose.model('User', userSchema);
