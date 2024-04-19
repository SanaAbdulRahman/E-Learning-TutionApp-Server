require("dotenv").config();
import mongoose, { Document, Model, Schema } from "mongoose";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";

const emailRegexPattern: RegExp = /^[^\$@]+@[^\$@]+\.[^\$@]+$/;

export interface IUser extends Document {
  name: string;
  email: string;
  password: string;
  avatar: {
    public_id: string;
    url: string;
  };
  role: string;
  isVerified: boolean;
  courses: Array<{ courseId: String }>;
  comparePassword: (password: string) => Promise<boolean>;
  SignAccessToken: () => string;
  SignRefreshToken: () => string;
}

const userSchema: Schema<IUser> = new mongoose.Schema(
  {
    name: {
      type: String,
      required: [true, "Please enter your name"],
      //unique: true
    },
    email: {
      type: String,
      required: [true, "Please enter your email"],
      validate: {
        validator: function (value: string) {
          return emailRegexPattern.test(value);
        },
        message: "Please enter a valid email!",
      },
      unique: true,
      // match: emailRegexPattern
    },
    password: {
      type: String,
      
      minlength: [6, "Password must be atleast 6 characters"],
      select: false,
    },

    //Profile picture
    avatar: {
      public_id: String,
      url: String,
    },
    role: {
      type: String,
      default: "user",
    },
    isVerified: {
      type: Boolean,
      default: false,
    },
    courses: [
      {
        courseId: String,
        // type: mongoose.Schema.Types.ObjectId,
        //ref: 'Course' // Reference to the Course model
      },
    ],
  },
  { timestamps: true }
);

// Hash password before saving to database
userSchema.pre<IUser>("save", async function (next) {
  try {
    if (!this.isModified("password")) {
      return next();
    }
    const hashedPassword = await bcrypt.hash(this.password, 10);
    this.password = hashedPassword;
    next();
  } catch (error: any) {
    return next(error);
  }
});

//sign access token
userSchema.methods.SignAccessToken = function () {
  return jwt.sign({ id: this._id }, process.env.ACCESS_TOKEN || "",{
    expiresIn:"5m"
  });
};

//sign refresh token
userSchema.methods.SignRefreshToken = function () {
  return jwt.sign({ id: this._id }, process.env.REFRESH_TOKEN || "",{
    expiresIn:"3d"
  });
};

// Custom method to compare password
userSchema.methods.comparePassword = async function (enteredpassword: string) {
  try {
    return await bcrypt.compare(enteredpassword, this.password);
  } catch (error: any) {
    throw new Error(error);
  }
};
const userModel: Model<IUser> = mongoose.model("User", userSchema);

//const User = mongoose.model('User', userSchema);

export default userModel;
