require("dotenv").config();
import { Request, Response, NextFunction } from "express";
import userModel, { IUser } from "../models/user.models";
import ErrorHandler from "../utils/ErrorHandler";
import CatchAsyncError from "../middlewares/catchAsyncErrors";
import jwt, { JwtPayload, Secret } from "jsonwebtoken";
import ejs, { closeDelimiter } from "ejs";
import { redis } from "../utils/redis";
import path from "path";
import sendMail from "../utils/sendMail";
import { accessTokenOptions, refreshTokenOptions, sendToken } from "../utils/jwt";
import HTTP_STATUS_CODES from "../constants/httpStatusCodes";
import { getUserById } from "../services/user.service";
import cloudinary from "cloudinary";

interface IRegistrationBody {
  name: string;
  email: string;
  password: string;
  avatar?: string;
}
interface IActivationToken {
  token: string;
  activationCode: string;
}
export const createActivationToken = (user: any): IActivationToken => {
  const activationCode = Math.floor(1000 + Math.random() * 9000).toString();

  const token = jwt.sign(
    {
      user,
      activationCode,
    },
    process.env.ACTIVATION_SECRET as Secret,
    {
      expiresIn: "5m",
    }
  );
  return {
    token,
    activationCode,
  };
};
export const registrationUser = CatchAsyncError(
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const { name, email, password } = req.body;
      const isEmailExist = await userModel.findOne({ email });
      if (isEmailExist) {
        return next(
          new ErrorHandler("Email already exist", HTTP_STATUS_CODES.BAD_REQUEST)
        );
      }
      const user: IRegistrationBody = {
        name,
        email,
        password,
      };
      const activationToken = createActivationToken(user);
      const activationCode = activationToken.activationCode;
      const data = { user: { name: user.name }, activationCode };
      const html = await ejs.renderFile(
        path.join(__dirname, "../mails/activation-mail.ejs"),
        data
      );
      try {
        await sendMail({
          email: user.email,
          subject: "Actiate your account",
          template: "activation-mail.ejs",
          data,
        });
        res.status(HTTP_STATUS_CODES.CREATED).json({
          success: true,
          message: `Please check your email: ${user.email} to activate your account`,
          activationToken: activationToken.token,
        });
      } catch (error: any) {
        return next(
          new ErrorHandler(error.message, HTTP_STATUS_CODES.BAD_REQUEST)
        );
      }
    } catch (error: any) {
      return next(
        new ErrorHandler(error.message, HTTP_STATUS_CODES.BAD_REQUEST)
      );
    }
  }
);
interface IActivationRequest {
  activation_token: string;
  activation_code: any; // Corrected property name
}

export const activateUser = CatchAsyncError(
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const { activation_token, activation_code } =
        req.body as IActivationRequest; // Destructure activation_token and activation_code
      const { user, activationCode } = jwt.verify(
        activation_token,
        process.env.ACTIVATION_SECRET as string
      ) as { user: IUser; activationCode: string }; // Corrected destructuring syntax

      // Check if activation code matches
      if (activationCode !== activation_code) {
        return next(
          new ErrorHandler(
            "Invalid activation code",
            HTTP_STATUS_CODES.BAD_REQUEST
          )
        );
      }

      const { name, email, password } = user; // Destructure user object
      const existingUser = await userModel.findOne({ email }); // Corrected variable name

      if (existingUser) {
        return next(
          new ErrorHandler(
            "Email already exists",
            HTTP_STATUS_CODES.BAD_REQUEST
          )
        );
      }

      const newUser = await userModel.create({
        name,
        email,
        password, 
      }); 

      res.status(HTTP_STATUS_CODES.CREATED).json({
        success: true,
      }); // Added missing semicolon
    } catch (error: any) {
      return next(
        new ErrorHandler(error.message, HTTP_STATUS_CODES.BAD_REQUEST)
      );
    }
  }
);

//Login user
interface ILoginRequest {
  email: string;
  password: string;
}

export const loginUser = CatchAsyncError(
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const { email, password } = req.body as ILoginRequest;
      if (!email || !password) {
        return next(
          new ErrorHandler(
            "Please enter email and password",
            HTTP_STATUS_CODES.BAD_REQUEST
          )
        );
      }
      const user = await userModel.findOne({ email }).select("+password");
      if (!user) {
        return next(
          new ErrorHandler(
            "Invalid email or password",
            HTTP_STATUS_CODES.BAD_REQUEST
          )
        );
      }
      const isPasswordMatch = await user.comparePassword(password);
      if (!isPasswordMatch) {
        return next(
          new ErrorHandler(
            "Invalid email or password",
            HTTP_STATUS_CODES.BAD_REQUEST
          )
        );
      }
      sendToken(user, 200, res);
    } catch (error: any) {
      return next(
        new ErrorHandler(error.message, HTTP_STATUS_CODES.BAD_REQUEST)
      );
    }
  }
);
//logout user
// export const logoutUser = CatchAsyncError(
//   async (req: Request, res: Response, next: NextFunction) => {
//     try {
//       res.cookie("access_token", "", { maxAge: 1 });
//       res.cookie("refresh_token", "", { maxAge: 1 });
//       const userId = req.user?._id;
//       if (!userId) {
//         throw new ErrorHandler("User ID not found", 400);
//       }

//       // Delete user session from Redis
//       await redis.del(userId);

//       res.status(200).json({
//         success: true,
//         message: "Logged out successfully",
//       });
//     } catch (error: any) {
//       return next(new ErrorHandler(error.message, 400));
//     }
//   }
// );
// Logout user
export const logoutUser = CatchAsyncError(
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      // Clear access_token and refresh_token cookies
      res.clearCookie("access_token");
      res.clearCookie("refresh_token");

      // Check if req.user is defined and contains the user ID
      const userId = req.user?._id;
      if (!userId) {
        throw new ErrorHandler("User ID not found",  HTTP_STATUS_CODES.BAD_REQUEST);
      }

      // Delete user session from Redis
      await redis.del(userId);

      res.status(200).json({
        success: true,
        message: "Logged out successfully",
      });
    } catch (error: any) {
      return next(new ErrorHandler(error.message,  HTTP_STATUS_CODES.BAD_REQUEST));
    }
  }
);

//update access token
export const updateAccessToken=CatchAsyncError(async(req:Request,res:Response,next:NextFunction)=>{
  try {
    const refresh_token=req.cookies.refresh_token as string;
    const decoded=jwt.verify(refresh_token,
      process.env.REFRESH_TOKEN as string) as JwtPayload;

      const message='Could not refresh token';
      if(!decoded){
        return next(new ErrorHandler(message, HTTP_STATUS_CODES.BAD_REQUEST));
      }

      const session=await redis.get(decoded.id as string);

      if(!session){
        return next(new ErrorHandler(message,HTTP_STATUS_CODES.BAD_REQUEST));
      }

      const user=JSON.parse(session);

      const accessToken=jwt.sign({id:user._id},process.env.ACCESS_TOKEN as string,{
        expiresIn:"5m"
      })
console.log("accessToken",accessToken);
      
      const refreshToken=jwt.sign({id:user._id},process.env.REFRESH_TOKEN as string,{
        expiresIn:"3d"
      })
      console.log("refreshToken",refreshToken);
      req.user=user;
      res.cookie("access_token",accessToken,accessTokenOptions);
      res.cookie("refresh_token",refreshToken,refreshTokenOptions); 

      res.status(HTTP_STATUS_CODES.OK).json({
        status:"Success",
        accessToken,
      })
    
  } catch (error: any) {
    return next(new ErrorHandler(error.message,  HTTP_STATUS_CODES.BAD_REQUEST));
  }
})


//get user info

export const getUserInfo=CatchAsyncError(async(req:Request,res:Response,next:NextFunction)=>{
  try {
    const userId=req.user?._id;
getUserById(userId,res);
    
  } catch (error: any) {
    return next(new ErrorHandler(error.message,  HTTP_STATUS_CODES.BAD_REQUEST));
  }
 
})

interface ISocialAuthBody{
  email:string;
  name:string;
  avatar:string;
}
//social auth
export const socialAuth=CatchAsyncError(async(req:Request,res:Response,next:NextFunction)=>{
  try {
    const {email,name,avatar}=req.body as ISocialAuthBody;
    const user=await userModel.findOne({email});
    if(!user){
      const newUser=await userModel.create({email,name,avatar});
      sendToken(newUser,200,res);
    }
    else{
      sendToken(user,200,res);
    }
  }catch (error: any) {
    return next(new ErrorHandler(error.message,  HTTP_STATUS_CODES.BAD_REQUEST));
  }
})

//update user info

interface IUpdateUserInfo{
  name?:string;
  email?:string;
}
 export const updateUserInfo=CatchAsyncError(async(req:Request,res:Response,next:NextFunction)=>{
  try {
    const {name}=req.body as IUpdateUserInfo;
    const userId=req.user?._id;
    const user=await  userModel.findById(userId);

    // if(email && user){
    //   const isEmailExist=await userModel.findOne({email});
    //   if(isEmailExist){
    //     return next(new ErrorHandler('Emal already exist',HTTP_STATUS_CODES.BAD_REQUEST));
    //   }
    //   user.email=email;
    // }
    if(name && user){
      user.name=name;
    }

    await user?.save();

    await redis.set(userId,JSON.stringify(user));

    res.status(HTTP_STATUS_CODES.CREATED).json({
      success:true,
      user,
    })
  } catch (error: any) {
    return next(new ErrorHandler(error.message,  HTTP_STATUS_CODES.BAD_REQUEST));
  }
 })

 interface IUpdatePassword{
  oldPassword:string;
  newPassword:string;
 }

 export const updatePassword=CatchAsyncError(async(req:Request,res:Response,next:NextFunction)=>{

  try {

    const {oldPassword,newPassword}=req.body as IUpdatePassword;
    if(!oldPassword || !newPassword){
      return next(new ErrorHandler("Please enter old and new passwords",HTTP_STATUS_CODES.BAD_REQUEST));
    }
    const user=await userModel.findById(req.user?._id).select("+password");

    if(user?.password===undefined){
      return next(new ErrorHandler('Invalid user',HTTP_STATUS_CODES.BAD_REQUEST));
    }
    const isPasswordMatch=await user.comparePassword(oldPassword);

    if(!isPasswordMatch){
      return next(new ErrorHandler("Invalid old password",HTTP_STATUS_CODES.BAD_REQUEST));
    }

    user.password=newPassword;

    await user.save();

    await redis.set(req.user?._id,JSON.stringify(user));

    res.status(HTTP_STATUS_CODES.CREATED).json({
      success:true,
      user,
    });
    
  } catch (error: any) {
    return next(new ErrorHandler(error.message, HTTP_STATUS_CODES.BAD_REQUEST));
  }
 })

 //update user profile picture /avatar

 interface IUpdateProfilePcture{
  avatar:string
 }

 export const updateUserProfilePicture=CatchAsyncError(async (req:Request,res:Response,next:NextFunction)=>{
  try {
    const {avatar}=req.body;

    const userId=req.user?._id;
    const user=await userModel.findById(userId);

    if(avatar && user){
      if(user?.avatar?.public_id){

        await cloudinary.v2.uploader.destroy(user?.avatar?.public_id);

          const myCloud=await cloudinary.v2.uploader.upload(avatar,{
            folder:"avatars",
            width:150
          });

          user.avatar={
            public_id:myCloud.public_id,
            url:myCloud.secure_url
          }
         }
         else{
          const myCloud=await cloudinary.v2.uploader.upload(avatar,{
            folder:"avatars",
            width:150
          });
          user.avatar={
            public_id:myCloud.public_id,
            url:myCloud.secure_url
          }
         }
    }
    await user?.save();
    await redis.set(userId,JSON.stringify(user));

    res.status(HTTP_STATUS_CODES.OK).json({
      success:true,
      user
    })
    
  }  catch (error: any) {
    return next(new ErrorHandler(error.message, HTTP_STATUS_CODES.BAD_REQUEST));
  }
 })