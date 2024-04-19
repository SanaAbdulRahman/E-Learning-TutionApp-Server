import express from "express";
import {isAuthenticated} from "../middlewares/auth";
//import {authorizeRoles} from "../middlewares/auth";
import {
  activateUser,
  loginUser,
  registrationUser,
  logoutUser,
  updateAccessToken,
  getUserInfo,
  socialAuth,
  updateUserInfo,
  updatePassword,
  updateUserProfilePicture,
} from "../controllers/user.controller";

const userRouter = express.Router();

userRouter.post("/registration", registrationUser);

userRouter.post("/activate-user", activateUser);

userRouter.post("/login", loginUser);

userRouter.get("/logout", isAuthenticated, logoutUser);

userRouter.get("/refresh",updateAccessToken);

userRouter.get("/me",isAuthenticated,getUserInfo);

userRouter.post("/social-auth",socialAuth);

userRouter.put("/update-user-info",isAuthenticated,updateUserInfo);

userRouter.put("/update-user-password",isAuthenticated,updatePassword);

userRouter.put("/update-user-avatar",isAuthenticated,updateUserProfilePicture);








export default userRouter;
