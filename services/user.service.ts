import { Response } from "express";
import HTTP_STATUS_CODES from "../constants/httpStatusCodes";
import { redis } from "../utils/redis";


//Get user by id
export const getUserById=async(id:string,res:Response)=>{
    const userJson=await redis.get(id);
    if(userJson){
        const user=JSON.parse(userJson);
        res.status(HTTP_STATUS_CODES.CREATED).json({
            success:true,
            user,
        });
    }
    
}