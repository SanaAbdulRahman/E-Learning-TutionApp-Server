require("dotenv").config();
import express,{NextFunction,Request,Response} from 'express';
export const app = express();
import cors from 'cors';
import cookieParser from 'cookie-parser';
import {ErrorMiddleware} from './middlewares/error'; 
import userRouter from './routes/user.route';
import HTTP_STATUS_CODES from './constants/httpStatusCodes';



//body parser
app.use(express.json({ limit: "50mb" }));

//cookie parser
app.use(cookieParser());

//cors => cross origin resource sharing

app.use(cors({
   // origin: process.env.ORIGIN,
   origin:['http://localhost:3000'],
   credentials:true
}))

//routes
app.use("/api/v1", userRouter)

//testing api
app.get("/test", (req:Request, res:Response, next:NextFunction) => {
    res.status(HTTP_STATUS_CODES.OK).json({
        success: true,
        message: "API is working",
    })
})

//unknown routes
app.all("*", (req:Request, res:Response, next:NextFunction) => {
    const err = new Error(`Route ${req.originalUrl} not found`) as any;
    err.statusCode = HTTP_STATUS_CODES.NOT_FOUND;
    next(err);
});


app.use(ErrorMiddleware);

