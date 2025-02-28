import express from "express"
import dotenv from "dotenv"
import cookieParser from "cookie-parser"
dotenv.config()
import authRoutes from "./routes/auth.route.js"
import messageRoutes from "./routes/message.route.js"
import {connectDB} from "./lib/db.js"

const app = express();
const PORT = process.env.PORT

app.use(express.json());
app.use(cookieParser())
app.use("/api/auth", authRoutes);
app.use("/api/auth", messageRoutes);

app.listen(PORT, ()=>{
    console.log("server is running on PORT:"+ PORT);
    connectDB();    
})
