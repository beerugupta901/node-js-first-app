import express from "express";
import ejs from "ejs";
import cookieParser from "cookie-parser";
import path from "path";
import mongoose from "mongoose";
import jwt from "jsonwebtoken"; 
import { setEngine } from "crypto";
import { error } from "console";
import { Session } from "inspector";
import bcrypt from "bcrypt";
const app=express();

app.use(cookieParser())
app.use(express.urlencoded({extended:"true"}));
app.set("view engine","ejs")

mongoose.connect("mongodb://127.0.0.1:27017/",{//conncting to database namely "authentication"
    dbName:"authentication"
}).then((result) => {
    console.log("connected to database")
}).catch((err) => {
    console.log(error)
});

const User=mongoose.model("user",new mongoose.Schema({
    name:String,   //here "user" is the name of model
    email:String,
    password:String,
}))

const isAuthenticated=async (req,res,next)=>{
    const {token}=req.cookies;
    if(token){

     const decoded=jwt.verify(token,"abcdefgh") //this will hold all the decoded data i.e. _id
     req.user= await User.findById(decoded._id)  
     next()   //control send to "/"
    }
     res.render("login")
}



app.get("/",isAuthenticated,(req,res)=>{
    res.render("logout",{naam:req.user.name}) //controls comes here from next()
})

app.post("/signup",async (req,res)=>{
    const{name, email,password}=req.body
    const user2 =await User.findOne({email})
    if(user2){
        res.render("login",{message:"User already exists,login"})
    }
    
    const hashedPassword =await bcrypt.hash(password,10)
    const user1 = await User.create({name,email,password:hashedPassword})   //created new user
   
    res.redirect("/");
})

app.get("/logout",(req,res)=>{
    res.cookie("token","",{
        maxAge:0
    }) //cleared token
    res.redirect("/") //now "/" page will render login page as no token is there
})



app.post("/login", async (req, res) => {
    const { email, password } = req.body;
    const user3 = await User.findOne({ email });

    if (!user3) {
        return res.render("signup")
    }

    const isMatch =await bcrypt.compare(password,user3.password)
    if (isMatch) {
        let token = jwt.sign({ _id: user3._id }, "abcdefgh");
        res.cookie("token", token, {  // passing created user's info in token
            httpOnly: true,
            maxAge: 600 * 1000 // 10 minute session
        });
        return res.redirect("/");
    }
    
    res.render("login", { message: "Incorrect Password" });
});



app.listen("3000",()=>{
    console.log("server is working")
});