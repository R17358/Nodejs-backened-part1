import mongoose from "mongoose";
import express from "express";      //npm i mongoose - to connect database
import path from "path";
import cookieParser from "cookie-parser";   //to access cookies
import jwt from "jsonwebtoken";     //for id encryption
import bcrypt from "bcrypt";    //for password hashing

mongoose.connect("mongodb://127.0.0.1:27017",{          //database connection
    dbName: "backened",
}).then(()=>console.log("Database Connected")).catch((e)=>console.log(e));

const userSchema = new mongoose.Schema({
    name:String,                                            //define schema of daatabase
    password:String,            //Number
});

const User = mongoose.model("User",userSchema)      //table or collection

const app = express();

app.set("view engine", "ejs");
app.use(express.static(path.join(path.resolve(),"static")));
app.use(express.urlencoded({extended: true}));      //middleware to access form data
app.use(cookieParser());        //cookies

const isAuthenticated = async(req,res,next)=>{
    const {token} = req.cookies;
    if(token){

        const decoded = jwt.verify(token, "abcdefghi");
        //console.log(decoded);
        req.user = await User.findById(decoded._id);
        next();
    }
    else{
        res.redirect("/login");
    }
}
app.get("/",isAuthenticated,(req,res) => {
    //console.log(req.user);
    res.render("logout",{name:req.user.name});
});
app.get("/login",(req,res)=>{
    res.render("login");
});
app.get("/register", async(req,res) => {
    res.render("register");
})
app.post("/login",async(req,res) => {
    const {name,password} = req.body;
    let user = await User.findOne({name});

    if(!user) return res.redirect("/register");

   // const isMatch = user.password === password;
    const isMatch = await bcrypt.compare(password, user.password);      //comparing password

    if(!isMatch) return res.render("login",{message:"Incorrect password"});

    const token = jwt.sign({_id:user._id},"abcdefghi");

    res.cookie("token",token,{
        httpOnly:true,expires:new Date(Date.now()+60*1000)
    });
    res.redirect("/");
});

app.post("/register", async(req,res) =>{

   // console.log(req.body);
    const {name,password} = req.body;

    let user = await User.findOne({name});
    if(user)
    {
        return res.redirect("/login");       //if user is  in database
    }

        const hashedPassword = await bcrypt.hash(password,10);      //password hashing

        user = await User.create({
            name,
            password: hashedPassword,
        });
    
        const token = jwt.sign({_id:user._id},"abcdefghi");
    
        res.cookie("token",token,{
            httpOnly:true,expires:new Date(Date.now()+60*1000)
        });
        res.redirect("/");
    
});

app.get("/logout", (req,res) => {
    res.cookie("token", null, {
        expires: new Date(Date.now()),
    });
    res.redirect("/");
});

app.listen(5000, () => {
    console.log("Server is working");       //npm i ejs
});