require('dotenv').config();// for security on github
const express = require("express");// for rest api
const mongoose = require("mongoose");// for mongodb connection
const bodyParser = require("body-parser");// for form data
const jwt = require("jsonwebtoken");// for jwt
const cors = require("cors");// for cross origin policy
const bcrypt = require('bcrypt');// for hashing passwords
const Joi = require('@hapi/joi'); // for validation
const app = express();
const PORT = 3000;

app.use(cors());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
const joiUserSchema = Joi.object({
    email: Joi.string().email().required(),
    userName: Joi.string().required(),
    password: Joi.string().required(),
    items: Joi.array()
});
const UserSchema = new mongoose.Schema({
    email: {
        type: String,
        required: true,
        unique: true
      },
    userName: {
        type: String,
        required: true
      },
    password: {
        type: String,
        required: true
      },
    items:Array
});

const userModel =  mongoose.model("user",UserSchema); 
const jwtKey = String(process.env.JWT_SECRET);
const saltRounds = Number(process.env.SALT_ROUND);

mongoose.connect(process.env.CONNECTION_STRING, {useNewUrlParser: true, useUnifiedTopology: true});
mongoose.connection.once('open', function() {
 console.log("connected to "+process.env.CONNECTION_STRING)
});



app.post("/api/signup",async (req,res)=>{
    try{
        // check if the email already existed
        const data = {
            email:req.body.email,
            userName:req.body.userName,
            password: req.body.password
        }
        const user = await userModel.findOne({email:data.email});
        if(user){
            res.status(401).send("user already in database");
            return;
        }
        if(!data.userName || !data.password) throw new Error("no password or username provided");
        // hash new passsword
        let hashedPassword = bcrypt.hashSync(data.password, saltRounds);
        let obj = {
            email:data.email,
            userName:data.userName,
            password:hashedPassword,
            items:[]
        }
        // joi validation
        await joiUserSchema.validateAsync(obj);
        // create the user
        const newUser = new userModel(obj);
        await newUser.save();
        const token = jwt.sign({ _id:newUser._id }, jwtKey,{ expiresIn: '24h' });
        res.status(201).send(token);
    }catch(ex){
        res.status(400).send(ex);
    }
    
});

app.post("/api/login",async (req,res)=>{
    try{
        // check if user exist
        const data = {
            email:req.body.email,
            password: req.body.password
        }
        const user = await userModel.findOne({email:data.email});
        if(user){
            let isPassword = await bcrypt.compare(data.password, user.password);
            if(!isPassword) throw new Error("wrong password or email");
            const token = jwt.sign({ _id:user._id }, jwtKey,{ expiresIn: '24h' });
            res.status(200).send(token);
            return;
        }else{
            res.status(400).send("no such user");
        }
    }catch(ex){
        res.status(400).send(ex);
    }
     
});

// used to check authentication as middleware
function checkAuth(req,res,next){
    const token = req.header('x-auth-token');
    if(!token){return res.status(401).send('No Available token');}

    try{
        const decoded= jwt.verify(token,jwtKey);
        req.userId = decoded;
        next();
    }
    catch(ex){
        return res.status(400).send('Invalid Token');
    }
}

// get user items and name
app.get("/api/items",checkAuth,async (req,res)=>{
    try{
        const user = await userModel.findById(req.userId);
        if(!user){
            return res.status(400).send('cannot get items');
        }
        return res.status(200).json({items:user.items,name:user.userName});
    }catch(ex){
        return res.status(400).send('cannot get items');
    }
 
});


// add item
app.post('/api/item',checkAuth,async (req,res)=>{
    try{
        if(!req.body) throw new Error("no body found in request");
        const user = await userModel.findById(req.userId);
        if(!user){
            return res.status(400).send('cannot get items');
        }
        user.items.push(req.body);
        await user.save();
        return res.status(201).json(user.items);
    }catch(ex){
        return res.status(400).send(ex);
    }
})

// update item
app.put('/api/item/:index',checkAuth,async (req,res)=>{
    try{
        const user = await userModel.findById(req.userId);
        if(!user){
            return res.status(400).send('cannot edit items');
        }
        user.items[Number(req.params.index)].done = !user.items[Number(req.params.index)].done;
        user.markModified("items");
        await user.save();
        return res.status(200).json(user.items);
    }catch(ex){
        return res.status(400).send(ex);
    }
})



// update item
app.delete('/api/item/:index',checkAuth,async (req,res)=>{
    try{
        const user = await userModel.findById(req.userId);
        if(!user){
            return res.status(400).send('cannot edit items');
        }
        user.items.splice(Number(req.params.index),1);
        user.markModified("items");
        await user.save();
        return res.status(200).json(user.items);
    }catch(ex){
        return res.status(400).send(ex);
    }
})
app.listen(process.env.PORT || PORT,()=>console.log(`listening on port ${process.env.PORT || PORT}`))