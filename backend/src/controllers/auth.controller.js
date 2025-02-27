import { generateToken } from "../lib/utils.js";
import User from "../models/user.model.js";
import bcrypt from "bcryptjs"
// import express from "express";


export const signup = async (req, res) => {
    const { fullName, email, password } = req.body;
    try {
        if(!fullName || !email || !password)
            return res.status(400).json({message: "Some mandatory fields are empty"})
        if (password.length < 6)
            return res.status(400).json({ message: "Password must be atleast 6 characters" })

        const user = await User.findOne({ email })
        if (user)
            return res.status(400).json({ message: "user with this email already exists" })

        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password,salt)

        const newUser = new User({
            fullName:fullName,
            email:email,
            password:hashedPassword,
        })

        if(newUser){
            //generalte JWT token
            await newUser.save();
            generateToken(newUser._id, res)

            res.status(201).json({
                _id:newUser._id,
                fullName:newUser.fullName,
                email:newUser.email,
                profilePic:newUser.profilePic,
            })
        } else{
            res.status(400).json({message:"Invalid user data"})
        }
    } catch(err){
        console.log("error in signup controller", err.message)
        return res.status(500).json({message:"Internal server error"})
    }
}

export const login = async (req, res) => {
    const {email, password} = req.body;
    try{
        const user = await User.findOne({email})

        if(!user)
            return res.status(400).json({message:"Invalid credentials"})

        const isPasswordCorrect = await bcrypt.compare(password, user.password)
        if(!isPasswordCorrect)
            return res.status(400).json({message:"Invalid Credentials"})

        generateToken(user._id, res)

        res.status(200).json({
            _id:user._id,
            fullName:user.fullName,
            email:user.email,
            profilePic:user.profilePic
        })
    } catch(err){
        console.log("Error in login controller", err.message)
        res.status(500).json({message:"Internal server error"})
    }
}

export const logout = (req, res) => {
    try{
        res.cookie("jwt", "", {maxAge:0})
        res.status(200).json({message:"Logged out successfully"})
    } catch(err){
        console.log("Error in logout controller", err.message)
        res.status(500).json({message:"Internal server error"})
    }
}