import User from "../models/user.model.js";
import Message from "../models/message.model.js"
import cloudinary from "../lib/cloudinary.js";

export const getUsersForSidebar = async (req, res) => {
    try {
        const loggedInUserId = req.user._id;
        const filteredUsers = await User.find({ _id: { $ne: loggedInUserId } }).select("-password")

        res.status(200).json(filteredUsers)
    } catch (err) {
        console.log("Error in getUsersForSidebar", err.message)
        return res.status(500).json({ message: "Internal server error" })
    }
}

export const getMessages = async (req, res) => {
    try {
        const { id: userToChatId } = req.params;
        const myId = req.user._id;

        const messages = await Message.find({
            $or: [
                { senderId: myId, receiverId: userToChatId },
                { senderId: userToChatId, receiverId: myId },
            ]
        })

        res.status(200).json(messages)
    } catch (err) {
        console.log("Error in getMessages controller", err.message)
        return res.status(500).json({ message: "Internal server error" })

    }
}

export const sendMessages = async (req, res) => {
    try{
        const {text, image} = req.body
        const {id:receiverId} = req.params
        const senderId = req.user._id

        let imageUrl
        if(image){
            const uploadResponse = await cloudinary.uploader.upload(image)
            imageUrl = uploadResponse.secure_url
        }

        const newMessage = new Message({
            senderId:senderId,
            receiverId:receiverId,
            text:text,
            image:imageUrl
        })

        await newMessage.save();

        //todo: real time msg functionality goes here via socket.io ====================================

        res.status(201).json(newMessage)
    } catch(err){
        console.log("Error in sendMessages controller", err.message)
        return res.status(500).json({message:"Internal server error"})
    }
}