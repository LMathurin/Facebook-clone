const mongoose = require("mongoose");
const config = require('config');
const jwt = require('jsonwebtoken');
const { commentSchema } = require('./comments');


const addUserSchema = new mongoose.Schema({

    username: {
        type: String,
        required: true,
        minlength: 5,
        maxlength: 20,
        unique: true,
    },
    email: {
        type: String,
        required: true,
        max: 50,
        unique: true,
    },
    password: {
        type: String,
        required: true,
        min: 6,
    },
    profilePicture: {
        type: String,
        default: "",
    },
    followers: {
        type: Array,
        default: [],
    },
    following: {
        type: Array,
        default: [],
    },
    bio: {
        type: String,
        max: 80
    },
    location: {
        type: String,
        max: 80 
    },
    education: {
        type: String,
        trim: true,
    },
    
    friends: [{ type: Schema.Types.ObjectId, ref: 'User' }],
   },

   { timestamps: true }    
);


const User = mongoose.model('User', addUserSchema);

function validateUser(user) {
    const schema = Joi.object({
    name: Joi.string().min(5).max(50).required(),
    email: Joi.string().min(5).max(255).required().email(),
    password: Joi.string().min(5).max(1024).required(),
    });
    return schema.validate(user);
};    

exports.User = User;
exports.validateUser = validateUser;
