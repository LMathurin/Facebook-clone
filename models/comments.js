const mongoose = require("mongoose");
const config = require('config');
const Joi = require('Joi');


const commentSchema = new mongoose.Schema ({
    
    comment: {
        type: String,
        required: true
    },
    likes: {
        type: Number,
        default: 0,
    },
    dislikes: {
        type: Number,
        default: 0,
    },
    date: {
        type: Date,
        default: Date.now,
    },
});

const Comment = mongoose.model('Comment', commentSchema);

exports.Comment = Comment;
exports.commentSchema = commentSchema;