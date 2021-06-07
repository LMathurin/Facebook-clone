const mongoose = require('mongoose');
const config = require('config');
const Joi = require('Joi');

const FriendRequestSchema = new mongoose.Schema ({

    sender: {
        type: Schema.Types.ObjectId,
        ref: 'User',
    },
    receiver: {
        type: Schema.Types.ObjectId,
        ref: 'User',
    },
    isAccepted: {
        type: Boolean,
        default: false,
    },
},

    { timestamps: true },
  
);

module.exports = mongoose.model('FriendRequest', FriendRequestSchema);