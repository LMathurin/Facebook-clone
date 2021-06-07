const Joi = require('joi');
const config = require('config/');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const User = require('../models/user');
const express = require('express');
const router = express.Router();



router.post('/add-user', async (req, res) => {
    try {
      const { error } = validateLogin(req.body);
      if (error) return res.status(400).send(error.details[0].message);

      let user = await User.findOne({ email: req.body.email });
      if (!user) return res.status(400).send('Invalid email or password.');

      const validPassword = await bcrypt.compare(req.body.password, user.password);

      if (!validPassword) return res.status(400).send('Invalid email or password.')

      const token = jwt.sign({_id: user._id, name: user.name }, config.get('jwtSecret'));

      return res.send(token);
    } catch (ex) {
      return res.status(500).send(`Internal Server Error: ${ex}`);
    }
});      

function validateLogin(req) {
    const schema = Joi.object({
      email: Joi.string().min(5).max(255).required().email(),
      password: Joi.string().min(5).max(1024).required(),
    });
    return schema.validate(req);
}

router.post("/register", async (req, res) => {
    try {
      let { email, password, passwordCheck, displayName } = req.body;

      if (!email || !password || !passwordCheck)
        return res
        .status(400)
        .json({ msg: "Not all fields have been entered." });
      if (password.length < 5) 
        return res
        .status(400)
        .json({msg: "The password needs to be at least 5 characters long." });
      if (password !== passwordCheck) 
        return res
        .status(400)
        .json ({ msg: "Enter the same password twice for verification." });

      const existingUser = await User.findOne({ email: email });
      if (existingUser) 
        return res
         .status(400)
         .json({ msg: "An account with this email already exists." });

      if (!displayName) displayName = email;

      const salt = await bcrypt.genSalt();
      const passwordHash = await bcrypt.hash(password, salt);
  
      const newUser = new User({
        username: req.body.username,
        email: req.body.email,
        password: hashedPassword,
      });
  
      const user = await newUser.save();
      res.status(200).json(user);
    } catch (err) {
      res.status(500).json(err)
    }
});
  
//LOGIN
router.post("/login", async (req, res) => {
    try {
      const user = await User.findOne({ email: req.body.email });
      !user && res.status(404).json("user not found");
  
      const validPassword = await bcrypt.compare(req.body.password, user.password)
      !validPassword && res.status(400).json("Invalid password")
  
      res.status(200).json(user)
    } catch (err) {
      res.status(500).json(err)
    }
});
  
router.get ("/logout", async (req, res) => { req.logout();
   return res.json({
      message: 'Successfully logged out'
  });
});


module.exports = router;
  