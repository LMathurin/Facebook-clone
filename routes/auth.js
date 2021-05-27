const Joi = require('joi');
const config = require('config');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const User = require("../models/user");
const router = express.Router();

router.post('/', async (req, res) => {
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
      //generate new password
      const salt = await bcrypt.genSalt(10);
      const hashedPassword = await bcrypt.hash(req.body.password, salt);
  
      //create new user
      const newUser = new User({
        username: req.body.username,
        email: req.body.email,
        password: hashedPassword,
      });
  
      //save user and respond
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
      !validPassword && res.status(400).json("wrong password")
  
      res.status(200).json(user)
    } catch (err) {
      res.status(500).json(err)
    }
});
  
  module.exports = router;