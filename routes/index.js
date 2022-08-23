const router = require("express").Router();
const User = require("../models/User.model");
const bcrypt = require("bcryptjs");
const jsonWebToken = require("jsonwebtoken");
const { isAuthenticated } = require("../middleware/middleware");
/* GET default route */
router.get("/", (req, res, next) => {
  res.json({ success: true });
});

router.post("/signup", async (req, res, next) => {
  const { username, password } = req.body;
  if (!password || !username) {
    return res
      .status(400)
      .json({ message: "Please provide a password and username." });
  }
  if (password.length < 4) {
    return res.status(400).json({ message: "password is too short!" });
  }
  try {
    const foundUser = await User.findOne({ username });
    if (foundUser) {
      return res.status(400).json({
        message:
          "Username already in use, try logging in or registering with an other username.",
      });
    }
    const hashedPassword = bcrypt.hashSync(password);
    const newUser = {
      username,
      password: hashedPassword,
    };
    const createdUser = await User.create(newUser);
    res.status(201).json(createdUser);
  } catch (error) {
    next(error);
  }
});

router.post("/login", async (req, res, next) => {
  const { username, password } = req.body;
  try {
    const foundUser = await User.findOne({ username });
    if (!foundUser) {
      res
        .status(400)
        .json({ message: "could not find an account with this username" });
    }
    const matchingPassword = bcrypt.compareSync(password, foundUser.password);
    if (!matchingPassword) {
      res.status(400).json({ message: "wrong password" });
    }
    const payload = { username };
    const token = jsonWebToken.sign(payload, process.env.TOKEN_SECRET, {
      algorithm: "HS256",
      expiresIn: "1h",
    });
    res.status(200).json(token);
  } catch (error) {
    next(error);
  }
});

router.get("/main", isAuthenticated, async (req, res, next) => {
  try {
    res.json({
      picture:
        "https://cdn.pixabay.com/photo/2017/02/20/18/03/cat-2083492__340.jpg",
    });
  } catch (error) {
    next(error);
  }
});

router.use("/private", isAuthenticated, async (req, res, next) => {
  try {
    res.json({
      picture: "https://media2.giphy.com/media/ICOgUNjpvO0PC/giphy.gif",
    });
  } catch (error) {
    next(error);
  }
});

module.exports = router;
