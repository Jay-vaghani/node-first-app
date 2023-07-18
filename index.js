const express = require("express");
const mongoose = require("mongoose");
const cookieParser = require("cookie-parser");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const path = require("path");
const app = express();

mongoose
  .connect("mongodb://127.0.0.1:27017", {
    dbName: "backend",
  })
  .then(() => console.log("Database Connected"))
  .catch((err) => console.log(err));

const UserDataSchema = mongoose.Schema({
  name: {
    type: String,
    required: true,
  },
  email: {
    type: String,
    required: true,
  },
  password: String,
});

const UserData = mongoose.model("user", UserDataSchema);

app.set("view engine", "ejs");

app.use(express.static(path.join(path.resolve(), "/public")));

app.use(express.urlencoded({ extended: true }));

app.use(cookieParser());

const isAuthenticated = async (req, res, next) => {
  const { token } = req.cookies;
  if (token) {
    const decoded = jwt.verify(token, "password");

    req.user = await UserData.findById(decoded._id);

    next();
  } else {
    res.redirect("/login");
  }
};

app.get("/", isAuthenticated, (req, res) => {
  const { name } = req.user;
  res.render("logout", { name: name });
});

app.get("/register", (req, res) => {
  res.render("register");
});

app.get("/login", (req, res) => {
  res.render("login");
});

// *************************************************************

app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  let user = await UserData.findOne({ email });

  if (!user) {
    return res.redirect("/register");
  }

  const isMatch = await bcrypt.compare(password, user.password);

  if (!isMatch) {
    return res.render("login", { message: "Invalid Password" });
  }

  const token = jwt.sign({ _id: user._id }, "password");

  res.cookie("token", token, {
    httpOnly: true,
    expires: new Date(Date.now() + 60 * 1000),
  });
  res.redirect("/");
});

app.post("/register", async (req, res) => {
  const { name, email, password } = req.body;

  let user = await UserData.findOne({ email: email });

  if (user) {
    return res.redirect("/login");
  }

  const hashedPassword = await bcrypt.hash(password, 10);

  user = await UserData.create({ name, email, password: hashedPassword });

  const token = jwt.sign({ _id: user._id }, "password");

  res.cookie("token", token, {
    httpOnly: true,
    expires: new Date(Date.now() + 60 * 1000),
  });
  res.redirect("/");
});

app.post("/logout", (req, res) => {
  res.cookie("token", null, {
    httpOnly: true,
    expires: new Date(Date.now()),
  });
  res.redirect("/");
});

app.listen("5000", () => {
  console.log("Server Is Running");
});
