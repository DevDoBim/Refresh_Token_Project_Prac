const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
const express = require("express");
const app = express();
const port = 3002;
const SECRET_KEY = `HangHae99`;

app.use(cookieParser());

app.get("/", (req, res) => {
  res.status(200).send("Hello Token!");
})

app.listen(port, () => {
  console.log(port, '포트로 서버가 열렸어요!');
})