const express = require("express");
const bodyParser = require("body-parser");
const low = require("lowdb");
const shortid = require("shortid");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const { authenticator } = require("otplib");

const FileSync = require("lowdb/adapters/FileSync");

const SECRET_APP = "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d";
const SERVICE = "demo";

const app = express();
const port = 3000;

const adapter = new FileSync("db.json");
const db = low(adapter);

db.defaults({ users: [] }).write();

app.use(bodyParser.json());

app.post("/signup", (req, res) => {
  const { username, password } = req.body;

  if (!(username && password)) {
    return res.status(400).send({ message: "BAD_REQUEST" });
  }

  const secret = authenticator.generateSecret();
  const hashedPassword = bcrypt.hashSync(password, 10);

  db.get("users")
    .push({
      id: shortid.generate(),
      username,
      password: hashedPassword,
      secret: secret
    })
    .write();

  const otp = authenticator.keyuri(username, SERVICE, secret);
  return res.status(200).send({ username, otp });
});

app.post("/login", (req, res) => {
  const { username, password, otp } = req.body;

  if (!(username && password && otp)) {
    return res.status(400).send({ message: "BAD_REQUEST" });
  }

  const user = db
    .get("users")
    .find({ username: username })
    .value();

  if (!user) {
    return res.status(404).send({
      token: null,
      message: "USER_NOT_FOUND"
    });
  }

  if (bcrypt.compareSync(password, user.password)) {
    const isValid = authenticator.check(otp, user.secret);
    if (isValid) {
      const token = jwt.sign({ id: user._id }, SECRET_APP, {
        expiresIn: 86400
      });
      return res.status(200).send({ token });
    } else {
      return res.status(403).send({
        token: null,
        message: "OTP_NOT_VALID"
      });
    }
  }
});

app.listen(port, () => console.log(`🔑 ${port}`));
