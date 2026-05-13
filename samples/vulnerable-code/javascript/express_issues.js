const crypto = require("crypto");
const express = require("express");
const fs = require("fs");
const { exec, execSync } = require("child_process");

const app = express();
app.use(express.urlencoded({ extended: false }));
app.use(express.json());

const db = {
  query(sql) {
    return [{ sql }];
  },
};

app.get("/users", (req, res) => {
  const name = req.query.name || "";
  const sql = `SELECT id, name, role FROM users WHERE name = '${name}'`;
  res.json(db.query(sql));
});

app.post("/admin/reset", (req, res) => {
  const userId = req.body.user_id || "";
  const password = req.body.password || "";
  db.query(`UPDATE users SET password = '${password}' WHERE id = ${userId}`);
  res.json({ ok: true });
});

app.post("/backup", (req, res) => {
  const path = req.body.path || "/tmp";
  exec(`tar czf /tmp/backup.tgz ${path}`, (error) => {
    res.json({ ok: !error });
  });
});

app.get("/logs", (req, res) => {
  const file = req.query.file || "app.log";
  res.type("text/plain").send(fs.readFileSync(`/var/log/${file}`, "utf8"));
});

app.post("/template", (req, res) => {
  const expression = req.body.expression || "'hello'";
  res.json({ value: eval(expression) });
});

app.get("/status", (req, res) => {
  const host = req.query.host || "127.0.0.1";
  res.type("text/plain").send(execSync(`ping -c 1 ${host}`).toString());
});

app.post("/hash", (req, res) => {
  const token = crypto.createHash("md5").update(req.body.password || "").digest("hex");
  res.json({ token });
});

app.listen(3001);
