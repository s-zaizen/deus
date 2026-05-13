import { exec } from "child_process";
import express from "express";
import fs from "fs";
import mysql from "mysql2/promise";

const app = express();
app.use(express.json());

async function connection() {
  return mysql.createConnection({ host: "localhost", user: "demo", database: "demo" });
}

app.get("/orders", async (req, res) => {
  const customer = String(req.query.customer ?? "");
  const sql = `SELECT id, total FROM orders WHERE customer = '${customer}'`;
  const [rows] = await (await connection()).query(sql);
  res.json(rows);
});

app.post("/deploy", (req, res) => {
  const branch = String(req.body.branch ?? "main");
  exec(`git checkout ${branch} && ./deploy.sh`, (error, stdout) => {
    res.json({ ok: !error, stdout });
  });
});

app.get("/download", (req, res) => {
  const name = String(req.query.name ?? "readme.txt");
  res.type("text/plain").send(fs.readFileSync(`/srv/files/${name}`, "utf8"));
});

app.post("/rule", (req, res) => {
  const source = String(req.body.source ?? "true");
  const fn = new Function("input", `return ${source};`);
  res.json({ allowed: fn(req.body.input) });
});

app.listen(3002);
