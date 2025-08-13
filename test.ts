import express from "express";
import type { Request, Response, NextFunction } from "express";

const app = express();
app.use(express.json());

// logger
app.use((req: Request, _res: Response, next: NextFunction) => {
  console.log(req.method, req.url);
  next();
});

interface User {
  id: number;
  username: string;
  email: string;
  password: string; // hash ??
}

const users: User[] = [];
let nextId = 0;

//  ولیدیشن
const isNonEmptyString = (v: unknown): v is string =>
  typeof v === "string" && v.trim().length > 0;

const isEmail = (s: string) =>
  /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(s);

const isPassword = (s:string) =>
  /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^\w\s]).{8,}$/.test(s);

// POST /register  { username, email, password }
app.post("/register", (req: Request, res: Response) => {
  const { username, email, password } = req.body ;

  if (!isNonEmptyString(username))
    return res.status(400).json({ message: "username is required" });

  if (!isNonEmptyString(email) || !isEmail(email))
    return res.status(400).json({ message: "valid email is required" });

  if (!isNonEmptyString(password) || !isPassword(password))
    return res.status(400).json({ message: "Password must be at least 8 chars, include uppercase, lowercase, number, and special character" });

  // عدم تکرار
  if (users.some(u => u.username === username))
    return res.status(409).json({ message: "username already exists" });

  if (users.some(u => u.email === email))
    return res.status(409).json({ message: "email already exists" });

  // ساخت کاربر 
  const user: User = { id: nextId++, username, email, password };
  users.push(user);
//nextId++;

  // برنگردوندن پسورد
  res.status(201).json({
    message: "User registered",
    user: { id: user.id, username: user.username, email: user.email },
  });
});

//لاگین { email,username, password }
app.post("/login", (req: Request, res: Response) => {
  const { login, password } = req.body ?? {};
  

  if (!isNonEmptyString(login) || !isNonEmptyString(password))
    return res.status(400).json({ message: "login and password are required" });

  // پیدا کردن کاربر
  const user = users.find(
    u => (u.email === login || u.username === login) && u.password === password
  );

  if (user?.password!==password) {
    return res.status(401).json({ message: "Invalid credentials" });
  }

  res.json({
    message: "Login successful",
    user: { id: user.id, username: user.username, email: user.email },
  });
});

app.listen(3000, () => {
  console.log("server is listening on port 3000");
});





