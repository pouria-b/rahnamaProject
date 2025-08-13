import express from "express";
import type { Request, Response, NextFunction } from "express";
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
import dotenv from "dotenv";

dotenv.config();

const app = express();
app.use(express.json());

// Logger
app.use((req, _res, next) => {
  console.log(req.method, req.url);
  next();
});

interface User {
  id: number;
  username: string;
  email: string;
  passwordHash: string;
}

const users: User[] = [];
let nextId = 1;

// Validation helpers
const isNonEmptyString = (v: unknown): v is string =>
  typeof v === "string" && v.trim().length > 0;
const isEmail = (s: string) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(s);
const isPassword = (s: string) =>
  /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^\w\s]).{8,}$/.test(s);

// JWT
const JWT_SECRET = process.env.JWT_SECRET || "dev_secret_change_me";
const JWT_EXPIRES = process.env.JWT_EXPIRES || "15m";

function signAccessToken(user: User) {
  return jwt.sign(
    { sub: user.id, username: user.username, email: user.email },
    JWT_SECRET,
    { expiresIn: JWT_EXPIRES }
  );
}

// Auth middleware
function auth(req: Request, res: Response, next: NextFunction) {
  const authHeader = req.headers.authorization || "";
  const token = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : null;
  if (!token) return res.status(401).json({ message: "Missing Authorization header" });

  try {
    const decoded = jwt.verify(token, JWT_SECRET) as any;
    (req as any).user = { id: decoded.sub, username: decoded.username, email: decoded.email };
    next();
  } catch {
    return res.status(401).json({ message: "Invalid or expired token" });
  }
}

// Register
app.post("/register", async (req: Request, res: Response) => {
  const { username, email, password } = req.body ?? {};

  if (!isNonEmptyString(username))
    return res.status(400).json({ success: false, message: "username is required" });
  if (!isNonEmptyString(email) || !isEmail(email))
    return res.status(400).json({ success: false, message: "valid email is required" });
  if (!isNonEmptyString(password) || !isPassword(password))
    return res.status(400).json({
      success: false,
      message: "Password must be at least 8 chars, include uppercase, lowercase, number, and special character"
    });

  if (users.some(u => u.username === username))
    return res.status(409).json({ success: false, message: "username already exists" });
  if (users.some(u => u.email === email))
    return res.status(409).json({ success: false, message: "email already exists" });

  const passwordHash = await bcrypt.hash(password, 10);
  const user: User = { id: nextId++, username, email, passwordHash };
  users.push(user);

  res.status(201).json({
    success: true,
    message: "User registered",
  });
});

// Login
app.post("/login", async (req: Request, res: Response) => {
  const { login, password } = req.body ?? {};
  if (!isNonEmptyString(login) || !isNonEmptyString(password))
    return res.status(400).json({ success: false, message: "login and password are required" });

  const user = users.find(u => u.email === login || u.username === login);
  if (!user) return res.status(401).json({ success: false, message: "Invalid credentials" });

  const ok = await bcrypt.compare(password, user.passwordHash);
  if (!ok) return res.status(401).json({ success: false, message: "Invalid credentials" });

  const accessToken = signAccessToken(user);
  res.json({ success: true, message: "Login successful", accessToken });
});

// Protected route
app.get("/me", auth, (req: Request, res: Response) => {
  const user = (req as any).user;
  res.json({ success: true, message: "Login successful" });
});

app.listen(3000, () => {
  console.log("server is listening on port 3000");
});
