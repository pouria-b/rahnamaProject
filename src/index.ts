import express from "express";
import type { Request, Response, NextFunction } from "express";
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
import dotenv from "dotenv";
import { PrismaClient } from "@prisma/client";

dotenv.config();

const app = express();
app.use(express.json());

// Logger
app.use((req, _res, next) => {
  console.log(req.method, req.url);
  next();
});

// Prisma
const prisma = new PrismaClient();

// Types
interface AuthUser { id: number; username: string; email: string }
interface AuthRequest extends Request { user?: AuthUser }

// Helpers
const isNonEmptyString = (v: unknown): v is string =>
  typeof v === "string" && v.trim().length > 0;
const isEmail = (s: string) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(s);
const isPassword = (s: string) =>
  /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^\w\s]).{8,}$/.test(s);
const normEmail = (e: string) => e.trim().toLowerCase();

// JWT
const JWT_SECRET = process.env.JWT_SECRET || "dev_secret_change_me";
const JWT_EXPIRES = process.env.JWT_EXPIRES || "15m";

function signAccessToken(user: AuthUser) {
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
    (req as AuthRequest).user = { id: decoded.sub, username: decoded.username, email: decoded.email };
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
      message:
        "Password must be at least 8 chars, include uppercase, lowercase, number, and special character",
    });

  try {
    // وجود قبلی
    const [byU, byE] = await Promise.all([
      prisma.user.findUnique({ where: { username: username.trim() } }),
      prisma.user.findUnique({ where: { email: normEmail(email) } }),
    ]);
    if (byU) return res.status(409).json({ success: false, message: "username already exists" });
    if (byE) return res.status(409).json({ success: false, message: "email already exists" });

    const passwordHash = await bcrypt.hash(password, 10);
    await prisma.user.create({
      data: {
        username: username.trim(),
        email: normEmail(email),
        passwordHash,
      },
    });

    return res.status(201).json({ success: true, message: "User registered" });
  } catch (e: any) {
    // P2002 = unique constraint
    if (e?.code === "P2002") {
      const target = Array.isArray(e?.meta?.target) ? e.meta.target.join(",") : "";
      const msg =
        target.includes("username") ? "username already exists" :
        target.includes("email") ? "email already exists" : "duplicate key";
      return res.status(409).json({ success: false, message: msg });
    }
    console.error(e);
    return res.status(500).json({ success: false, message: "internal error" });
  }
});

// Login
app.post("/login", async (req: Request, res: Response) => {
  const { login, password } = req.body ?? {};
  if (!isNonEmptyString(login) || !isNonEmptyString(password))
    return res.status(400).json({ success: false, message: "login and password are required" });

  const isEmailLogin = login.includes("@");
  const user = isEmailLogin
    ? await prisma.user.findUnique({ where: { email: normEmail(login) } })
    : await prisma.user.findUnique({ where: { username: login.trim() } });

  if (!user) return res.status(401).json({ success: false, message: "Invalid credentials" });

  const ok = await bcrypt.compare(password, user.passwordHash);
  if (!ok) return res.status(401).json({ success: false, message: "Invalid credentials" });

  const accessToken = signAccessToken({ id: user.id, username: user.username, email: user.email });
  return res.json({ success: true, message: "Login successful", accessToken });
});

// Protected route
app.get("/me", auth, (req: Request, res: Response) => {
  const { user } = req as AuthRequest;
  return res.json({ success: true, user });
});

// start
const PORT = Number(process.env.PORT || 3000);
prisma.$connect()
  .then(() => {
    app.listen(PORT, () => console.log(`server is listening on port ${PORT}`));
  })
  .catch((err) => {
    console.error("DB connect failed:", err);
    process.exit(1);
  });

// graceful shutdown (اختیاری)
process.on("SIGINT", async () => {
  await prisma.$disconnect();
  process.exit(0);
});
