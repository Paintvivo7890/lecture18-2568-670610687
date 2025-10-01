import { Router, type Request, type Response } from "express";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";
dotenv.config();

import type { User, CustomRequest } from "../libs/types.js";
import { users, reset_users } from "../db/db.js";
import authenticateToken from "../middlewares/authenMiddleware.js";
import checkRoleAdmin from "../middlewares/checkRoleAdminMiddleware.js";

const router = Router();
const JWT_SECRET = process.env.JWT_SECRET || "forgot_secret";

router.get("/", authenticateToken, checkRoleAdmin, (_req: CustomRequest, res: Response) => {
  try {
    return res.status(200).json({
      success: true,
      message: "Users list",
      data: users,
    });
  } catch (err) {
    return res.status(500).json({
      success: false,
      message: "Something is wrong, please try again",
      error: err,
    });
  }
});

router.post("/login", (req: Request, res: Response) => {
  try {
    const { username, password } = req.body ?? {};
    const user = users.find((u: User) => u.username === username && u.password === password);

    if (!user) {
      return res.status(401).json({
        success: false,
        message: "Invalid username or password",
      });
    }

    const token = jwt.sign(
      {
        username: user.username,
        studentId: user.studentId,
        role: user.role,
      },
      JWT_SECRET,
      { expiresIn: "15m" }
    );
    user.tokens = user.tokens ? [...user.tokens, token] : [token];

    return res.status(200).json({
      success: true,
      message: "Login successful",
      token,
      role: user.role,
      studentId: user.studentId,
    });
  } catch (err) {
    return res.status(500).json({
      success: false,
      message: "Login error",
      error: err,
    });
  }
});

router.post("/logout", authenticateToken, (req: CustomRequest, res: Response) => {
  try {
    const token = req.token;
    const payload = req.user;

    if (!token || !payload?.username) {
      return res.status(401).json({ success: false, message: "Authorization required" });
    }

    const user = users.find((u: User) => u.username === payload.username);
    if (!user) {
      return res.status(401).json({ success: false, message: "Unauthorized user" });
    }

    if (!user.tokens || !user.tokens.includes(token)) {
      return res.status(401).json({ success: false, message: "Invalid token" });
    }

    user.tokens = user.tokens.filter((t) => t !== token);

    return res.status(200).json({
      success: true,
      message: "Logout successful",
    });
  } catch (err) {
    return res.status(500).json({
      success: false,
      message: "Logout error",
      error: err,
    });
  }
});

router.post("/reset", (_req: Request, res: Response) => {
  try {
    reset_users();
    return res.status(200).json({
      success: true,
      message: "User database has been reset",
    });
  } catch (err) {
    return res.status(500).json({
      success: false,
      message: "Something is wrong, please try again",
      error: err,
    });
  }
});

export default router;
