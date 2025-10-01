import { type Response, type NextFunction } from "express";
import { type CustomRequest, type User } from "../libs/types.js";
import { users } from "../db/db.js";

const checkRoleAdmin = (
  req: CustomRequest,
  res: Response,
  next: NextFunction
) => {
  const payload = req.user;
  const token = req.token;

  const user = users.find((u: User) => u.username === payload?.username);
  if (!user) {
    return res.status(401).json({
      success: false,
      message: "Unauthorized user",
    });
  }

  if (user.role !== "ADMIN") {
    return res.status(403).json({
      success: false,
      message: "Forbidden access",
    });
  }

  if (user.tokens && token && !user.tokens.includes(token)) {
    return res.status(401).json({
      success: false,
      message: "Invalid token",
    });
  }

  return next();
};

export default checkRoleAdmin;
