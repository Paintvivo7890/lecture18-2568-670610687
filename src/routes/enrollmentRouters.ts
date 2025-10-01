import { Router, type Request, type Response } from "express";
import type { CustomRequest, User, Enrollment, Student } from "../libs/types.js";
import { users, students, enrollments, reset_enrollments } from "../db/db.js";
import authenticateToken from "../middlewares/authenMiddleware.js";
import checkRoleAdmin from "../middlewares/checkRoleAdminMiddleware.js";
import checkRoleStudent from "../middlewares/checkRoleStudentMiddleware.js";
import { zEnrollmentBody, zStudentId } from "../libs/zodValidators.js";

const router = Router();

router.get("/", authenticateToken, checkRoleAdmin, (_req: Request, res: Response) => {
  const data = students.map((s) => {
    const courseIds = enrollments
      .filter((e) => e.studentId === s.studentId)
      .map((e) => e.courseId);
    return { studentId: s.studentId, courses: courseIds };
  });
  return res.status(200).json({
    success: true,
    message: "Enrollments Information",
    data,
  });
});

router.post("/reset", authenticateToken, checkRoleAdmin, (_req: Request, res: Response) => {
  reset_enrollments();
  return res.status(200).json({
    success: true,
    message: "enrollments database has been reset",
  });
});

router.get("/:studentId", authenticateToken, (req: CustomRequest, res: Response) => {
  try {
    const studentId = req.params.studentId;
    const r = zStudentId.safeParse(studentId);
    if (!r.success) {
      return res.status(400).json({ message: "Validation failed", errors: r.error.issues[0]?.message });
    }

    const studentIndex = students.findIndex((s: Student) => s.studentId === studentId);
    if (studentIndex === -1) {
      return res.status(404).json({ success: false, message: "StudentId does not exists" });
    }

    const payload = req.user;
    const user = users.find((u: User) => u.username === payload?.username);
    if (!user) return res.status(401).json({ success: false, message: "Unauthorized user" });
    if (user.role === "STUDENT" && user.studentId !== studentId) {
      return res.status(403).json({ success: false, message: "Forbidden access" });
    }

    const courseIds = enrollments
      .filter((e) => e.studentId === studentId)
      .map((e) => e.courseId);

    return res.status(200).json({
      success: true,
      message: "Enrollment information",
      data: { studentId, courses: courseIds },
    });
  } catch (err) {
    return res.status(500).json({ success: false, message: "Something is wrong, please try again", error: err });
  }
});

router.post("/:studentId", authenticateToken, checkRoleStudent, (req: CustomRequest, res: Response) => {
  try {
    const studentId = req.params.studentId;
    const body = req.body as Enrollment;

    const r1 = zStudentId.safeParse(studentId);
    const r2 = zEnrollmentBody.safeParse(body);
    if (!r1.success) return res.status(400).json({ message: "Validation failed", errors: r1.error.issues[0]?.message });
    if (!r2.success) return res.status(400).json({ message: "Validation failed", errors: r2.error.issues[0]?.message });

    const studentIndex = students.findIndex((s) => s.studentId === studentId);
    if (studentIndex === -1) return res.status(404).json({ success: false, message: "StudentId does not exists" });

    const payload = req.user;
    const user = users.find((u: User) => u.username === payload?.username);

    if (studentId != body.studentId || user?.studentId != studentId || user?.studentId != body.studentId) {
      return res.status(403).json({ success: false, message: "Forbidden access" });
    }

    const dup = enrollments.find((e) => e.studentId === body.studentId && e.courseId === body.courseId);
    if (dup) return res.status(409).json({ success: false, message: "Enrollment is already exists" });

    enrollments.push(body);

    const courseIds = enrollments
      .filter((e) => e.studentId === studentId)
      .map((e) => e.courseId);

    return res.status(201).json({
      success: true,
      message: `Student ${studentId} && Course ${body.courseId} has been added successfully`,
      data: { studentId, courses: courseIds },
    });
  } catch (err) {
    return res.status(500).json({ success: false, message: "Something is wrong, please try again", error: err });
  }
});

router.delete("/:studentId", authenticateToken, checkRoleStudent, (req: CustomRequest, res: Response) => {
  try {
    const studentId = req.params.studentId;
    const body = req.body as Enrollment;

    const r1 = zStudentId.safeParse(studentId);
    const r2 = zEnrollmentBody.safeParse(body);
    if (!r1.success) return res.status(400).json({ message: "Validation failed", errors: r1.error.issues[0]?.message });
    if (!r2.success) return res.status(400).json({ message: "Validation failed", errors: r2.error.issues[0]?.message });

    const payload = req.user;
    const user = users.find((u: User) => u.username === payload?.username);
    if (studentId != body.studentId || user?.studentId != studentId || user?.studentId != body.studentId) {
      return res.status(403).json({ success: false, message: "Forbidden access" });
    }

    const studentIndex = students.findIndex((s) => s.studentId === studentId);
    if (studentIndex === -1) return res.status(404).json({ success: false, message: "StudentId does not exists" });

    const idx = enrollments.findIndex((e) => e.studentId === studentId && e.courseId === body.courseId);
    if (idx === -1) return res.status(404).json({ success: false, message: "Enrollment does not exists" });

    enrollments.splice(idx, 1);

    const courseIds = enrollments
      .filter((e) => e.studentId === studentId)
      .map((e) => e.courseId);

    return res.status(200).json({
      success: true,
      message: `Student ${studentId} && Course ${body.courseId} has been deleted successfully`,
      data: { studentId, courses: courseIds },
    });
  } catch (err) {
    return res.status(500).json({ success: false, message: "Something is wrong, please try again", error: err });
  }
});

export default router;
