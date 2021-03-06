
import { Router } from 'express'
import authenticationController from '../controllers/authentication.contoller'

const router = Router()


router.get("/", (req, res) => {
    res.send("Hello World!");
});

router.get("/users", authenticationController.getAllUsers);
router.get("/users/all-users-email", authenticationController.getAllUsersEmail);
router.get("/users/:id", authenticationController.getUserById);
router.get("/users/email/:email", authenticationController.getUserByEmail);
router.post("/sign-up", authenticationController.signUp);
router.post("/sign-in", authenticationController.signIn);
router.post("/verify-user", authenticationController.verifyUser);
router.post("/forgot-password", authenticationController.forgotPassword);
router.post("/reset-password", authenticationController.resetPassword);
router.put("/update-password", authenticationController.updatePassword);
router.post("/send-verification-code", authenticationController.sendVerificationCode);
router.post("/update-user-role", authenticationController.updateUserRole);
router.delete("/users/:id", authenticationController.deleteUser);

export default router;