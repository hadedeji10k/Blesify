import successResponseHandler from "../helpers/successResponseHandler";
import errorResponseHandler from "../helpers/errorResponseHandler";
import authService from "../services/authenticationService";

const authenticationController = {
  signUp: async (req, res) => {
    try {
      const { email, password, firstName, lastName } = req.body;

      const user = await authService.signUp(
        email,
        password,
        firstName,
        lastName
      );

      if (user) {
        return successResponseHandler(
          res,
          201,
          user,
          "User created successfully",
          true
        );
      } else {
        return errorResponseHandler(res, 400, "User already exists", false);
      }
    } catch (error) {
      return errorResponseHandler(res, 500, "Request Not Processed", false);
    }
  },

  signIn: async (req, res, next) => {
    const { email, password } = req.body;
    try {
      const user = await authService.signIn(email, password);
      if (user) {
        return successResponseHandler(
          res,
          200,
          user,
          "User logged in successfully",
          true
        );
      } else {
        return errorResponseHandler(res, 400, "Invalid credentials", false);
      }
    } catch (error) {
      return errorResponseHandler(res, 500, "Request Not Processed", false);
    }
  },

  getAllUsers: async (req, res) => {
    try {
      const users = await authService.getAllUsers();

      if (users) {
        return successResponseHandler(
          res,
          201,
          users,
          "Users fetched successfully",
          true
        );
      } else {
        return errorResponseHandler(res, 400, "Users not fetched", false);
      }
    } catch (error) {
      return errorResponseHandler(res, 500, "Request Not Processed", false);
    }
  },

  getUserById: async (req, res) => {
    const userId = req.params.id;
    try {
      const user = await authService.getUserById(userId);

      if (user) {
        return successResponseHandler(
          res,
          201,
          user,
          "User fetched successfully",
          true
        );
      } else {
        return errorResponseHandler(res, 400, "User not fetched", false);
      }
    } catch (error) {
      return errorResponseHandler(res, 500, "Request Not Processed", false);
    }
  },

  getUserByEmail: async (req, res) => {
    const email = req.body.email || req.params.email;
    try {
      const user = await authService.getUserByEmail(email);

      if (user) {
        return successResponseHandler(
          res,
          201,
          user,
          "User fetched successfully",
          true
        );
      } else {
        return errorResponseHandler(res, 400, "User not fetched", false);
      }
    } catch (error) {
      return errorResponseHandler(res, 500, "Request Not Processed", false);
    }
  },

  verifyUser: async (req, res, next) => {
    const { email, verificationCode } = req.body;

    try {
      const user = await authService.verifyUser(email, verificationCode);

      if (user) {
        return successResponseHandler(
          res,
          200,
          user,
          "User verified successfully",
          true
        );
      } else {
        return errorResponseHandler(
          res,
          400,
          "User not found or not verified",
          false
        );
      }
    } catch (error) {
      return errorResponseHandler(res, 500, "Request Not Processed", false);
    }
  },

  sendVerificationCode: async (req, res, next) => {
    const { email } = req.body;

    try {
      const user = await authService.sendVerificationCode(email);

      if (user) {
        return successResponseHandler(
          res,
          200,
          user,
          "Verification code sent successfully",
          true
        );
      } else {
        return errorResponseHandler(res, 400, "User not found or User already verified", false);
      }
    } catch (error) {
      return errorResponseHandler(res, 500, "Request Not Processed", false);
    }
  },

  forgotPassword: async (req, res) => {
    const { email } = req.body;
    try {
      const user = await authService.forgotPassword(email);
      if (user) {
        return successResponseHandler(
          res,
          200,
          user,
          "Password reset link sent to your email",
          true
        );
      } else {
        return errorResponseHandler(res, 400, "Invalid email", false);
      }
    } catch (error) {
      return errorResponseHandler(res, 500, "Request Not Processed", false);
    }
  },

  resetPassword: async (req, res) => {
    const { password, verificationCode, token } = req.body;
    try {
      const user = await authService.resetPassword(token, verificationCode, password);

      if (user) {
        return successResponseHandler(
          res,
          200,
          user,
          "Password reset successfully",
          true
        );
      } else {
        return errorResponseHandler(res, 400, "Invalid token", false);
      }
    } catch (error) {
      return errorResponseHandler(res, 500, "Request Not Processed", false);
    }
  },

  updatePassword: async (req, res) => {
    const { userId, oldPassword, newPassword } = req.body;

    try {
      const user = await authService.updatePassword(
        userId,
        oldPassword,
        newPassword
      );

      if (user) {
        return successResponseHandler(
          res,
          200,
          user,
          "Password updated successfully",
          true
        );
      } else {
        return errorResponseHandler(
          res,
          400,
          "User not found or Old password not correct or password not updated successfully",
          false
        );
      }
    } catch (error) {
      return errorResponseHandler(res, 500, "Request Not Processed", false);
    }
  },

  updateUserRole: async (req, res) => {
    const { userId, role } = req.body;

    try {
      const user = await authService.updateUserRole(userId, role);

      if (user) {
        return successResponseHandler(
          res,
          200,
          user,
          "User role updated successfully",
          true
        );
      } else {
        return errorResponseHandler(
          res,
          400,
          "User not found or role not updated successfully",
          false
        );
      }
    } catch (error) {
      return errorResponseHandler(res, 500, "Request Not Processed", false);
    }
  },

  deleteUser: async (req, res) => {
    const userId = req.params.id;

    try {
      const user = await authService.deleteUser(userId);

      if (user) {
        return successResponseHandler(
          res,
          200,
          user,
          "User deleted successfully",
          true
        );
      } else {
        return errorResponseHandler(res, 400, "User not found", false);
      }
    } catch (error) {
      return errorResponseHandler(res, 500, "Request Not Processed", false);
    }
  },

  getAllUsersEmail: async (req, res) => {
     try {
      const usersEmail = await authService.getAllUsersEmail();

      if (usersEmail) {
        return successResponseHandler(
          res,
          200,
          usersEmail,
          "Users Emails fetched successfully",
          true
        );
      } else {
        return errorResponseHandler(res, 400, "Users Emails not fetched successfully", false);
      }
    } catch (error) {
      return errorResponseHandler(res, 500, "Request Not Processed", false);
    }
  }
};

export default authenticationController;
