import bcrypt from "bcryptjs";
import User from "../models/user";
// const User = require("../models/user");
import jwt from "jsonwebtoken";
import env from "../config/environment/index";
import validateEmail from "../utils/validateEmail";
import validatePassword from "../utils/validatePassword";
import emailSender from "../utils/emailSender";

const authenticationService = {
  async signUp(email, password, firstName, lastName) {
    const isUserTaken = await validateEmail(email);
    
    if (isUserTaken) {
      return false;
    }

    const verificationCode = Math.floor(Math.random() * 100000);

    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = new User({
      firstName,
      lastName,
      name: `${firstName} ${lastName}`,
      email,
      role: "user",
      password: hashedPassword,
      verificationCode,
    });

    await newUser.save();

    let token = jwt.sign(
      {
        userId: newUser._id,
        role: newUser.role,
        email: newUser.email,
        firstName: newUser.firstName,
        lastName: newUser.lastName,
        name: newUser.name,
      },
      process.env.JWT_SECRET,
      { expiresIn: "1h" }
    );

    const html = `
    <h1>Welcome to Blesify Event Application</h1>

    <p>
      Copy the code below to complete your registration.
    </p>
    <p>
      <b>${verificationCode}</b>
    </p>
      <br>
    <p>
      Or Please click on the link below to verify your email address and complete your registration.
    </p>
    <a href="${process.env.CLIENT_URL}/verify-email?token=${token}">Verify Email</a>
    `;

    const emailSent = await emailSender(email, "Verify User Account - Blesify", html);

    if(emailSent) {
      return { token, user: newUser };
    } else {
      return false;
    }
  },

  async signIn(email, password) {
    const isPasswordValid = await validatePassword(email, password);

    if (!isPasswordValid) {
      return false;
    }

    let user = await User.findOne({ email });

    const token = jwt.sign(
      {
        userId: user._id,
        role: user.role,
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
        name: user.name,
      },
      env.JWT_SECRET,
      { expiresIn: "1h" }
    );
    return { token, user };
  },

  async getUserByEmail(email) {
    const user = await User.findOne({ email });
    return user;
  },

  async getUserById(id) {
    const user = await User.findById(id);
    return user;
  },

  async getAllUsers() {
    const users = await User.find({});
    return users;
  },

  async verifyUser(email, verificationCode) {
    const user = await User.findOne({ email });

    if (user.verificationCode === parseInt(verificationCode)) {
      user.isVerified = true;
      user.verificationCode = null;
      await user.save();

    let token = jwt.sign(
      {
        userId: user._id,
        role: user.role,
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
        name: user.name,
      },
      process.env.JWT_SECRET,
      { expiresIn: "1h" }
    );

    return { token, user };
    }

    return false;
  },

  async sendVerificationCode(email) {
    const user = await User.findOne({ email });

    if (!user) {
      return false;
    }

    if (user.isVerified) {
      return false;
    }

    const verificationCode = Math.floor(Math.random() * 100000);

    user.verificationCode = verificationCode;

    let token = jwt.sign(
      {
        userId: user._id,
        role: user.role,
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
        name: user.name,
      },
      process.env.JWT_SECRET,
      { expiresIn: "1h" }
    );

    const html = `
    <h1>Blesify Event Application</h1>
    <p>Hi ${user.firstName},</p>

    <p>
      You requested for a new verification code.
    </p>
    <br>

    <p>
      Copy the code below to complete your registration.
    </p>
    <p> 
      <b>${verificationCode}</b>
    </p>
      <br>

    <p> 
    Kindly ignore this email if you did not request for a new verification code.
    </p>
    <p>Thanks</p>
    <br><br>
    <p>The ${env.CLIENT_NAME} Team</p>
    `;

    const emailSent = await emailSender(email, "Verify User Account - Blesify", html);

    if(emailSent) {
    await user.save();
      return { token, user: newUser };
    } else {
      return false;
    }
  },

  async forgotPassword(email) {
    try {
      const user = await User.findOne({ email });

      if (!user) {
        return false;
      }

      const verificationCode = Math.floor(Math.random() * 100000);

      user.verificationCode = verificationCode;

      let token = jwt.sign(
        {
          userId: user._id,
          email: user.email,
          firstName: user.firstName,
          lastName: user.lastName,
          name: user.name,
          verificationCode: user.verificationCode,
        },
        env.JWT_SECRET,
        { expiresIn: "1h" }
      );

      let html = `
      <h1>Reset Password</h1>
      <p>Hi ${user.firstName},</p>
      <br><br>
      <p>You recently requested to reset your password for your account.</p>
      <br>
      <p>Please click the link below to reset your password:</p>
      <a href="${env.CLIENT_URL}/reset-password/${token}/${verificationCode}">Reset Password</a>
      <br><br>
      <p>If you did not request a password reset, please ignore this email or reply to let us know.</p>
      <br>
      <p>Thanks</p>
      <br><br>
      <p>The ${env.CLIENT_NAME} Team</p>
      `;

      const emailSent = await emailSender(user.email, "Reset Password", html);

      if(emailSent) {
        await user.save();
        return { user, token };
      } else {
        return false;
      }

    } catch (error) {
      return false;
    }
  },

  async resetPassword(token, verificationCode, password) {
    try {

      const decoded = jwt.verify(token, env.JWT_SECRET);

      const user = await User.findById(decoded.userId);

      if (!user) {
        return false;
      }

      const hashedPassword = await bcrypt.hash(password, 10);

      user.password = hashedPassword;
      user.verificationCode = "";

      await user.save();

      return user;
    } catch (error) {
      return false;
    }
  },

  async updatePassword(userId, oldPassword, newPassword) {
    const user = await User.findById(userId);

    if (!user) {
      return false;
    }

    const isPasswordValid = await bcrypt.compare(oldPassword, user.password);

    if (!isPasswordValid) {
      return false;
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);

    user.password = hashedPassword;

    await user.save();

    return user;
  },

  async updateUserRole(userId, role) {
    const user = await User.findById(userId);

    if (!user) {
      return false;
    }

    user.role = role;

    await user.save();

    return user;
  },

  async deleteUser(userId) {
    const user = await User.findByIdAndDelete(userId);
    return user;
  },

  async getAllUsersEmail () {
    const users = await User.find({})
    const usersEmail = users.map((item) => {
      return item.email
    })

    return usersEmail;
  }
};

export default authenticationService;
