const { Schema, model } = require("mongoose");

const UserSchema = new Schema (
    {
        firstName: {
            type: String,
            required: true,
        },
        lastName: {
            type: String,
            required: true,
        },
        name: {
            type: String,
            required: true,
        },
        email: {
            type: String,
            required: true,
        },
        createdBy: {
            type: Schema.Types.ObjectId,
            ref: "User",
        },
        image: {
            type: String,
        },
        role: {
            type: String,
            default: "user",
            enum: ["user", "admin"],
        },
        password: {
            type: String,
            required: true,
        },
        verificationCode: {
            type: Number,
        },
        isVerified: {
            type: Boolean,
            default: false,
        },
        passwordResetCode: {
            type: String,
        }
    },
    { timestamps: true }
)

module.exports = model("User", UserSchema);