import mongoose from "mongoose";
import bcrypt from "bcrypt";

const userSchema = new mongoose.Schema(
  {
    // Common fields for both roles
    firstName: {
      type: String,
      required: [true, "FirstName is required"],
      trim: true,
    },
    lastName: {
      type: String,
      required: [true, "LastName is required"],
      trim: true,
    },
    email: {
      type: String,
      required: [true, "Email is required"],
      unique: true,
      lowercase: true,
      trim: true,
    },
    password: {
      type: String,
      required: [true, "Password is required"],
      minlength: [6, "Password must be at least 6 characters"],
    },
    phoneNumber: {
      type: String,
      trim: true,
    },
    role: {
      type: String,
      enum: ["contributor", "participant"],
      required: [true, "Role is required"],
    },
    isVerified: {
      type: Boolean,
      default: false,
    },

    // Additional fields specific to contributors
    contributorProfile: {
      expertise: { type: String },
      bio: { type: String },
      countryOfResidence: { type: String },
      organizationName: { type: String },
      jobTitle: { type: String },
      organizationType: { type: String },
    },

    // Additional fields specific to participants
    participantProfile: {
      interests: [{ type: String }],
      about: { 
        type: String,
        required: function() { return this.role === "participant"; }
      },
      goals: { 
        type: String,
        required: function() { return this.role === "participant"; }
      },
      countryOfResidence: { 
        type: String,
        required: function() { return this.role === "participant"; }
      },
      countryOfBirth: { 
        type: String,
        required: function() { return this.role === "participant"; }
      },
      placeOfBirth: { 
        type: String,
        required: function() { return this.role === "participant"; }
      },
      ethnicGroup: { 
        type: String,
        required: function() { return this.role === "participant"; }
      },
      language: { 
        type: String,
        required: function() { return this.role === "participant"; }
      },
      languageFluent: {
        type: [{ type: String }],
        required: function() { return this.role === "participant"; }
      },
      regionalDialect: { 
        type: String,
        required: function() { return this.role === "participant"; }
      },
      educationLevel: { 
        type: String,
        required: function() { return this.role === "participant"; }
      },
      educationCurrentStatus: { 
        type: String,
        required: function() { return this.role === "participant"; }
      },
      educationFieldOfStudy: { 
        type: String,
        required: function() { return this.role === "participant"; }
      },
      educationYearCompleted: { 
        type: String,
        required: function() { return this.role === "participant"; }
      },
      employmentStatus: { 
        type: String,
        required: function() { return this.role === "participant"; }
      },
      employmentYearsExperience: { 
        type: Number,
        required: function() { return this.role === "participant"; }
      },
      employmentSector: { 
        type: String,
        required: function() { return this.role === "participant"; }
      },
      employmentIndustry: { 
        type: String,
        required: function() { return this.role === "participant"; }
      },
      employmentJobTitle: { 
        type: String,
        required: function() { return this.role === "participant"; }
      },
      linkedInProfile: { type: String }, // Optional
      availabilityToParticipate: { 
        type: String,
        required: function() { return this.role === "participant"; }
      },
      participateHoursPerWeek: { 
        type: Number,
        required: function() { return this.role === "participant"; }
      },
      currency: { 
        type: String,
        required: function() { return this.role === "participant"; }
      },
    },
  },
  {
    timestamps: true,
  }
);

// Hash password before saving
// FIXED: Removed next() call - not needed with async functions in Mongoose
userSchema.pre("save", async function () {
  if (!this.isModified("password")) return;
  this.password = await bcrypt.hash(this.password, 10);
});

// Method to compare passwords
userSchema.methods.comparePassword = async function (candidatePassword) {
  return await bcrypt.compare(candidatePassword, this.password);
};

const User = mongoose.model("User", userSchema);

export default User;