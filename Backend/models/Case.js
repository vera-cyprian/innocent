const mongoose = require("mongoose");

const caseSchema = new mongoose.Schema(
  {
    primaryImage: { type: String, required: true },
    images: [{ type: String }],
    title: { type: String, required: true },
    category: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Category",
      required: true,
    },
    content: { type: String, required: true },
    description: { type: String, required: true },
    postedBy: { type: String, default: "Admin" },
    videos: [{ type: String }],
  },
  { timestamps: true }
);

const Case = mongoose.model("Case", caseSchema);

module.exports = Case;
