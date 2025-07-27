const mongoose = require("mongoose");

const hazardSchema = new mongoose.Schema({
  title: { type: String, required: true },
  image: { type: String, required: true }, // Image filename
  description: { type: String, required: true },
  location: { type: String, required: true },
  mapLink: {
    type: String,
    required: true,
    validate: {
      validator: function (v) {
        return /^https:\/\/www\.google\.com\/maps/.test(v);
      },
      message: "Invalid Google Maps link."
    }
  },
  reporter: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Reporter',
    required: true
  },
  catagory: String,
  createdAt: { type: Date, default: Date.now },

  // Community validation
  flag: {
    trueVotes: { type: Number, default: 0 },
    falseVotes: { type: Number, default: 0 },
    voters: [
      {
        user: { type: mongoose.Schema.Types.ObjectId, ref: "Reporter" },
        vote: { type: String, enum: ["true", "false"] }
      }
    ]
  },

  // New comment section
 comments: [
  {
    text: { type: String, required: true },
    commenter: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Reporter"
    },
    createdAt: {
      type: Date,
      default: Date.now
    }
  }
],



coordinates: {
  type: { type: String, enum: ['Point'], default: 'Point' },
  coordinates: { type: [Number], default: [0, 0] } // [lng, lat]
},




status: {
  type: String,
  enum: ['Reported', 'Acknowledged', 'In Progress', 'Resolved', 'Rejected'],
  default: 'Reported'
},

 





});
hazardSchema.index({ coordinates: "2dsphere" });
module.exports = mongoose.model("Hazard", hazardSchema);

