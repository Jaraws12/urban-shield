const mongoose = require('mongoose');

const reporterSchema = new mongoose.Schema({
  fullname: String,
  email: String,
  phone: String,
  password: String,
  googleId: String,

  // Reference to reported hazards
  reportedHazards: [
    {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'Hazard'
    }
  ],
  location: {
    type: { type: String, enum: ['Point'], default: 'Point' },
    coordinates: { type: [Number], default: [0, 0] } // [longitude, latitude]
  },
  role: {
    type: String,
    enum: ['user', 'admin'],
    default: 'user',
  },
});

// ✅ Create 2dsphere index for location field
reporterSchema.index({ location: '2dsphere' });

module.exports = mongoose.model('Reporter', reporterSchema);
