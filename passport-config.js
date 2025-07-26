const passport = require("passport");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const Reporter = require("./models/reporter");

passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: "/auth/google/callback"
},
async (accessToken, refreshToken, profile, done) => {
  try {
    let user = await Reporter.findOne({ googleId: profile.id });

    if (!user) {
      user = new Reporter({
        googleId: profile.id,
        fullname: profile.displayName,
        email: profile.emails[0].value
      });
      await user.save();
    }

    return done(null, user);
  } catch (err) {
    return done(err, null);
  }
}));

passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
  const user = await Reporter.findById(id);
  done(null, user);
});
