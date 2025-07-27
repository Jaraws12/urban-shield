const express=require("express");
const app= express();
const path = require("path");
const mongoose = require("mongoose");
const session = require("express-session");
const flash = require("connect-flash");
const bcrypt = require("bcrypt");
const Reporter=require("./models/reporter")
const Hazard=require("./models/hazard");
const { generateToken, verifyToken } = require("./middleware/isloggedin.js");
const cookieParser = require("cookie-parser");
const nodemailer = require("nodemailer");
const multer = require("multer");
const axios = require("axios");
const crypto = require("crypto");
const sharp = require("sharp");
const fs = require("fs");
app.set("view engine", "ejs");
app.use(cookieParser());
app.use(express.static(path.join(__dirname, "public")));
app.use(express.urlencoded({ extended: true }));
app.use(express.json()); 
app.use(express.static("uploads"));
app.use(
    session({
        secret: "your_secret_key",
        resave: false,
        saveUninitialized: false
    })
);
app.use(flash());



app.use((req, res, next) => {
  res.locals.success = req.flash("success");
  res.locals.error = req.flash("error");
  res.locals.welcome = req.flash("welcome");
  next();
});




app.use((req, res, next) => {
  console.log("Session contents:", req.session);
  next();
});


///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
import fs from 'fs';
import path from 'path';

const uploadsDir = path.join(__dirname, 'public/uploads');
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir, { recursive: true });
}




//////////////////////////////////////////////////////////////////////////////////////////////



// Set up multer storage
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, "public/uploads/");
  },
  filename: function (req, file, cb) {
    const uniqueSuffix = Date.now() + "-" + Math.round(Math.random() * 1E9);
    cb(null, uniqueSuffix + path.extname(file.originalname));
  }
});

const upload = multer({ storage: storage });

//mongodb connection

mongoose.connect(process.env.MONGO_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true
})
.then(() => console.log("Connected to MongoDB"))
.catch(err => console.log("MongoDB Connection Error:", err));

app.get("/",(req,res)=>{
     res.render("home");

});

app.get("/login", (req, res) => {
    const formData = req.flash("formData")[0] || {};
    const error = req.flash("error")[0];
    console.log("Flash error received at /login:", error);

    res.render("login", {
        formData,
        error
    });
});



//post register

app.post("/register", async (req, res) => {
    try {
        const { fullname, email, phone, password } = req.body;

        // 🔍 Check if user already exists
        const existingUser = await Reporter.findOne({
            $or: [{ email }, { phone }]
        });
       // console.log(existingUser);

       if (existingUser) {
    req.flash("error", "Email or phone number already registered!");
    req.flash("formData", { fullname, email, phone });
    console.log("Set flash error:", "Email or phone number already registered!");
    return res.redirect("/login");
}


        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = new Reporter({
            fullname,
            email,
            phone,
            password: hashedPassword
        });

        console.log(newUser);


        await newUser.save();
         req.session.reporterId = newUser._id;
         console.log(newUser._id);
         console.log(req.session.reporterId);



          await Reporter.findOneAndUpdate({ email: 'swarajnitrkl@gmail.com' }, { role: 'admin' });


        const token = generateToken(newUser);
        res.cookie("token", token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === "production",
            maxAge: 2 * 60 * 60 * 1000,
        });

        // ✅ Send welcome email
        const transporter = nodemailer.createTransport({
            service: "gmail",
            auth: {
                user: "swarajnitrkl@gmail.com",
                pass: "jtik znfb krqf qlyj"
            }
        });

        const mailOptions = {
            from: "swarajnitrkl@gmail.com",
            to: email,
            subject: "Welcome to Our Platform!",
            text: `Hi ${fullname},\n\nThanks for registering with us! We're excited to have you on board.`
        };

        transporter.sendMail(mailOptions, (error, info) => {
            if (error) {
                console.error("Email send error:", error);
            } else {
                console.log("Email sent:", info.response);
            }
        });

        req.flash("success", "Registration successful! Welcome.");
        res.render("post_home"); // 🔁 update this to your actual post-login route

    } catch (error) {
        console.error("Registration error:", error);
        req.flash("error", "Something went wrong. Please try again.");
        res.redirect("/login");
    }
});



//post login
app.post("/login", async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await Reporter.findOne({ email });

        if (!user) {
            req.flash("error", "User not found");
            return res.status(401).json({ message: "User not found" });
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            req.flash("error", "Invalid credentials");
            return res.status(401).json({ message: "Invalid credentials" });
        }
        req.session.reporterId = user._id;

        // ✅ Generate JWT Token
        const token = generateToken(user);

        // ✅ Set the token as a cookie (HTTP-only for security)
        res.cookie("token", token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === "production", // ✅ Secure in production
            maxAge: 2 * 60 * 60 * 1000, // ✅ 2 hours expiry
        });

        req.flash("welcome", `Welcome back, ${user.username}!`);
        res.render("post_home"); // ✅ Redirect without `{ token }`
    } catch (error) {
        res.status(500).json({ error: "Error logging in" });
    }
}); 


//logout

app.get("/logout", (req, res) => {
    res.clearCookie("token"); // ✅ Remove JWT Cookie
    req.session.destroy((err) => { // ✅ Destroy session (if any)
        if (err) {
            console.error("Session destruction error:", err);
            return res.redirect("/");
        }
        res.redirect("/"); // ✅ Redirect to login page after logout
    });
});


//post home
app.get("/home",verifyToken,  (req, res) => {
    const user = req.user;
    if(user){
        res.render("post_home", { user: req.user });
    }
    else{
        res.render("home");
    }
});

//post about
app.get("/about",verifyToken,  (req, res) => {
    const user = req.user;
    if(user){
        res.render("post_about", { user: req.user });
    }
    else{
        res.render("home");
    }
});

//report

app.get("/report", verifyToken, (req, res) => {
  const user = req.user;
  const error = req.query.error;

  if (user) {
    res.render("report", { user, error });  // ✅ pass error to EJS
  } else {
    res.render("home");
  }
});


//how to use
app.get("/htu",verifyToken,  (req, res) => {
    const user = req.user;
    if(user){
        res.render("htu", { user: req.user });
    }
    else{
        res.render("home");
    }
});



// All reports


app.get("/allreports", verifyToken, async (req, res) => {
  try {
    const user = req.user;

    if (!user) {
      return res.render("home");
    }

    const reports = await Hazard.find()
  .sort({ createdAt: -1 })
  .populate("reporter", "fullname"); // Only populate the name field of the reporter
 // Optional: sort by date
  //  console.log(reports);



    res.render("allreports", { user, reports });
  } catch (error) {
    console.error("Error fetching reports:", error);
    res.status(500).send("Server error while fetching reports.");
  }
});



// POST /report


// app.post("/report", upload.single("image"), async (req, res) => {
//   try {
//     const { title, description, location, mapLink } = req.body;
//     const image = req.file.filename;
    
//     // Get reporter ID from session (or however you're storing it)
//     const reporterId = req.user._id;
  

//     // if (!reporterId) {
//     //   return res.status(401).send("Reporter not authenticated.");
//     // }

//     const hazard = new Hazard({
//       title,
//       image,
//       description,
//       location,
//       mapLink,
//       reporter: reporterId, // Link to the reporter
//     });

//     await hazard.save();

//     res.status(200).send("Hazard reported successfully!");
//     // Optionally: res.redirect("/thank-you");
//   } catch (err) {
//     console.error(err);
//     res.status(500).send("An error occurred while saving the report.");
//   }
// });



//track
app.get("/track", verifyToken, async (req, res) => {
  try {
    const user = req.user;

    if (!user) {
      return res.render("home");
    }

    // Fetch the reporter with populated reportedHazards
    const reporter = await Reporter.findById(user._id).populate("reportedHazards");

    if (!reporter) {
      return res.status(404).send("User not found");
    }

    res.render("track", { hazards: reporter.reportedHazards });
  } catch (error) {
    console.error("Error fetching reports:", error);
    res.status(500).send("Server error while fetching reports.");
  }
});



///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////



// app.post("/report", verifyToken, upload.single("image"), async (req, res) => {
//   try {
//     const { title, description, location, mapLink, catagory } = req.body; // 🟢 Added catagory
//     const image = req.file.filename;
//     const reporterId = req.user._id;

//     const hazard = new Hazard({
//       title,
//       image,
//       description,
//       location,
//       mapLink,
//       catagory, // 🟢 Add catagory to the hazard object
//       reporter: reporterId,
//     });

//     // Save the new hazard
//     await hazard.save();

//     // Push hazard._id into reporter's reportedHazards
//     await Reporter.findByIdAndUpdate(reporterId, {
//       $push: { reportedHazards: hazard._id },
//     });

//     res.status(200).send("Hazard reported successfully!");
//   } catch (err) {
//     console.error(err);
//     res.status(500).send("An error occurred while saving the report.");
//   }
// });
async function getImageHash(imagePath) {
  const buffer = await sharp(imagePath).resize(100).toBuffer();
  return crypto.createHash("sha256").update(buffer).digest("hex");
}



app.post("/report", verifyToken, upload.single("image"), async (req, res) => {
  try {
    const { title, description, location, mapLink, catagory } = req.body;
    const image = req.file.filename;
    const reporterId = req.user._id;

    // 📍 Extract latitude and longitude
    let lat, lng;
    let match = mapLink.match(/@([-.\d]+),([-.\d]+)/) || mapLink.match(/q=([-.\d]+),([-.\d]+)/);
    if (match) {
      lat = parseFloat(match[1]);
      lng = parseFloat(match[2]);
    } else {
      return res.status(400).send("Invalid Google Maps link format.");
    }

    const newImagePath = path.join(__dirname, "public/uploads", image);

    // 🟡 Check for similar hazards nearby
    const nearbyHazards = await Hazard.find({
      coordinates: {
        $near: {
          $geometry: {
            type: "Point",
            coordinates: [lng, lat]
          },
          $maxDistance: 5000
        }
      },
      catagory: catagory
    });
//gemini check

// 🟢 Gemini image verification before proceeding
const imagePathForGemini = path.join(__dirname, "public/uploads", image);

// Encode the image as base64
const base64Image = fs.readFileSync(imagePathForGemini, { encoding: "base64" });

// Call Gemini API (replace with actual API key & URL)
const geminiResponse = await axios.post(`https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key=${process.env.GEMINI_API_KEY}`, {
  contents: [
    {
      parts: [
        {
          inlineData: {
            mimeType: "image/jpg", // adjust based on file type
            data: base64Image
          }
        },
        {
          text: "Is this image showing a real-world hazard such as pothole, fire, flood, collapsed structure, garbage, etc.? Answer with only 'yes' or 'no'."
        }
      ]
    }
  ]
});

const geminiResult = geminiResponse.data.candidates[0].content.parts[0].text.trim().toLowerCase();

// ❌ Reject non-hazard image
if (geminiResult !== "yes") {
  fs.unlinkSync(imagePathForGemini); // delete the uploaded image
  return res.redirect(`/report?error=${encodeURIComponent("Image does not appear to show a real hazard. Please upload a clearer or valid hazard image.")}`);
}





    for (let hazard of nearbyHazards) {
      const existingImagePath = path.join(__dirname, "public/uploads", hazard.image);
      if (fs.existsSync(existingImagePath)) {
        const response = await axios.post("http://localhost:5001/compare", null, {
          params: {
            img1: newImagePath,
            img2: existingImagePath
          }
        });

        if (response.data.similar) {
          return res.redirect(`/report?error=${encodeURIComponent(`This hazard already exists under "${catagory}" category. Check existing reports.`)}`);
        }
      }
    }

    // ✅ Save hazard
    const hazard = new Hazard({
      title,
      image,
      description,
      location,
      mapLink,
      catagory,
      reporter: reporterId,
      coordinates: {
        type: "Point",
        coordinates: [lng, lat]
      }
    });

    await hazard.save();

    await Reporter.findByIdAndUpdate(reporterId, {
      $push: { reportedHazards: hazard._id }
    });

    // 📣 Notify nearby users
    const nearbyUsers = await Reporter.find({
      location: {
        $near: {
          $geometry: {
            type: "Point",
            coordinates: [lng, lat]
          },
          $maxDistance: 200
        }
      }
    });

    const transporter = nodemailer.createTransport({
      service: "Gmail",
      auth: {
        user: "swarajnitrkl@gmail.com",
        pass: "jtik znfb krqf qlyj"
      }
    });

    const emailPromises = nearbyUsers.map(user =>
      transporter.sendMail({
        from: "Hazard Reporter <swarajnitrkl@gmail.com>",
        to: user.email,
        subject: "🚨 New Hazard Alert in Your Area!",
        html: `
          <h2>${title}</h2>
          <p>${description}</p>
          <p><strong>Location:</strong> ${location}</p>
          <p><a href="${mapLink}" target="_blank">View on Map</a></p>
          <img src="cid:hazardimage" style="max-width: 100%; height: auto;" />
        `,
        attachments: [
          {
            filename: image,
            path: newImagePath,
            cid: "hazardimage"
          }
        ]
      })
    );

    await Promise.all(emailPromises);

    res.status(200).send("Hazard reported and notifications sent!");
  } catch (err) {
    console.error("Error in /report:", err);
    res.status(500).send("An error occurred while saving the report.");
  }
});
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////





app.post('/admin/hazard/status/:id', async (req, res) => {
  try {
    const hazardId = req.params.id;
    const { status } = req.body;

    // Validate status
    const validStatuses = ['Reported', 'Acknowledged', 'In Progress', 'Resolved', 'Rejected'];
    if (!validStatuses.includes(status)) {
      return res.status(400).send("Invalid status value.");
    }

    // Update in DB
    await Hazard.findByIdAndUpdate(hazardId, { status });

    res.redirect('/admin/reports'); // or wherever your dashboard is
  } catch (err) {
    console.error('Error updating hazard status:', err);
    res.status(500).send("Failed to update status.");
  }
});





////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

////////////passport setup  //////////////////

const passport = require("passport");
require("./passport-config"); // import passport config

//const session = require("express-session");
//app.use(session({ secret: "secret", resave: false, saveUninitialized: false }));
app.use(passport.initialize());
app.use(passport.session());




app.get("/auth/google",
  passport.authenticate("google", { scope: ["profile", "email"] })
);

app.get("/auth/google/callback",
  passport.authenticate("google", { failureRedirect: "/login" }),
  (req, res) => {
    const token = generateToken(req.user);
    res.cookie("token", token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      maxAge: 2 * 60 * 60 * 1000,
    });
    res.redirect("/home");
  }
);


////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//admin


const isAdmin = require("./middleware/isadmin.js");

app.get("/admin/reports", verifyToken, isAdmin, async (req, res) => {
  const reports = await Hazard.find().populate('reporter');
  res.render("adminDashboard.ejs", { reports });
});

///voting  routes


app.post("/hazard/:id/vote/:type", verifyToken, async (req, res) => {
  const { id, type } = req.params;
  const userId = req.user._id;

  if (!["true", "false"].includes(type)) {
    return res.status(400).send("Invalid vote type");
  }

  try {
    const hazard = await Hazard.findById(id);
    if (!hazard) return res.status(404).send("Hazard not found");

    const existingVoteIndex = hazard.flag.voters.findIndex(v => v.user.toString() === userId.toString());

    if (existingVoteIndex === -1) {
      // First-time voting
      hazard.flag.voters.push({ user: userId, vote: type });
      hazard.flag[`${type}Votes`]++;
    } else {
      const existingVote = hazard.flag.voters[existingVoteIndex];

      if (existingVote.vote === type) {
        // Withdraw vote
        hazard.flag[`${type}Votes`]--;
        hazard.flag.voters.splice(existingVoteIndex, 1);
      } else {
        // Change vote
        hazard.flag[`${existingVote.vote}Votes`]--;
        hazard.flag[`${type}Votes`]++;
        hazard.flag.voters[existingVoteIndex].vote = type;
      }
    }

    await hazard.save();
   res.json({
  trueVotes: hazard.flag.trueVotes,
  falseVotes: hazard.flag.falseVotes
});

  } catch (err) {
    console.error(err);
    res.status(500).send("Internal Server Error");
  }
});







app.get("/hazard/:id/comments", async (req, res) => {
  try {
    const hazard = await Hazard.findById(req.params.id)
      .populate("comments.commenter", "fullname email") // Populate commenter details
      .exec();

    if (!hazard) {
      return res.status(404).send("Hazard not found");
    }

    res.render("comments", { hazard });
  } catch (err) {
    console.error(err);
    res.status(500).send("Internal Server Error");
  }
});




app.post("/hazard/:id/comments",verifyToken, async (req, res) => {
  try {
    const { commentText } = req.body;

    await Hazard.findByIdAndUpdate(
      req.params.id,
      {
        $push: {
          comments: {
            text: commentText,
            commenter: req.user._id // ensure user is authenticated
          }
        }
      },
      { new: true }
    );

    res.redirect(`/hazard/${req.params.id}/comments`);
  } catch (err) {
    console.error(err);
    res.status(500).send("Could not add comment");
  }
});


//add location of the residence
app.get("/add-location", verifyToken, (req, res) => {
  res.render("add-location", { user: req.user });
});

//post add location
app.post('/add-location', verifyToken, async (req, res) => {
  try {
    const { mapLink } = req.body;

    // Extract latitude and longitude from link
    const match = mapLink.match(/@?(-?\d+\.\d+),\s*(-?\d+\.\d+)/) || mapLink.match(/q=(-?\d+\.\d+),\s*(-?\d+\.\d+)/);

    if (!match) {
      return res.status(400).send("Invalid Google Maps link.");
    }

    const latitude = parseFloat(match[1]);
    const longitude = parseFloat(match[2]);

    // Update reporter's location in DB
    await Reporter.findByIdAndUpdate(req.user._id, {
      location: {
        type: "Point",
        coordinates: [longitude, latitude] // GeoJSON format: [lng, lat]
      }
    });

    res.status(200).send("Location updated successfully.");
  } catch (err) {
    console.error("Error saving location:", err);
    res.status(500).send("Something went wrong.");
  }
});







app.listen(3000,()=>console.log("app is listining"));
