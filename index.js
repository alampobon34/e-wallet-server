const express = require("express");
const app = express();
require("dotenv").config();
const cors = require("cors");
const cookieParser = require("cookie-parser");
const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const SALT_ROUNDS = 10;

const port = process.env.PORT || 8000;

const corsOptions = {
  origin: ["http://localhost:3000"],
  credentials: true,
  optionSuccessStatus: 200,
};
app.use(cors(corsOptions));

app.use(express.json());
app.use(cookieParser());

// DB_USER=alampobon34
// DB_PASS=4oXLpcM3lr7CuVwm
// ACCESS_TOKEN_SECRET=31ca4f2112b210203f7a383b436748bca560a78d3e7dd74609fc1c0d5525df8682ab5aed34245edd838d3e98b04a1c020f06e27ff5b51dc65d936b199a859afa

const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@ph-b9-assignment-11-db.fegaod7.mongodb.net/?retryWrites=true&w=majority&appName=ph-b9-assignment-11-db
`;
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

const verifyToken = async (req, res, next) => {
  const token = req.cookies?.token;
  if (!token) {
    return res.status(401).send({ message: "unauthorized access" });
  }
  jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, decoded) => {
    if (err) {
      console.log(err);
      return res.status(401).send({ message: "unauthorized access" });
    }
    req.user = decoded;
    next();
  });
};

async function run() {
  try {
    const usersCollection = client.db("ewallet-db").collection("users");

    const verifyParticipant = async (req, res, next) => {
      const user = req.user;
      const query = { email: user?.email };
      const result = await usersCollection.findOne(query);
      console.log(result?.role);
      if (!result || result?.role !== "Participant") {
        return res
          .status(403)
          .send({ message: "Only Participant Can Access!!" });
      }
      next();
    };

    const verifyOrganizer = async (req, res, next) => {
      const user = req.user;
      const query = { email: user?.email };
      const result = await usersCollection.findOne(query);
      console.log(result?.role);
      if (!result || result?.role !== "Organizer") {
        return res.status(403).send({ message: "Only Organizer Can Access!!" });
      }
      next();
    };

    app.post("/register", async (req, res) => {
      try {
        let userData = req.body;
        const { email, phone, pin, name, type } = userData;
        const query = { $or: [{ email: email }, { phone: phone }] };
        const user = await usersCollection.findOne(query);
        if (user) {
          res.send({
            status: 422,
            message: "Already Registered this email/phone",
          });
        } else if (!email || !phone || !pin || !name) {
          res.send({
            status: 422,
            message: "Invalid Input",
          });
        } else {
          bcrypt.genSalt(SALT_ROUNDS, function (err, salt) {
            bcrypt.hash(pin, salt, async function (err, hash) {
              if (err) {
                res.send({
                  status: 422,
                  message: "Error occur in the password field",
                });
              } else {
                userData = {
                  ...userData,
                  pin: hash,
                  type: type === "AGENT" ? "AGENT" : "USER",
                  active: "NO",
                };
                const result = await usersCollection.insertOne(userData);
                if (result.insertedId) {
                  res.send({
                    status: 201,
                    message: "User Register Successfully!",
                  });
                } else {
                  res.send({ status: 422, message: "Something Went Wrong" });
                }
              }
            });
          });
        }
      } catch (e) {
        console.log(e);
        res.send({ message: "Internal Server Error" }).status(500);
      }
    });

    app.post("/login", async (req, res) => {
      const data = req.body;
      const { email, password, phone } = data;
      const query = { $or: [{ email: email }, { phone: phone }] };
      const user = await usersCollection.findOne(query);
      if (user) {
        if (user?.active !== "YES") {
          res.send({ message: "Your account is activate yet!", user: null });
        }
        bcrypt.compare(password, user?.pin, function (err, isMatch) {
          if (err) {
            res.send({ message: "Invalid Credentials", user: null });
          } else {
            if (isMatch) {
              const token = jwt.sign(
                { email },
                process.env.ACCESS_TOKEN_SECRET,
                {
                  expiresIn: "365d",
                }
              );
              const response = {
                status: 200,
                user: {
                  _id: user._id,
                  name: user.name,
                  email: user.email,
                  phone: user.phone,
                  balance: user.balance,
                  type: user.type,
                  active: user.active,
                  accessToken: token,
                },
              };
              res.send(response);
            } else {
              res.send({ message: "Invalid Credentials", user: null });
            }
          }
        });
      } else {
        res.send({ status: 401, user: null });
      }

      //   res
      //     .cookie("token", token, {
      //       httpOnly: true,
      //       secure: process.env.NODE_ENV === "production",
      //       sameSite: process.env.NODE_ENV === "production" ? "none" : "strict",
      //     })
      //     .send({ success: true, token: token });
    });

    app.get("/logout", async (req, res) => {
      try {
        res
          .clearCookie("token", {
            maxAge: 0,
            secure: process.env.NODE_ENV === "production",
            sameSite: process.env.NODE_ENV === "production" ? "none" : "strict",
          })
          .send({ success: true });
      } catch (err) {
        res.status(500).send(err);
      }
    });

    // Send a ping to confirm a successful connection
    // await client.db('admin').command({ ping: 1 })
    // console.log(
    //     'Pinged your deployment. You successfully connected to MongoDB!'
    // )
  } finally {
  }
}
run().catch(console.dir);

app.get("/", (req, res) => {
  res.send("MCMS server is running..");
});

app.listen(port, () => {
  console.log(`MCMS is running on port ${port}`);
});
