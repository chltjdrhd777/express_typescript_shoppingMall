import express from "express";
import cors from "cors";
import bodyParser from "body-parser";
import cookieParser from "cookie-parser";
import mongoose from "mongoose";
const mongoDBAccessKey = require("./config/key");
import userRouter from "./routes/users";

//initializing app (const app = express())
const app = express();
app.use(cors());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(cookieParser());
////////////////////////////////////////////

//initializing mongoose
mongoose
  .connect(mongoDBAccessKey.mongoURI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
    useCreateIndex: true,
    useFindAndModify: false,
  })
  .then(() => console.log("MongoDB is now connected"))
  .catch((err) => console.log(err));
///////////////////////////////////////

//routes
app.use("/users", userRouter);
////////////////////////////////////////
//PORT
const port = process.env.PORT || 8080;

app.listen(port, () => {
  console.log(`listening port ${port}`);
});
//////////////////////////////////////
