import { CustomRequestQuery } from "./../middleware/auth";
import express, { Response } from "express";
import User from "../models/User";
import { auth } from "../middleware/auth";

const router = express.Router();

router.post("/register", (req, res) => {
  const user = new User(req.body);

  user.save((err, userData) => {
    if (err) return res.json({ success: false, err });

    return res.status(200).json({ success: true, userData });
  });
});

router.post("/login", (req, res) => {
  User.findOne({ email: req.body.email }).then((targetUser) => {
    if (!targetUser) {
      res.json({ loginState: false, message: "there is no matched user" });
    } else {
      targetUser.comparePassword(req.body.password).then((result) => {
        if (!result) {
          res.json({ loginState: false, message: "wrong password" });
        } else {
          targetUser.generateToken().then((tokenUpdatedUser) => {
            if (!tokenUpdatedUser)
              return res.json({
                loginState: false,
                message: "Token is not updated successfully",
              });

            res
              .cookie("authorized_user", tokenUpdatedUser.token)
              .status(200)
              .json({ loginState: true, message: "login complete" });
          });
        }
      });
    }
  });
});

router.get("/logout", auth, (req: CustomRequestQuery, res: Response) => {
  User.findOneAndUpdate({ _id: req.checkedUser._id }, { token: "" }).exec(
    (err, doc) => {
      if (err)
        return res.json({
          success: false,
          message: "there is an error for logging out",
        });

      return res.json({
        success: true,
        message: "successfully logged out and delete your token",
        doc,
      });
    }
  );
});

export default router;
