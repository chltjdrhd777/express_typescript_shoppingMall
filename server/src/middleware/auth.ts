import { UserBaseDocumentType } from "./../models/User";
import User from "../models/User";
import { Request, NextFunction } from "express";

export interface CustomRequestQuery extends Request {
  checkedUser: UserBaseDocumentType;
}

export let auth = (req: CustomRequestQuery, _res, next: NextFunction) => {
  let token = req.cookies.authorized_user;
  User.findByToken(token, (doc) => {
    req.checkedUser = doc;
    next();
  });
};
