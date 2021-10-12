const jwt = require("jsonwebtoken");
const Users = require("../users/users-model");
const { JWT_SECRET } = require("../secrets");

const restricted = (req, res, next) => {
  const token = req.headers.authorization;
  if (!token) {
    return next({ status: 401, message: "Token required" });
  }

  jwt.verify(token, JWT_SECRET, (err, decodedToken) => {
    if (err) {
      return next({ status: 401, message: "Token invalid" });
    }

    req.decodedToken = decodedToken;
    return next();
  });
};

const only = (role_name) => (req, res, next) => {
  if (req.decodedToken.role_name === role_name) {
    next();
  } else {
    next({ status: 403, message: "This is not for you" });
  }
  next();
};

const checkUsernameExists = async (req, res, next) => {
  const { username } = req.body;
  const user = await Users.findBy({ username }).first();
  if (user) {
    res.user = user;
    next();
  } else {
    next({ status: 401, message: "Invalid credentials" });
  }
  next();
};

const validateRoleName = (req, res, next) => {
  if (!req.body.role_name || !req.body.role_name.trim()) {
    req.role_name = "student";
    next();
  } else if (req.body.role_name.trim() === "admin") {
    next({ status: 422, message: "Role name can not be admin" });
  } else if (req.body.role_name.trim().length > 32) {
    next({ status: 422, message: "Role name can not be longer than 32 chars" });
  } else {
    req.role_name = req.body.role_name.trim();
    next();
  }
};

module.exports = {
  restricted,
  checkUsernameExists,
  validateRoleName,
  only,
};
