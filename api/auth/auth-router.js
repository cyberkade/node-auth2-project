const router = require("express").Router();
const bcrypt = require("bcryptjs");
const { checkUsernameExists, validateRoleName } = require("./auth-middleware");
const Users = require("../users/users-model");
const buildToken = require("./token-builder");

router.post("/register", validateRoleName, async (req, res, next) => {
  try {
    const { username, password } = req.body;
    const rounds = process.env.BCRYPT_ROUNDS || 8;
    const hash = bcrypt.hashSync(password, rounds);
    const user = { username, password: hash, role_name: req.role_name };
    const newUser = await Users.add(user);
    res.status(201).json(newUser[0]);
  } catch (err) {
    next(err);
  }
});

router.post("/login", checkUsernameExists, (req, res, next) => {
  const { password } = req.body;
  if (bcrypt.compareSync(password, res.user.password)) {
    const token = buildToken(res.user);
    res.status(200).json({
      message: `${res.user.username} is back!`,
      token,
    });
  } else {
    next({ status: 401, message: "Invalid Credentials" });
  }
});

module.exports = router;
