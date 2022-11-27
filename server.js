const fs = require("fs");
const jsonServer = require("json-server");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");

const server = jsonServer.create();
const router = jsonServer.router("db.json");
const middlewares = jsonServer.defaults();

const SECRET_KEY = "123456789";
const EXPIRES_IN = "1d";
const TOKEN_TYPE = "Bearer";

const auth = function (req, res, next) {
  const status = 401;
  const message = "Unauthorized";

  try {
    const [tokenType, accessToken] = req.headers.authorization.split(" ");
    if (!accessToken || tokenType !== TOKEN_TYPE) {
      res.status(status).json({ status, message });
    }

    jwt.verify(accessToken, SECRET_KEY, (error, decode) => {
      if (error) {
        res.status(status).json({ status, message });
      } else {
        next();
      }
    });
  } catch (err) {
    res.status(status).json({ status, message });
  }
};

server.use(middlewares);
server.use(jsonServer.bodyParser);

server.use("/api", router);
server.use("/private/api", auth, router);

server.get("/profile", auth, (req, res) => {
  try {
    const authHeader = req.headers.authorization;
    const [_, accessToken] = authHeader.split(" ");
    const { email } = jwt.decode(accessToken);

    const rawData = fs.readFileSync("./accounts.json", "utf8");
    const accounts = JSON.parse(rawData) || [];
    const account = accounts.find((item) => item.email === email);

    if (account) {
      delete account.password;
      res.status(200).json(account);
    } else {
      res.status(400);
    }
  } catch (error) {
    res.status(500).json({ error: "Server Error" });
  }
});

server.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    const status = 401;
    const message = "Unauthorized";

    const rawData = fs.readFileSync("./accounts.json", "utf8");
    const accounts = JSON.parse(rawData) || [];
    const user = accounts.find((item) => item.email === email);

    if (!user) {
      res.status(status).json({ status, message });
      return;
    }

    const validPassword = await bcrypt.compare(password, user.password);

    if (validPassword) {
      const accessToken = jwt.sign({ email }, SECRET_KEY, {
        expiresIn: EXPIRES_IN,
      });

      res
        .status(200)
        .json({ accessToken, expiresIn: EXPIRES_IN, tokenType: TOKEN_TYPE });
    } else {
      res.status(status).json({ status, message });
    }
  } catch (error) {
    console.log("error ", error);
    res.status(500).json({ error: "Server Error" });
  }
});

server.post("/register", async (req, res) => {
  try {
    const user = req.body;

    if (!(user.email && user.password)) {
      return res.status(400);
    }

    const rawData = fs.readFileSync("./accounts.json", "utf8");
    const accounts = JSON.parse(rawData) || [];
    const isExisting = accounts.some((item) => item.email === user.email);

    if (isExisting) {
      return res
        .status(400)
        .send({ error: `User with email ${user.email} is existing` });
    }

    const salt = await bcrypt.genSalt(10);
    user.password = await bcrypt.hash(user.password, salt);

    accounts.push(user);

    fs.writeFileSync("./accounts.json", JSON.stringify(accounts, null, 2));

    res.status(200).json({ message: "created" });
  } catch (err) {
    res.status(500).json({ error: "Server Error" });
  }
});

const port = process.env.PORT || 9000;

server.listen(port, () => {
  console.log("API running on http://localhost:", port);
});
