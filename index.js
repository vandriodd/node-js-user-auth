import express from "express"
import { PORT, SECRET_JWT_KEY } from "./config.js"
import { UserRepository } from "./user-repository.js"
import jwt from "jsonwebtoken"
import cookieParser from "cookie-parser"

const app = express()
app.set("view engine", "ejs")
app.use(express.json()) // express.json() is a middleware that parses the body of the request
app.use(cookieParser())

app.use((req, res, next) => {
  const token = req.cookies.access_token

  req.session = { user: null }
  try {
    const data = jwt.verify(token, SECRET_JWT_KEY)
    req.session.user = data
  } catch (err) {
    req.session.user = null
  }

  next() // <- continue to the next middleware or route handler
})

app.get("/", (req, res) => {
  const { user } = req.session
  res.render("index", user)
})

app.post("/login", async (req, res) => {
  const { username, password } = req.body

  try {
    const user = await UserRepository.login({ username, password })
    const token = jwt.sign({ id: user._id, username: user.username }, SECRET_JWT_KEY, {
      expiresIn: "1h",
    })

    // TODO: Generate refresh token
    // const refreshToken = jwt.sign(
    //   { id: user._id, username: user.username },
    //   SECRET_JWT_KEY,
    //   {
    //     expiresIn: "7d",
    //   }
    // )

    res
    .cookie("access_token", token, {
      httpOnly: true, // <- the cookie only can be accessed by the server
      secure: process.env.NODE_ENV === "production", // <- cookie is only sent over https
      sameSite: "strict", // <- prevent CSRF attacks (cookie only can be accessed from the same site)
      maxAge: 1000 * 60 * 60 // <- cookie expires in 1 hour
    })
    .send({ user })
  } catch (err) {
    res.status(401).send({ error: err.message })
  }
})

app.post("/register", async (req, res) => {
  const { username, password } = req.body // express doesn't parse the body by default if it's a json request

  try {
    const id = await UserRepository.create({ username, password })
    res.send({ id })
  } catch (err) {
    // Usually is NOT a good idea to send the error message to the client
    res.status(400).send({ error: err.message })
  }
})

app.post("/logout", (req, res) => {
  res
    .clearCookie("access_token")
    .json({ message: "Logout successful" })
})

app.get("/protected", (req, res) => {
  const { user } = req.session
  if (!user) {
    return res.status(403).send("Access not authorized")
  }

  res.render("protected", user)
})

app.listen(PORT, () => {
  console.log(`Server running on port http://localhost:${PORT}`)
})
