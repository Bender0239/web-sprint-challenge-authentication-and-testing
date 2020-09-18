const router = require('express').Router();
const knex = require("knex")
const config = require("../knexfile")
const db = knex(config.development)
const bcrypt = require("bcryptjs")
const jwt = require("jsonwebtoken")

function add(user){
  return db("users").insert(user)
}

function findBy(filter) {
	return db("users")
		.select("id", "username", "password")
		.where(filter)
}

router.post("/register", async (req,res, next) => {
  try {
    
    if (req.body){
      const {username, password, department} = req.body
      const newUser = {
          username,
          password: await bcrypt.hash(password, 6)
      }
      await add(newUser)
      res.status(201).json({message: "user added"})
  } else {
      res.status(400).json({message: "Please provide valid username and password!"})
  }
  } catch(err) {
    next(err)
  }
})

router.post('/login', async (req, res, next) => {
  try {
		const { username, password } = req.body
		const user = await findBy({ username }).first()
		
		if (!user) {
			return res.status(401).json({
				message: "Invalid Credentials",
			})
		}

		// hash the password again and see if it matches what we have in the database
		const passwordValid = await bcrypt.compare(password, user.password)

		if (!passwordValid) {
			return res.status(401).json({
				message: "Invalid Credentials",
			})
		}

		const token = jwt.sign({
			userID: user.id,
		}, process.env.JWT_SECRET)

		res.json({
			message: `Welcome ${user.username}!`,
			token,
		})
	} catch(err) {
		next(err)
	}
});

module.exports = router;
