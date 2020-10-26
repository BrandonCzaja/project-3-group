//I need to test the auth routes with our actual routes

const Outreach = require("../models/outreach");
const { Router } = require("express");
const router = Router();
const auth = require('../authMiddleware/authMiddleware')

//index route: Not sure if this will require user login
router.get("/", async (req, res) => {
  res.json(await Outreach.find({}));
});

//create route: Requires User Login
router.post("/", auth, async (req, res) => {
  res.json(await Outreach.create(req.body));
});

//update route: Requires User Login
router.put("/:id", auth, async (req, res) => {
  res.json(await Outreach.findByIdAndUpdate(req.params.id, req.body, { new: true }));
});

//delete route: Requires User Login
router.delete("/:id", auth, async (req, res) => {
  res.json(await Outreach.findByIdAndRemove(req.params.id));
});

// EXPORT ROUTER
module.exports = router;
