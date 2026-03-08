const express = require("express");
const cors = require("cors");
const urlRoutes = require("./routes/urlRoutes");
const emailRoutes = require("./routes/emailRoutes");

const app = express();

app.use(cors());
app.use(express.json());
app.use("/api", urlRoutes);
app.use("/api", emailRoutes);

app.get("/", (req, res) => {
    res.send("Phishing Detection Backend Running");
});

app.listen(5000, () => {
    console.log("Server running on port 5000");
});