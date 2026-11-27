const express = require("express");

const app = express();
app.get("/", (req, res) => res.send("hello from express"));

const port = process.env.PORT || 3000;
app.listen(port, process.env.HOST || "0.0.0.0", () => console.log(`listening on ${port}`));
