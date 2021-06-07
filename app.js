const express = require('express');
const connectDB = require('./config/db');
const authRoute = require("./routes/auth");
const userRoute = require("./routes/users");
const app = express();
const cors = require('cors');


connectDB();

app.use(express.json());
app.use(cors());


app.use("/api/auth" , authRoute)
app.use("/api/users", userRoute)



const port = process.env.PORT || 8082;

app.listen(port, () => console.log(`Server running on port ${port}`));