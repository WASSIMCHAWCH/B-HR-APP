import express from "express";
import cors from "cors";
import mysql from "mysql";
import jwt from "jsonwebtoken";
import bcrypt from "bcrypt";
import cookieParser from "cookie-parser";

const salt = 11;
const app = express();

app.use(express.json());
app.use(cors({
    origin: ["http://localhost:3000"],
    methods: ["POST", "GET"],
    credentials: true,
}));
app.use(cookieParser());

const db = mysql.createPool({
    host: "localhost",
    user: "root",
    password: "",
    database: "conge",
});

// User Signup Route
app.post('/signup', (req, res) => {
    const sql = "INSERT INTO signup (`matricule`, `name`, `signupDate`, `solde`, `password`, `role`) VALUES (?)";
    
    bcrypt.hash(req.body.password.toString(), salt, (err, hash) => {
        if (err) return res.json({ Error: "Error hashing password" });

        const values = [
            req.body.matricule,
            req.body.name,
            req.body.signupDate,
            req.body.solde,
            hash,
            "User"
        ];

        db.query(sql, [values], (err) => {
            if (err) return res.json({ Error: "Problem inserting data into the database" });
            return res.json({ Status: "Success" });
        });
    });
});

// User Login Route
app.post('/login', (req, res) => {
    const sql = 'SELECT * FROM signup WHERE matricule = ?';
    db.query(sql, [req.body.matricule], (err, data) => {
        if (err) return res.json({ Error: "login error in server" });
        if (data.length > 0) {
            bcrypt.compare(req.body.password.toString(), data[0].password, (err, response) => {
                if (err) return res.json({ Error: "wrong password" });
                if (response) {
                    const matricule = data[0].matricule;
                    const role = data[0].role;
                    const token = jwt.sign({ matricule, role }, "jwt-secret-key", { expiresIn: '5min' });
                    res.cookie('token', token);
                    return res.json({ Status: "Success" });
                } else {
                    return res.json({ Error: "password not matched" });
                }
            });
        } else {
            return res.json({ Error: "no email existed" });
        }
    });
});

// Middleware to verify user and fetch role
const verifyUser = (roles = []) => (req, res, next) => {
    const token = req.cookies.token;
    if (!token) {
        return res.json({ Error: "You are not authenticated" });
    } else {
        jwt.verify(token, "jwt-secret-key", (err, decoded) => {
            if (err) {
                return res.json({ Error: "Token is not valid" });
            } else if (roles.length && !roles.includes(decoded.role)) {
                return res.json({ Error: "You do not have access" });
            } else {
                req.matricule = decoded.matricule;
                req.role = decoded.role;

                // Fetch the user name from the database using the matricule
                const sql = 'SELECT name FROM signup WHERE matricule = ?';
                db.query(sql, [req.matricule], (err, data) => {
                    if (err) {
                        return res.json({ Error: "Database query error" });
                    }
                    if (data.length > 0) {
                        req.name = data[0].name; // Add name to request object
                        next(); // Call the next middleware function
                    } else {
                        return res.json({ Error: "User not found" });
                    }
                });
            }
        });
    }
};

// Route to get user role
app.get('/get-role', verifyUser(), (req, res) => {
    res.json({ role: req.role });
});

// Protected routes based on roles
app.get('/dashboard', verifyUser(['USER', 'HR', 'ADMIN']), (req, res) => {
    res.json({ Status: "Success", message: "Welcome to the dashboard" });
});

app.get('/hr-section', verifyUser(['HR', 'ADMIN']), (req, res) => {
    res.json({ Status: "Success", message: "Welcome to the HR section" });
});

app.get('/admin-section', verifyUser(['ADMIN']), (req, res) => {
    res.json({ Status: "Success", message: "Welcome to the admin section" });
});

// Example of using the verifyUser middleware in a route
app.get('/profilName', verifyUser(), (req, res) => {
    res.json({ Status: "Success", name: req.name });
});

// Logout route
app.get('/logout', (req, res) => {
    res.clearCookie('token');
    return res.json({ Status: "Success" });
});

// Start the server
app.listen(5000, () => console.log("app is running on port 5000"));