import express from "express";
import cors from "cors";
import mysql from "mysql";
import jwt from "jsonwebtoken";
import bcrypt from "bcrypt";
import cookieParser from "cookie-parser";
import bodyParser from "body-parser";


const salt = 11;
const app = express();
app.use(bodyParser.json());

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

app.post('/demande', (req, res) => {
    const { typeConge, heureDebut, heureFin, dateDebut, dateFin, totalTimeOff } = req.body;
  
    // SQL query to insert into the demande table
    const query = `
      INSERT INTO demande (typeConge, heureDebut, heureFin, dateDebut, dateFin, totalTimeOff) 
      VALUES (?, ?, ?, ?, ?, ?)
    `;
  
    // Execute the query, safely inserting user data
    db.query(
      query,
      [typeConge, heureDebut || null, heureFin || null, dateDebut || null, dateFin || null, totalTimeOff],
      (error, results) => {
        if (error) {
          console.error('Error inserting data:', error);
          return res.status(500).send('Error inserting data');
        }
        res.status(200).send('Demande de congé enregistrée avec succès!');
      }
    );
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
                    const name = data[0].name;

                    const token = jwt.sign({ matricule, role, name}, "jwt-secret-key", { expiresIn: '5min' });
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
const verifyUser = () => (req, res, next) => {
    const token = req.cookies.token;
    if (!token) return res.json({ Error: "You are not authenticated" });

    jwt.verify(token, "jwt-secret-key", (err, decoded) => {
        if (err) return res.json({ Error: "Invalid token" });

        req.matricule = decoded.matricule;
        req.role = decoded.role;
        req.name = decoded.name;
        next();

        // Fetch user name from the database

    });
};

// Route to get user role
app.get('/get-role', verifyUser(), (req, res) => {
    res.json({ Status: "Success", role: req.role , name: req.name });
});

// Logout route
app.get('/logout', (req, res) => {
    res.clearCookie('token');
    return res.json({ Status: "Success" });
});



// Example of using the verifyUser middleware in a route
app.get('/profilName', verifyUser(), (req, res) => {
    res.json({ Status: "Success", name: req.name, matricule: req.matricule });
});


// API Endpoint to get leave history by matricul
app.get('/history/:matricule', (req, res) => {
    const matricul = req.params.matricule;
  
    const query = 'SELECT * FROM historique WHERE matricul = ?'; // Adjust table name as needed
    db.query(query, [matricul], (err, results) => {
      if (err) {
        console.error('Error fetching leave history:', err);
        return res.status(500).json({ error: 'Database error' });
      }
      
      // Return results in the response
      res.json(results);
    });
  });

// Start the server
app.listen(5000, () => console.log("app is running on port 5000"));