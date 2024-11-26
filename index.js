import express from "express";
import cors from "cors";
import mysql from "mysql";
import jwt from "jsonwebtoken";
import bcrypt from "bcrypt";
import cookieParser from "cookie-parser";
import bodyParser from "body-parser";
import multer from "multer";


const salt = 11;
const app = express();




app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

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







app.get('/history_maladie', (req, res) => {
  const { matricule } = req.query; // Get matricule from query parameters

  if (!matricule) {
    return res.status(400).json({ error: 'Matricule is required' });
  }

  const query = 'SELECT * FROM conge_maladie WHERE matricule = ?'; // Use matricule in the query
  db.query(query, [matricule], (err, results) => {
    if (err) return res.status(500).json({ error: err.message });

    // Transform rows to include Base64 for file_data
    const transformedResults = results.map((row) => ({
      ...row,
      file_data: row.file_data ? row.file_data.toString('base64') : null,
    }));

    res.json(transformedResults);
  });
});




// Endpoint to handle "conge-maladie" form submission
app.post('/congeeparjour', (req, res) => {
  const { name, matricule, dateDebut, dateFin, nombreDeJours, commentaire } = req.body;

  // Validate required fields
  if (!name || !matricule || !dateDebut || !dateFin || !nombreDeJours || !commentaire) {
    return res.status(400).json({ message: 'Tous les champs requis doivent être remplis.' });
  }


  // SQL query to insert the form data
  const query = `
    INSERT INTO congee (name, matricule, dateDebut, dateFin, nombreDeJours, commentaire)
    VALUES (?, ?, ?, ?, ?, ?)
  `;

  db.query(
    query,
    [name, matricule, dateDebut, dateFin, nombreDeJours, commentaire],
    (err, result) => {
      if (err) {
        console.error('Error inserting data:', err);
        return res.status(500).json({ message: 'Erreur lors de l\'enregistrement du congé.' });
      }
      res.status(200).json({ message: 'Congé maladie enregistré avec succès!' });
    }
  );
});





// POST endpoint to handle form data from frontend
app.post('/autorisation', (req, res) => {
  const { date, heureDebut, heureFin, commentaire, nombredeheure, name, matricule } = req.body;

  // Validate required fields
  if (!date || !heureDebut || !heureFin || !nombredeheure) {
    return res.status(400).json({ message: 'Veuillez remplir tous les champs obligatoires.' });
  }

  // Correct SQL query with 7 placeholders
  const query = `
    INSERT INTO autorisations (date, heureDebut, heureFin, commentaire, nombredeheure, name, matricule)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `;
  const values = [date, heureDebut, heureFin, commentaire, nombredeheure, name, matricule];

  // Execute the query
  db.query(query, values, (err, result) => {
    if (err) {
      console.error('Database error:', err);
      return res.status(500).json({ message: 'Erreur lors de l\'enregistrement de la demande.' });
    }
    res.status(200).json({ message: 'Autorisation enregistrée avec succès!' });
  });
});









// Multer configuration for in-memory storage
const storage = multer.memoryStorage();
const upload = multer({
  storage: storage,
  fileFilter: (req, file, cb) => {
    const allowedTypes = ['application/pdf', 'image/jpeg', 'image/png'];
    if (!allowedTypes.includes(file.mimetype)) {
      return cb(new Error('Seuls les fichiers PDF, JPEG, et PNG sont acceptés.'));
    }
    cb(null, true);
  },
  limits: { fileSize: 5 * 1024 * 1024 }, // Limit file size to 5MB
});

// Endpoint to handle POST requests for "congé maladie"
app.post('/conge-maladie', upload.single('uploadedFile'), (req, res) => {
  const { dateDebut, dateFin, commentaire, name, matricule } = req.body;
  const file = req.file ? req.file.buffer : null; // File stored as a buffer for BLOB

  // Validate required fields
  if (!dateDebut || !dateFin || !name || !matricule) {
    return res.status(400).json({
      message: 'Veuillez remplir tous les champs obligatoires (dateDebut, dateFin, name, matricule).',
    });
  }

  // SQL Query to insert data with BLOB
  const query = `
    INSERT INTO conge_maladie (date_debut, date_fin, commentaire, file_data, file_type, name, matricule)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `;
  const values = [dateDebut, dateFin, commentaire, file, req.file?.mimetype || null, name, matricule];

  db.query(query, values, (err, result) => {
    if (err) {
      console.error('Error saving data to database:', err);
      return res.status(500).json({ message: 'Erreur lors de l\'enregistrement dans la base de données.' });
    }
    res.status(200).json({ message: 'Congé maladie enregistré avec succès!' });
  });
});

// Error handling middleware
app.use((err, req, res, next) => {
  if (err instanceof multer.MulterError) {
    return res.status(400).json({ message: `Erreur de téléchargement: ${err.message}` });
  } else if (err) {
    return res.status(500).json({ message: `Erreur serveur: ${err.message}` });
  }
  next();
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