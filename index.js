import express from "express"
import cors from "cors"
import mysql from "mysql"
import jwt from "jsonwebtoken"
import bcrypt, { hash } from "bcrypt"
import cookieParser from "cookie-parser"

const salt = 11;



const app=express();
app.use(express.json());
app.use(cors({
    origin: ["http://localhost:3000"],
    methods: ["POST","GET"],
    credentials : true
}));
app.use(cookieParser());

const db = mysql.createPool({
    host: "localhost",
    user: "root",
    password: "",
    database: "conge",
});


app.post('/signup', (req, res) => {
    const sql = "INSERT INTO signup (`matricule`,`name`,`signupDate`,`solde`,`password`) VALUES (?)";
    
    bcrypt.hash(req.body.password.toString(), salt, (err, hash) => {
        if (err) return res.json({ Error: "Error hashing password" });

        const values = [
            req.body.matricule,
            req.body.name,
            req.body.signupDate,
            req.body.solde,
            hash,
        ];

        db.query(sql, [values], (err, result) => {
            if (err) return res.json({ Error: "Problem inserting data into the database" });
            return res.json({ Status: "Success" });
        });
    });
});




app.post('/login', (req, res)=> {
    const sql = 'SELECT * FROM signup WHERE matricule = ?';
    db.query(sql, [req.body.matricule], (err, data)=>{
        if(err) return res.json({ Error : "login error in server" });
        if(data.length > 0){
            bcrypt.compare(req.body.password.toString(), data[0].password, (err, response) => {
                if(err) return res.json({Error: " wrong password "});
                if(response){
                    const matricule = data[0].matricule;
                    const token = jwt.sign({ matricule }, "jwt-secret-key", { expiresIn: '5min' });
                    res.cookie('token',token)
                    return res.json({Status : "Success"})
                }else{
                    return res.json({Error : "password not matched"})
                }
            })
        }else{
            return res.json({ Error : "no email existed" });
        }
    })
})


const verifyUser = (req, res, next) => {
    const token = req.cookies.token;
    if (!token) {
        return res.json({ Error: "You are not authenticated" });
    } else {
        jwt.verify(token, "jwt-secret-key", (err, decoded) => {
            if (err) {
                return res.json({ Error: "Token is not valid" });
            } else {
                req.matricule = decoded.matricule;

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

// Example of using the verifyUser middleware in a route
app.get('/profilName', verifyUser, (req, res) => {
    res.json({ Status: "Success", name: req.name });
});

app.get('/logout', (req, res) => {
    res.clearCookie('token');
    return res.json({Status: "Success"});
});




app.listen(5000,()=> console.log("app is running in port 5000"));