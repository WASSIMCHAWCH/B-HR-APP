import express from "express"
import cors from "cors"
import mysql from "mysql"
import jwt from "jsonwebtoken"
import bcrypt, { hash } from "bcrypt"
import cookieParser from "cookie-parser"

const salt = 11;



const app=express();
app.use(express.json());
app.use(cors());
app.use(cookieParser());

const db = mysql.createPool({
    host: "localhost",
    user: "root",
    password: "",
    database: "conge",
});



app.post('/signup', (req, res)=> {
    const sql = "INSERT INTO signup (`matricule`,`name`,`signupDate`,`solde`,`password`) VALUES (?)";
   bcrypt.hash(req.body.password.toString(), salt, (err, hash) =>{
    if(err) return res.json({ Error : "error from hashing password" });

    const values = [
        req.body.matricule,
        req.body.name,
        req.body.signupDate,
        req.body.solde,
        hash,
    ]
    db.query(sql, [values], (err, result)=>{
        if(err) return res.json({ Error : "problem inserting data from server to db" });
        return res.json({ Status : "Success" });
    })
   })
})



app.post('/login', (req, res)=> {
    const sql = 'SELECT * FROM signup WHERE matricule = ?';
    db.query(sql, [req.body.matricule], (err, data)=>{
        if(err) return res.json({ Error : "login error in server" });
        if(data.length > 0){
            bcrypt.compare(req.body.password.toString(), data[0].password, (err, response) => {
                if(err) return res.json({Error: " wrong password "});
                if(response){
                    return res.json({Status : "Success"})
                }else{
                    return res.json({Error : "password not matched"})
                }
            })
        }else{
            return res.json({ Error : "no email existed" });
        }
    })


   bcrypt.hash(req.body.password.toString(), salt, (err, hash) =>{
    if(err) return res.json({ Error : "error from hashing password" });

    const values = [
        req.body.matricule,
        req.body.name,
        req.body.signupDate,
        req.body.solde,
        hash,
    ]
   })
})





app.listen(5000,()=> console.log("app is running in port 5000"));