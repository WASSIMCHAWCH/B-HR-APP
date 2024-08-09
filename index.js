import express from "express"
import cors from "cors"

const app=express();
app.use(cors());

app.get("/getData",(req, res)=>{
    res.json({ hhh: 'Hello from the backend!' });
})

app.listen(5000,()=> console.log("app is running in port 5000"));