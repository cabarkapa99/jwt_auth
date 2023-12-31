require('dotenv').config();
const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');

const app = express();

app.use(express.json());

const users = [];

const posts = [
    {
        username:'Pera',
        title:"Blog 1"
    },
    {
        username:'Mika',
        title:"Blog 2"
    }
]

let refreshTokens = [];

app.post('/token', (req, res)=>{
    const refreshToken = req.body.token
    console.log(refreshToken);
    if(refreshToken == null) return res.sendStatus(401);
    if(!refreshTokens.includes(refreshToken)) return res.sendStatus(403);
    jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET, (err, user)=>{
        if(err) return res.sendStatus(403);
        const accessToken = generateAccessToken({name : user.name});
        res.json({accessToken: accessToken})
    })
})

app.get('/users', (req, res) =>{
    res.json(users);
})

app.post('/user', async (req, res)=>{
    try{
        const salt = await bcrypt.genSalt();
        const hashedPassword = await bcrypt.hash(req.body.password, salt);
        const user = {name:req.body.name, password: hashedPassword}
        users.push(user);
        res.status(201).send();
    }catch{
        res.status(500).send();
    }
})

app.get('/posts', authenticateToken, (req, res) =>{
    res.json(posts.filter(post => post.username === req.user.name));
})

app.post('/login', async (req, res)=>{
   //autentikacija  
    const usr = users.find(user => user.name === req.body.name)
    if(usr == null){
        return res.status(400).send('Nema korisnika')
    }
    try{
        if(await bcrypt.compare(req.body.password, usr.password)){

            // nakon autentikacije upisujemo u jwt ime korisnika i vracamo klijentu
            const username = req.body.name
            const user = {name: username}

            const accessToken = generateAccessToken(user);
            const refreshToken = jwt.sign(user, process.env.REFRESH_TOKEN_SECRET);
            refreshTokens.push(refreshToken)
            res.json({accessToken: accessToken, refreshToken: refreshToken})


        }else{
            res.send('Greska')
        }
    }catch{
        res.status(500).send();

    }

})

function authenticateToken(req, res, next){
    //ovde vrsimo proveru da li je token valjan
    // prvo ga dohvatamo iz hedera, a zatim proveravamo da li je valjan
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if(token == null) return res.sendStatus(401);

    jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user) =>{
        if(err) return res.sendStatus(403)

        console.log(user);
        req.user = user
        next();
    })
}

function generateAccessToken(user){
    return jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, {expiresIn: '1m'});
}

app.listen(3000);