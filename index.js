require('dotenv').config();

const express = require('express');
const crypto = require('crypto');
const cookieParser = require('cookie-parser');

const accountSid = 'AC8aab9d298e03539a3be2f07391db6921'
const authToken = 'faa6c05080c4fc00ef0ea2bebe6ec9f8'
const client = require('twilio')(accountSid, authToken)
const jwt = require('jsonwebtoken');
const res = require('express/lib/response');
const JWT_AUTH_TOKEN = '33b5234e83b3ae354d3ca6b74f7494bfd267e91298f5a646f3608b658799c31fb756e5d679a9cd146b3d54d663355bdc176b8170b2e4c01a41f01c232109a3f7'
const JWT_REFRESH_TOKEN = '1967a5a072b11c0b924ded410fac2782908dc7686e6356c9fce4da7a692cd402b206721b177d75d55d88f21f2f63b0b585f85732d5bd3ba8a316a3b5cd77b437'
let refreshTokens = [];
const smsKey ='b75a9f4e0df08a2189f2e61ee8d5a35b7fc1210020bcf4b1e7fbe9200bbe7d228769ab4fbdff199b881b01fd01ab61d78a8d58b1935bd2fcd6a6286c973ceba1'

const app= express();
app.use(express.json());
app.use(cookieParser());


app.get('/',(req,res)=>{
    res.send('success')
})
app.post('/sendOTP',(req,res)=>{
    const phone = req.body.phone;
    const otp = Math.floor(100000 + Math.random()*900000)
    const ttl = 2*60*1000
    const expires = Date.now() +ttl;
    const data =`${phone}.${otp}.${expires}`
    const hash = crypto.createHmac('sha256', smsKey).update(data).digest('hex')
    const fullhash=`${hash}.${expires}`

client.messages.create({
    body:`your one time Login Password for CFM is ${otp}`,
    from: +15039669352,
    to: phone
}).then((messages) => console.log(messages)).catch((err)=>console.error(err));

res.status(200).send({phone ,hash:fullhash,otp});

 })

app.post('/verifyOTP', (req, res) => {
    const phone = req.body.phone;
    const hash = req.body.hash;
    const otp=req.body.otp;
    let [hashValue , expires] = hash.split('.')

    let now = Date.now();
    if(now > parseInt(expires)){
        return res.status(504).send({msg:`timeout Please try again`})
    }
    const data =`${phone}.${otp}.${expires}`
    const newCalculatedHash = crypto.createHmac('sha256', smsKey).update(data).digest('hex')
    

    
    if(newCalculatedHash === hashValue) {
       
        // return res.status(202).send({msg:`user Confirmed`})
        const accessToken= jwt.sign({data:phone},JWT_AUTH_TOKEN,{expiresIn :'30s'})
        const refreshToken= jwt.sign({data:phone},JWT_REFRESH_TOKEN,{expiresIn :'1y'})
        refreshTokens.push(refreshToken)
        res.status(202).
        cookie('accessToken',accessToken,{
            expires: new Date(new Date().getTime() + 30 * 1000),
            sameSite : 'strict',
            httpOnly : true
        }).
        cookie('authSession',true,{
            expires: new Date(new Date().getTime() + 30 * 1000),
            sameSite : 'strict',
            httpOnly : true
        })
        .cookie('refreshToken',refreshToken,{
            expires: new Date(new Date().getTime() + 3557600000),
            sameSite : 'strict',
            httpOnly : true
        })
        .cookie('refreshTokenID',true,{
            expires: new Date(new Date().getTime() + 3557600000),
            sameSite : 'strict',
            httpOnly : true
        }).send({msg : `device verified`})
    
    }
    else{
        return res.status(400).send({verification : false , msg:`Invalid otp`})
    }


})
async function authenticationUser(req, res, next){
    const accessToken =req.cookie.accessToken

    jwt.verify(accessToken,JWT_AUTH_TOKEN, async(err,phone)=>{
        if(phone){
            req.phone=phone;
            next()
        }else if (err.message ==='TokenExpiredError'){
            return res.status(403).send ({success: false , msg : `access Token Expired `})
        }else {
            console.error(err)
            res.status(401).send({err, msg: `user not authenticated `})

        }
    })
}
app.post ('/refresh',(req,res)=>{
    const refreshToken = req.cookies.refreshToken;
    if(!refreshToken) return res.status(403).send({msg: `refresh token not found,please login again `})
    if(!refreshTokens.includes(refreshToken))
    return res.status(403).send({msg: `refresh Token Blocked,login again`})
   
    jwt.verify(refreshToken, JWT_REFRESH_TOKEN,(err,phone)=>{
        if(!err){
            const accessToken= jwt.sign({data:phone},JWT_AUTH_TOKEN,{expiresIn :'30s'})
            res.status(202).
            cookie('accessToken',accessToken,{
                expires: new Date(new Date().getTime() + 30 * 1000),
                sameSite : 'strict',
                httpOnly : true
            }).
            cookie('authSession',true,{
            expires: new Date(new Date().getTime() + 30 * 1000),
               
            }).send({previousSessionsExpiry : true ,success : true})
        }else{
            return res.status(403).send({success : false , msg :`invalided refresh Token`})

        }
    })
})

app.get('/logout',(req, res)=>{
    res
    .clearCookie('refreshToken')
    .clearCookie('accessToken')
   .clearCookie('authSession')  
  //  .clearCookie('refreshToken')
    .clearCookie('refreshTokenID')
    .send('user Logged Out')
})
app.listen(3000)
