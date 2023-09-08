const User = require('../models/User')
const jwt = require('jsonwebtoken')
const {UnauthenticatedError} = require('../errors')

const auth = (req,res,next)=>{
    //check header
    const authHeader = req.headers.authorization
    if(!authHeader || !authHeader.startsWith('Bearer ')){
        throw new UnauthenticatedError('Authentication Error')
    }
    const token = authHeader.split(' ')[1];

    try {
        const payload = jwt.verify(token,process.env.JWT_SECRET)
/*         console.log(`Decoded Payload: ${JSON.stringify(payload)}`); */
        //attach user to job routes
        req.user={userID:payload.userID, name:payload.name}
        next()
    } catch (error) {
        console.log(error)
        throw new UnauthenticatedError('Authentication Invalid')
    }
}
module.exports = auth;