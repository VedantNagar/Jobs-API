const User = require('../models/User')
const {StatusCodes} = require('http-status-codes')
const {BadRequestError, UnauthenticatedError} = require('../errors')


const register = async(req,res)=>{

    const user = await User.create({...req.body})//creating a user
    //...tempUser creates a new object by spreading the properties and values of tempUser. It has the same properties as of tempUser.
    //This new object is used as an argument to the User.create() method to provide the necessary data for creating a new user.

    const token = user.createJWT();

    res.status(StatusCodes.CREATED).json({user:{name:user.name},token})//Respond with user's name and the generated JWT token
}

const login = async(req,res)=>{
    const {email,password} = req.body
    if(!email || !password){
        throw new BadRequestError('Please provide email and password');
    }
    const user = await User.findOne({email})
    if(!user){
        throw new UnauthenticatedError('Invalid Credentials')
    }
    const isPasswordCorrect = await user.comparePassword(password)
    if(!isPasswordCorrect){
        throw new UnauthenticatedError('Invalid Credentials')
    }
    //compare password
    const token = user.createJWT();
    res.status(StatusCodes.OK).json({user:{name:user.name},token});
}
module.exports={
    register,login
}