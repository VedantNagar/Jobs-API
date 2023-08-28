const mongoose = require('mongoose')
const jwt = require('jsonwebtoken')
const bcrypt = require('bcryptjs')//Imports the 'bcryptjs' library, which is used for hashing passwords securely.

const userSchema = new mongoose.Schema({
    name:{
        type:String,
        required: [true,'Please provide Name'],
        minlength:3,
        maxlength:40,
    },
    email:{
        type:String,
        required:[true,'Please provide E-Mail'],
        match:[
            /^(([^<>()[\]\\.,;:\s@"]+(\.[^<>()[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/, //email validation
            'Please provide valid E-Mail',
        ],
        unique:true, //technically not a validator, creates a unique index
    },
       password:{
        type:String,
        required: [true,'Please provide Password'],
        minlength:4,
    },
})

userSchema.pre('save',async function(next){// ensures that the password is hashed before saving the user document to the database. 

/*
A "salt" is a random value that is used as an additional input during the process of hashing passwords. The purpose of a salt is to increase the security of password hashing by ensuring that even if two users have the same password, their hashed passwords will be different due to the unique salt used for each user. */

    const salt = await bcrypt.genSalt(10);
    //genSalt() function generates a random salt that is then used during the password hashing process.
    /*
    The 10 passed as an argument is the "rounds" factor. In bcrypt, the number of rounds determines the computational cost of hashing. The higher the number of rounds, the more secure and slower the hashing process becomes.
    The cost factor (10 in this case) is an exponential value, which means that each increment of the factor doubles the amount of work required. So, a cost factor of 10 would result in 1024 iterations of the underlying password hashing function.
    */

    this.password = await bcrypt.hash(this.password,salt)//the password is hashed
})

userSchema.methods.createJWT = function(){
    return jwt.sign({userID:this._id,name:this.name},'jwtSecret',{
        expiresIn: '30d',
    })
}
userSchema.methods.comparePassword = async function(userPassword){
    const isMatch = await bcrypt.compare(userPassword , this.password)
    return isMatch;
}
module.exports=mongoose.model('User',userSchema)