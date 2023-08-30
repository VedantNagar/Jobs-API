const mongoose = require('mongoose')

const jobSchema = new mongoose.Schema({
    company:{
        type:String,
        required:[true,'Please provide the company name'],
        maxlength:100
    },
    position:{
        type:String,
        required:[true,'Please provide the position'],
        maxlength:100
    },
    status:{
        type:String,
        enum:['interview','declined','pending'],
        default:'pending',
    },
    createdBy:{
        type:mongoose.Types.ObjectId,
        ref:'User',//which model we are referring to
        required:[true,'Please provide the user'],
    }
},{timestamps:true})

module.exports = mongoose.model('Job',jobSchema);