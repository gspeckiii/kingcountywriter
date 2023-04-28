const passwordResetCollection = require('../db').db().collection("passwordReset")
const usersCollection = require('../db').db().collection("users")
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const ObjectId = require('mongodb').ObjectId

let PasswordReset = function(data) {
    this.data= data
    this.errors = []

  }

 
  PasswordReset.prototype.insertHashIntoDb = function(){
    return new Promise(async(resolve, reject)=>{
        let passwordHash = await generateResetHash().catch((err) => {
            this.errors.push("Hash not generated");
            reject(err); // reject with error
        });
        try {
            if (typeof(this.data.email) != "string") {
                this.data.email = "";
            }
        
            const resetHash = passwordHash.resetHash;
            const resetToken = passwordHash.resetToken;
            const expiration = Date.now() + 3600000; // 1 hour from now
            const lostUser = await usersCollection.findOne({email: this.data.email});
        
            if (lostUser && resetToken) {
                await PasswordReset.delete(lostUser._id)
                    .catch((error) => {
                        this.errors.push("delete fail", error);
                        reject(this.errors); // reject with error
                    });

                this.data = {
                    userId: lostUser._id,
                    hash: resetHash,
                    expiration: expiration,
                    createTS: Math.floor(Date.now() / 1000)
                }
                await passwordResetCollection.insertOne(this.data);

                resolve({token: resetToken, userId: this.data.userId}); // resolve with token and userId
            } else {
                this.errors.push("no email by that name");
                reject(this.errors); // reject with error

            }
        } catch(error) {
            this.errors.push("Db not connecting",error);
            reject(this.errors); // reject with error
        }
    });
}

  function generateRandomString(length) {
    return crypto.randomBytes(Math.ceil(length / 2)).toString('hex').slice(0, length);
  }
  
  async function generateResetHash() {
    // Generate a random string (16 characters long, for example)
    const resetToken = generateRandomString(16);
  
    // Hash the reset token with bcrypt
    const salt = await bcrypt.genSalt(10);
    const resetHash = await bcrypt.hash(resetToken, salt);
  
    // You can now store the resetHash in your database and send the resetToken to the user's email
  
    return { resetToken, resetHash };
  }
  
  PasswordReset.delete = function (currentUserId) {
    return new Promise(async (resolve, reject) => {
      try {
        await passwordResetCollection.deleteMany({ userId: new ObjectId(currentUserId) });
        resolve();
      } catch (error) {
        this.errors.push("Db not connecting",error);
        reject(this.errors); // reject with error
       
      }
    });
  };


  PasswordReset.prototype.setPassword = async function() {
    try {
        if (this.data.newPassword.length < 12 || this.data.newPassword.length >50 ){
            throw  this.errors.push("Password needs to be greater than 12 characters and less than 50");
        }
        if(this.data.emailedToken.length != 16){
            throw this.errors.push("Token did not have the correct number of characters");
        }
      
        const resetData = await PasswordReset.findUserHash(this.data.userId);
        
        // Check if resetData exists
        if (!resetData) {
            throw this.errors.push("User Hash not found")
        }

        const currentTime = Date.now();
        const isValid = await PasswordReset.checkUserHash(this.data.emailedToken,resetData.hash);

        if (isValid && currentTime <= resetData.expiration) {
            // Save the new password to the database
            const newPasswordHash = await bcrypt.hash(this.data.newPassword, 10);
            const result = await usersCollection.updateOne(
                { _id: new ObjectId(this.data.userId) },
                { $set: { password: newPasswordHash } }
            );
            return result;
        } else {
            throw this.errors.push("Invalid token or expired link");
        }
    } catch (e) {
        throw this.errors.push("set password failed")

    }
};
     
PasswordReset.findUserHash = function(currentUserId){
    return new Promise(async(resolve,reject)=>{
        try {
            const resetData =await passwordResetCollection.findOne({userId: new ObjectId(currentUserId)})
            resolve(resetData);
          } catch (error) {
            reject(new Error("findUserHash fail: " + error.message));
          }
        })
    }
PasswordReset.checkUserHash = function(emailedToken,resetHash){
    return new Promise(async (resolve,reject)=>{
        try{
            const isValid = await bcrypt.compare(emailedToken, resetHash)
            resolve(isValid)
        }catch(error){
            this.errors.push("checkUserHash fail: ",error);
            reject(this.errors);

        }
    })
}


  
  module.exports = PasswordReset
