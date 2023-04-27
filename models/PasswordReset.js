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
            console.log("hash: "+ resetHash + "  resetToken: " + resetToken);
            const expiration = Date.now() + 3600000; // 1 hour from now
            const lostUser = await usersCollection.findOne({email: this.data.email});
            console.log(lostUser);
            if (lostUser && resetToken) {
                await PasswordReset.delete(lostUser._id)
                    .then((message) => {
                        console.log(message);
                    })
                    .catch((error) => {
                        console.log("delete fail", error);
                        reject(error); // reject with error
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
            reject(error); // reject with error
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
    console.log('Reset token:', resetToken);
    console.log('Reset hash:', resetHash);
  
    return { resetToken, resetHash };
  }
  
  PasswordReset.delete = function (currentUserId) {
    return new Promise(async (resolve, reject) => {
      try {
        await passwordResetCollection.deleteMany({ userId: new ObjectId(currentUserId) });
        resolve(console.log("delete success"));
      } catch (error) {
        reject(new Error("delete fail: " + error.message));
      }
    });
  };


  PasswordReset.prototype.setPassword = async function() {
    try {
        const resetData = await PasswordReset.findUserHash(this.data.userId);
        console.log(this.data.userId)
        // Check if resetData exists
        if (!resetData) {
            throw new Error("No reset data found for this user");
        }

        console.log(resetData.hash);
        console.log(resetData.expiration);
        console.log(this.data.emailedToken);
        
        const currentTime = Date.now();
    

        const isValid = await PasswordReset.checkUserHash(this.data.emailedToken,resetData.hash);
        console.log(isValid);

        if (isValid && currentTime <= resetData.expiration) {
            // Save the new password to the database
            const newPasswordHash = await bcrypt.hash(this.data.newPassword, 10);
            const result = await usersCollection.updateOne(
                { _id: new ObjectId(this.data.userId) },
                { $set: { password: newPasswordHash } }
            );
            return result;
        } else {
            throw new Error("Invalid token or expired link");
        }
    } catch (error) {
        console.error(error);
        throw error;
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
            console.log(error.message)
            reject(new Error("checkUserHash fail: " + error.message));

        }
    })
}


  
  module.exports = PasswordReset
