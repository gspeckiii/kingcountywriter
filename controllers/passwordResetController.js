
const PasswordReset= require('../models/PasswordReset')
const sendgrid = require('@sendgrid/mail')
sendgrid.setApiKey(process.env.SENDGRIDAPIKEY)





  exports.passwordReset = function(req, res) {
    const passwordReset = new PasswordReset(req.body);
    passwordReset.insertHashIntoDb()
        .then(function(result) {
            const resetToken = result.token;
            const userId = result.userId;
            
            // Use resetToken and userId as needed in your sendgrid email
            sendgrid.send({
                to: req.body.email,
                from: 'gspeckiii@proton.me',
                subject: "Reset KCW Password Pin",
                text: `${resetToken}`,
                html: `<p>${resetToken}</p>`
            })
            .then(() => {
                // req.flash("success", "New pin successfully created.")
                console.log("userId " + userId)
                res.render('password-reset-password', {userId:userId});
            })
            .catch((error) => {
                console.error(error);
                res.status(500).send("Error sending email");
            });
        })
        .catch(function(e) {
            console.error(e);
            res.status(500).send(e);
        });
}


exports.setPassword = function(req, res) {
    console.log("in controller");
    const passwordReset = new PasswordReset(req.body);
    console.log(req.body);
    
    passwordReset.setPassword()
        .then(() => {
            console.log("succeed in set password");
            // req.flash("success", "Password successfully updated.");
            res.redirect("/");
        })
        .catch((error) => {
            console.error("failed in controller:", error);
            // req.flash("errors", "You do not have permission to perform that action.");
            res.redirect("/");
        });
}

