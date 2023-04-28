
const PasswordReset= require('../models/PasswordReset')
const sendgrid = require('@sendgrid/mail')
sendgrid.setApiKey(process.env.SENDGRIDAPIKEY)

exports.viewPasswordReset = function(req,res) {
    res.render('password-reset')
  }
  exports.viewPasswordResetPassword = function(req,res) {
    res.render('create-reset-password')
  }



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
                res.render('password-reset-password', {userId:userId});
            })
            .catch((error) => {
                console.error(error);
                res.status(500).send("Error sending email");
            });
        })
        .catch(function(e) {
            req.flash('errors', e)
            req.session.save(function() {
              res.redirect('/password-reset')
            })
          })
}


exports.setPassword = function(req, res) {
    const passwordReset = new PasswordReset(req.body);

    passwordReset.setPassword()
        .then(() => {
            req.flash("success", "Password successfully updated.");
            res.redirect("/");
        })
        .catch(function(errors) {
    
            req.session.save(function() {
                res.render('password-reset-password', { userId: req.body.userId ,errors:this.errors});
            }.bind(passwordReset)); // bind the value of `this` to the `passwordReset` instance
        })
}

