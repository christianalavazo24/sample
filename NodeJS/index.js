var crypto = require('crypto');
var uuid = require('uuid');
var express = require('express');
var mysql = require('mysql');
var bodyParser = require('body-parser');
const { json } = require('body-parser');
const { stringify } = require('querystring');

//Connect to mysql
var con = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: '',
    database: 'demonodejs'
});


//START Password Utility
var getRamdonString = function(length){
    return crypto.randomBytes(Math.ceil(length/2))
        .toString('hex') /*convert to hexa format */
        .slice(0,length); /* return required number of characters*/
};

var sha512 = function(password, salt){
    var hash = crypto.createHmac('sha512', salt); //use SHA512
    hash.update(password);
    var value = hash.digest('hex');
    return {
        salt:salt,
        passwordHash:value
    };

};

function saltHashPassword(userPassword){
    var salt = getRamdonString(16);
    var passwordData = sha512(userPassword,salt);
    return passwordData;
}

function checkHashPassword(userPassword,salt)
{
    var passwordData = sha512(userPassword,salt);
    return passwordData;
}
//END Password Utility

var app = express();
app.use(bodyParser.json()); //Accept Json Parameter
app.use(bodyParser.urlencoded({extended: true})); // Accept URLencoded parameter


app.post('/register/', (req,res,next) =>{

    var post_data = req.body; //Get POST params
    var uid = uuid.v4(); // Get UUID v4 like '110abacsasasa-af0x-900-dadadadada'
    var plaint_password = post_data.password; // Get password from post parameter
    var hash_data = saltHashPassword(plaint_password);
    var password = hash_data.passwordHash; // Get hash value
    var salt = hash_data.salt; //get salt

    var name = post_data.name;
    var email = post_data.email;

    con.query('SELECT * FROM user where email=?', [email], function(err,result,fields){
        con.on('error', function(err) {
            console.log('[MYSQL ERROR]',err);
        });

        if(result && result.length)
        res.json('User Already Exists!!!');
        else
        {

        con.query('INSERT INTO `user`(`unique_id`, `name`, `email`, `encrypted_password`, `salt`, `created_at`, `updated_at`) VALUES (?,?,?,?,?,NOW(),NOW())',[uid,name,email,password,salt],function(err,result,fields){
       
            con.on('error', function(err) {
            console.log('[MYSQL ERROR]',err);
            res.json('Register Error', err);
        });
        res.json('Register Successfully!!');

    })    
    }  
    });
      
})


app.post('/login/', (req,res,next)=>{
    
    var post_data = req.body;//Get POST params

    //Extract email and password from request
    var user_password = post_data.password;
    var email = post_data.email;

    con.query('SELECT * FROM user where email=?', [email], function(err,result,fields){
        con.on('error', function(err) {
            console.log('[MYSQL ERROR]',err);
        });

        if(result && result.length)
        {
            var salt = result[0].salt; //Get salt of result if account exists.
            var encrypted_password = result[0].encrypted_password; //kung anu nasa database mo.
            //Hash password from Login request with salt in Database
            var hashed_password = checkHashPassword(user_password,salt).passwordHash;
            if(encrypted_password == hashed_password)
                res.end(JSON.stringify(result[0])) //If password is true, return all info of user
            else
                res.end(JSON.stringify('Wrong password'));    
        }

        else{

        res.json('User not exists!!!'); 
            
        }  
    }); 

    
  

})


app.post('/userscreate/', (req, res, next) => {
    
    var post_data = req.body; //Get POST params

    var firstname = post_data.firstname;
    var lastname = post_data.lastname;
    
        con.query('INSERT INTO `users`(`first_name`, `last_name`) VALUES (?,?)',[firstname,lastname],function(err,result,fields){
       
            con.on('error', function(err) {
            console.log('[MYSQL ERROR]',err);
            res.json('Register Error', err);
        });
        res.json('Register Successfully!!');

    })   
 })
    
  
// app.get('/', (req,res,next) =>{
//     console.log('Password : 123456');
//     var encrypt = saltHashPassword('123456');
//     console.log('Encrypt: '+encrypt.passwordHash);
//     console.log('Salt: '+encrypt.salt);
// })


//start server
app.listen(3000, () =>{
    console.log('EDMTDev Restful running  on port 3000');
})

