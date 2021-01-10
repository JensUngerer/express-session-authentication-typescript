function onSubmit() {
    const salt = CryptoJS.lib.WordArray.random(16).toString();
    // DEBUGGING
    // console.log(salt);
    
    const rawPassword = document.getElementById('password').value;
    const hashedPassword = CryptoJS.PBKDF2(rawPassword, salt).toString();
    const rawUsername = document.getElementById('username').value;
    const body =  {
        salt: salt,
        password: hashedPassword,
        username: rawUsername
    };
    // https://stackoverflow.com/questions/133925/javascript-post-request-like-a-form-submit
    post('/register', body);
}