function onSubmit(route) {
    // DEBUGGING
    // console.log(salt);
    
    const rawPassword = document.getElementById('password').value;
    const hashedPassword = CryptoJS.SHA512(rawPassword).toString();
    const rawUsername = document.getElementById('username').value;
    const body =  {
        password: hashedPassword,
        username: rawUsername
    };
    // https://stackoverflow.com/questions/133925/javascript-post-request-like-a-form-submit
    post(route, body);
}