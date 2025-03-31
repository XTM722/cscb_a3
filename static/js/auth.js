const loginBox = document.getElementById('login-box');
const registerBox = document.getElementById('register-box');
const forgotBox = document.getElementById('forgot-box');
const leftTitle = document.getElementById('left-panel-title');
const leftSub = document.getElementById('left-panel-sub');
const leftBtn = document.getElementById('left-panel-btn');

function toggleForm() {
    loginBox.style.display = 'none';
    registerBox.style.display = 'block';
    forgotBox.style.display = 'none';
    leftTitle.innerText = 'Welcome Back!';
    leftSub.innerText = 'Already have an account?';
    leftBtn.innerText = 'Login';
    leftBtn.onclick = showLogin;
}

function showLogin() {
    loginBox.style.display = 'block';
    registerBox.style.display = 'none';
    forgotBox.style.display = 'none';
    leftTitle.innerText = 'Hello, Welcome!';
    leftSub.innerText = "Don't have an account?";
    leftBtn.innerText = 'Register';
    leftBtn.onclick = toggleForm;
}

function showForgot() {
    loginBox.style.display = 'none';
    registerBox.style.display = 'none';
    forgotBox.style.display = 'block';
    leftTitle.innerText = 'Forgot Password?';
    leftSub.innerText = 'Reset your password here';
    leftBtn.innerText = 'Login';
    leftBtn.onclick = showLogin;
}