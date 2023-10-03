require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const cookieSession = require('cookie-session');
const { UserPool, authenticateUser, registerUser, verifyUser, forgotPassword, resetPassword, changePassword, getUser, updateUser, assignUser, getUserGroup } = require('./routes/auth');

const app = express();
app.use(bodyParser.json());
app.use(cookieSession({
    name: 'session',
    keys: ['your-secret-keys'],
    maxAge: 24 * 60 * 60 * 1000 // 24 hours
}));

app.post('/register', registerUser);
app.post('/login', authenticateUser);
app.post('/verify', verifyUser);
app.post('/forgot-password', forgotPassword);
app.post('/reset-password', resetPassword);
app.post('/change-password', auth, changePassword);
app.get('/user', getUser);
app.patch('/user', updateUser);
app.patch('/assign-user', assignUser);
app.get('/:username/user-group', getUserGroup);

function auth(req, res, next) {
    const authorizationHeader = req.headers.authorization;
    if (!authorizationHeader) {
        return res.status(401).json({ error: 'Authorization header missing' });
    }

    // Split the header to get the token part
    const tokenParts = authorizationHeader.split(' ');
    if (tokenParts.length !== 2 || tokenParts[0] !== 'Bearer') {
        return res.status(401).json({ error: 'Invalid token format' });
    }

    req.header.token = tokenParts[1];
    next()

}
app.listen(3002, () => {
    console.log('Server started on port 3002');
});
