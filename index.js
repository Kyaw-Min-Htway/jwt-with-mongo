const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');


const app = express();
app.use(express.json());

// Connect to Mongodb
mongoose.connect('mongodb://localhost:27017/myapp', { useNewUrlParser: true, useUnifiedTopology: true});

//User Schema
const UserSchema = new mongoose.Schema({
    email: { type: String, unique: true, required: true },
    password: { type: String, required: true }
});

const User = mongoose.model('User', UserSchema);

//Register route
app.post('/register', async (req, res) => {
    try{
        const { email, password } = req.body;
        const hashedPassword = await bcrypt.hash(password, 10);
        const user = new User({ email, password: hashedPassword });
        await user.save();
        res.status(201).send('User registered successfully');
    } catch (error){
        console.error(error);
        res.status(500).send('Error registering user');
    }
});

//Login route
app.post('/login', async(req, res) => {
    try{
        const { email, password } = req.body;
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(401).send('Invalid email or password');
        }
        const isPasswordValid = await bcrypt.compare(password, user.password);
        if(!isPasswordValid) {
            return res.status(401).send('Invalid email or password');
        }
        const token = jwt.sign({ email: user.email }, 'secret-key', { expiresIn: '10mins'});
        res.json({ token });
    } catch (error) {
        console.error(error);
        res.status(500).send("Error logging in");
    }
});

// Protected route
app.get('/protected', authenticateToken, (req, res) => {
    res.send('Protected route accessed');
});

function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split('')[1];
    if (token == null) return res.sendStatus(401);

    jwt.verify(token, 'secret-key', (err, user) => {
        if(err) return res.sendStatus(403);
        req.user = user;
        next();
    });
}

app.listen(3000, () => {
    console.log('Server is running on port 3000');
});