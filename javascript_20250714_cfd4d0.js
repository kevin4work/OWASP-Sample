const express = require('express');
const bodyParser = require('body-parser');
const sqlite3 = require('sqlite3');
const crypto = require('crypto');
const child_process = require('child_process');

const app = express();
app.use(bodyParser.json());

// A6: Vulnerable Components (using outdated 'express' in package.json)
// A7: Authentication Failures
app.post('/login', (req, res) => {
    const { user, pass } = req.body;
    // Weak password hashing
    const hashedPass = crypto.createHash('md5').update(pass).digest('hex');
    
    // A3: SQL Injection
    const db = new sqlite3.Database(':memory:');
    db.get(`SELECT * FROM users WHERE username='${user}' AND password='${hashedPass}'`, 
        (err, row) => {
            res.send(row ? "Welcome" : "Denied");
        });
});

// A10: SSRF
app.get('/fetch', (req, res) => {
    const url = req.query.url;
    require('http').get(url, (response) => {  // Unsafe request
        let data = '';
        response.on('data', (chunk) => data += chunk);
        response.on('end', () => res.send(data));
    });
});

// A1: Broken Object Level Authorization
app.get('/user/:id', (req, res) => {
    // No ownership verification
    res.send(`Data for user ${req.params.id}`);
});

// A8: Command Injection
app.post('/run', (req, res) => {
    const cmd = req.body.command;
    child_process.exec(cmd, (error, stdout) => {  // Unsafe command execution
        res.send(stdout);
    });
});

// A9: Missing Logging
app.get('/critical', (req, res) => {
    // No audit log for critical action
    res.send("Critical operation performed");
});

app.listen(3000, () => console.log('Server running'));