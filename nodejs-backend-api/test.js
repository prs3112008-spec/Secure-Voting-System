fetch('http://localhost:5000/api/auth/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
        email: 'test@example.com',
        password: 'mypassword'
    })
})
.then(res => res.json())
.then(data => console.log('Login Response:', data))
.catch(err => console.error('Error:', err));