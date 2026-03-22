const API_BASE_URL = window.location.origin;

function getToken() {
    return localStorage.getItem('token');
}

if (getToken()) {
    window.location.href = '/';
}

document.getElementById('login-btn').addEventListener('click', async () => {
    const username = document.getElementById('username').value.trim();
    const password = document.getElementById('password').value;

    const errorDiv = document.getElementById('login-error');
    errorDiv.classList.add('hidden');

    if (!username || !password) {
        errorDiv.textContent = 'Enter username and password.';
        errorDiv.classList.remove('hidden');
        return;
    }

    try {
        const response = await fetch(`${API_BASE_URL}/api/auth/login`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ username, password })
        });

        if (!response.ok) {
            let msg = 'Login failed';
            try {
                const data = await response.json();
                msg = data.error || msg;
            } catch (e) {}
            throw new Error(msg);
        }

        const data = await response.json();
        localStorage.setItem('token', data.token);
        window.location.href = '/';
    } catch (error) {
        errorDiv.textContent = `Error: ${error.message}`;
        errorDiv.classList.remove('hidden');
    }
});

