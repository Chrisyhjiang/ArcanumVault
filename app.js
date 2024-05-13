async function savePassword() {
    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;
    const response = await fetch('/save', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({username, password})
    });
    const data = await response.text();
    document.getElementById('output').innerText = data;
}

async function retrievePassword() {
    const username = document.getElementById('username').value;
    const response = await fetch(`/retrieve?username=${encodeURIComponent(username)}`);
    const data = await response.text();
    document.getElementById('output').innerText = data;
}
