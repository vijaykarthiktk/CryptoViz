function copyToClipboard(elementId) {
    const text = document.getElementById(elementId).textContent;
    navigator.clipboard.writeText(text)
        .then(() => alert('Copied to clipboard!'))
        .catch(err => alert('Error copying text: ' + err));
}

document.getElementById('hashForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    
    const password = document.getElementById('passwordInput').value;
    const variant = document.getElementById('variant').value;
    const memoryCost = document.getElementById('memoryCost').value;
    const timeCost = document.getElementById('timeCost').value;
    const parallelism = document.getElementById('parallelism').value;
    
    try {
        const response = await fetch('/hash/argon2/generate', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ 
                password: password,
                variant: variant,
                memory_cost: memoryCost,
                time_cost: timeCost,
                parallelism: parallelism
            })
        });
        
        const data = await response.json();
        
        document.getElementById('hashValue').textContent = data.hash;
        document.getElementById('hashResult').classList.remove('d-none');
    } catch (error) {
        alert('Error generating hash: ' + error.message);
    }
});

document.getElementById('verifyForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    
    const password = document.getElementById('verifyPassword').value;
    const hash = document.getElementById('verifyHash').value;
    
    try {
        const response = await fetch('/hash/argon2/verify', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ 
                password: password,
                hash: hash
            })
        });
        
        const data = await response.json();
        const verifyAlert = document.getElementById('verifyAlert');
        
        if (data.match) {
            verifyAlert.className = 'alert alert-success';
            verifyAlert.textContent = 'Password matches the hash! Authentication successful.';
        } else {
            verifyAlert.className = 'alert alert-danger';
            verifyAlert.textContent = 'Password does not match the hash. Authentication failed.';
        }
        
        document.getElementById('verifyResult').classList.remove('d-none');
    } catch (error) {
        alert('Error verifying password: ' + error.message);
    }
});
