document.getElementById('generateKeys').addEventListener('click', async () => {
    try {
        const response = await fetch('/generate-keys', {
            method: 'POST'
        });
        const data = await response.json();
        
        document.getElementById('privateKey').textContent = data.private_key;
        document.getElementById('publicKey').textContent = data.public_key;
        document.getElementById('keyOutput').classList.remove('d-none');
    } catch (error) {
        alert('Error generating keys: ' + error.message);
    }
});

function copyToClipboard(elementId) {
    const text = document.getElementById(elementId).textContent;
    navigator.clipboard.writeText(text)
        .then(() => alert('Copied to clipboard!'))
        .catch(err => alert('Error copying text: ' + err));
}

document.getElementById('encryptForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    
    const formData = new FormData();
    formData.append('file', document.getElementById('encryptFile').files[0]);
    formData.append('private_key', document.getElementById('encryptKey').value);
    
    try {
        const response = await fetch('/encrypt', {
            method: 'POST',
            body: formData
        });
        
        if (response.ok) {
            const blob = await response.blob();
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = 'encrypted_' + document.getElementById('encryptFile').files[0].name;
            document.body.appendChild(a);
            a.click();
            window.URL.revokeObjectURL(url);
            a.remove();
        } else {
            const error = await response.json();
            throw new Error(error.error);
        }
    } catch (error) {
        alert('Error encrypting file: ' + error.message);
    }
});

document.getElementById('decryptForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    
    const file = document.getElementById('decryptFile').files[0];
    const publicKey = document.getElementById('decryptKey').value;
    
    if (!file || !publicKey) {
        alert('Please select a file and enter the public key');
        return;
    }
    
    const formData = new FormData();
    formData.append('file', file);
    formData.append('public_key', publicKey.trim());
    
    try {
        const response = await fetch('/decrypt', {
            method: 'POST',
            body: formData
        });
        
        if (response.ok) {
            const blob = await response.blob();
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = 'decrypted_' + file.name;
            document.body.appendChild(a);
            a.click();
            window.URL.revokeObjectURL(url);
            a.remove();
        } else {
            const error = await response.json();
            throw new Error(error.error || 'Failed to decrypt file');
        }
    } catch (error) {
        alert('Error decrypting file: ' + error.message);
    }
});
