document.getElementById('generateKey').addEventListener('click', async () => {
    try {
        const response = await fetch('/generate-chacha20-key', {
            method: 'POST'
        });
        
        const data = await response.json();
        
        document.getElementById('secretKey').textContent = data.key;
        document.getElementById('nonce').textContent = data.nonce;
        document.getElementById('keyOutput').classList.remove('d-none');
    } catch (error) {
        alert('Error generating key: ' + error.message);
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
    formData.append('key', document.getElementById('encryptKey').value.trim());
    formData.append('nonce', document.getElementById('encryptNonce').value.trim());
    
    try {
        const response = await fetch('/symmetric/chacha20/encrypt', {
            method: 'POST',
            body: formData
        });
        
        if (response.ok) {
            const blob = await response.blob();
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = 'chacha20_encrypted_' + document.getElementById('encryptFile').files[0].name;
            document.body.appendChild(a);
            a.click();
            window.URL.revokeObjectURL(url);
            a.remove();
        } else {
            const error = await response.json();
            throw new Error(error.error || 'Failed to encrypt file');
        }
    } catch (error) {
        alert('Error encrypting file: ' + error.message);
    }
});

document.getElementById('decryptForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    
    const file = document.getElementById('decryptFile').files[0];
    const key = document.getElementById('decryptKey').value.trim();
    const nonce = document.getElementById('decryptNonce').value.trim();
    
    if (!file || !key || !nonce) {
        alert('Please select a file and enter the key and nonce');
        return;
    }
    
    const formData = new FormData();
    formData.append('file', file);
    formData.append('key', key);
    formData.append('nonce', nonce);
    
    try {
        const response = await fetch('/symmetric/chacha20/decrypt', {
            method: 'POST',
            body: formData
        });
        
        if (response.ok) {
            const blob = await response.blob();
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = 'decrypted_' + file.name.replace('chacha20_encrypted_', '');
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
