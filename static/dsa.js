document.getElementById('generateKeys').addEventListener('click', async () => {
    try {
        const keySize = document.getElementById('keySize').value;
        const response = await fetch('/generate-dsa-keys', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ key_size: keySize })
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

document.getElementById('signForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    
    const formData = new FormData();
    formData.append('file', document.getElementById('signFile').files[0]);
    formData.append('private_key', document.getElementById('signKey').value);
    
    try {
        const response = await fetch('/asymmetric/dsa/sign', {
            method: 'POST',
            body: formData
        });
        
        if (response.ok) {
            const blob = await response.blob();
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = document.getElementById('signFile').files[0].name + '.sig';
            document.body.appendChild(a);
            a.click();
            window.URL.revokeObjectURL(url);
            a.remove();
        } else {
            const error = await response.json();
            throw new Error(error.error || 'Failed to sign file');
        }
    } catch (error) {
        alert('Error signing file: ' + error.message);
    }
});

document.getElementById('verifyForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    
    const formData = new FormData();
    formData.append('file', document.getElementById('verifyFile').files[0]);
    formData.append('signature', document.getElementById('signatureFile').files[0]);
    formData.append('public_key', document.getElementById('verifyKey').value);
    
    try {
        const response = await fetch('/asymmetric/dsa/verify', {
            method: 'POST',
            body: formData
        });
        
        const data = await response.json();
        const verifyAlert = document.getElementById('verifyAlert');
        
        if (data.valid) {
            verifyAlert.className = 'alert alert-success';
            verifyAlert.textContent = 'Signature is valid! The file is authentic and has not been tampered with.';
        } else {
            verifyAlert.className = 'alert alert-danger';
            verifyAlert.textContent = 'Signature verification failed! The file may have been tampered with or the wrong public key was used.';
        }
        
        document.getElementById('verifyResult').classList.remove('d-none');
    } catch (error) {
        alert('Error verifying signature: ' + error.message);
    }
});
