function copyToClipboard(elementId) {
    const text = document.getElementById(elementId).textContent;
    navigator.clipboard.writeText(text)
        .then(() => alert('Copied to clipboard!'))
        .catch(err => alert('Error copying text: ' + err));
}

document.getElementById('textHashForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    
    const text = document.getElementById('textInput').value;
    const variant = document.getElementById('textHashVariant').value;
    const digestSize = document.getElementById('textDigestSize').value;
    const key = document.getElementById('textKey').value;
    
    try {
        const response = await fetch('/hash/blake2/text', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ 
                text: text,
                variant: variant,
                digest_size: digestSize,
                key: key || null
            })
        });
        
        const data = await response.json();
        
        document.getElementById('textHashValue').textContent = data.hash;
        document.getElementById('textHashResult').classList.remove('d-none');
    } catch (error) {
        alert('Error generating hash: ' + error.message);
    }
});

document.getElementById('fileHashForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    
    const file = document.getElementById('fileInput').files[0];
    const variant = document.getElementById('fileHashVariant').value;
    const digestSize = document.getElementById('fileDigestSize').value;
    const key = document.getElementById('fileKey').value;
    
    if (!file) {
        alert('Please select a file');
        return;
    }
    
    const formData = new FormData();
    formData.append('file', file);
    formData.append('variant', variant);
    formData.append('digest_size', digestSize);
    if (key) {
        formData.append('key', key);
    }
    
    try {
        const response = await fetch('/hash/blake2/file', {
            method: 'POST',
            body: formData
        });
        
        const data = await response.json();
        
        document.getElementById('fileHashValue').textContent = data.hash;
        document.getElementById('fileHashResult').classList.remove('d-none');
    } catch (error) {
        alert('Error generating hash: ' + error.message);
    }
});

document.getElementById('verifyHashForm').addEventListener('submit', (e) => {
    e.preventDefault();
    
    const hash1 = document.getElementById('hash1').value.trim().toLowerCase();
    const hash2 = document.getElementById('hash2').value.trim().toLowerCase();
    
    const verifyAlert = document.getElementById('verifyAlert');
    
    if (hash1 === hash2) {
        verifyAlert.className = 'alert alert-success';
        verifyAlert.textContent = 'The hashes match! This indicates the data is identical.';
    } else {
        verifyAlert.className = 'alert alert-danger';
        verifyAlert.textContent = 'The hashes do not match. This indicates the data is different.';
    }
    
    document.getElementById('verifyResult').classList.remove('d-none');
});
