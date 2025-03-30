document.addEventListener('DOMContentLoaded', function() {
    // Handle single key addition
    const addKeyForm = document.getElementById('addKeyForm');
    if (addKeyForm) {
        addKeyForm.addEventListener('submit', async function(e) {
            e.preventDefault();
            const formData = new FormData(this);
            
            try {
                const response = await fetch('/admin/add_key', {
                    method: 'POST',
                    body: formData
                });
                
                const data = await response.json();
                if (response.ok) {
                    alert('Key added successfully!');
                    location.reload();
                } else {
                    alert(data.error || 'Error adding key');
                }
            } catch (error) {
                alert('Error adding key');
            }
        });
    }

    // Handle bulk keys addition
    const addBulkKeysForm = document.getElementById('addBulkKeysForm');
    if (addBulkKeysForm) {
        addBulkKeysForm.addEventListener('submit', async function(e) {
            e.preventDefault();
            const formData = new FormData(this);
            
            try {
                const response = await fetch('/admin/add_bulk_keys', {
                    method: 'POST',
                    body: formData
                });
                
                const data = await response.json();
                if (response.ok) {
                    alert('Keys added successfully!');
                    location.reload();
                } else {
                    alert(data.error || 'Error adding keys');
                }
            } catch (error) {
                alert('Error adding keys');
            }
        });
    }

    // Handle key purchases
    const buyButtons = document.querySelectorAll('.buy-key');
    const keyModal = new bootstrap.Modal(document.getElementById('keyModal'));
    
    buyButtons.forEach(button => {
        button.addEventListener('click', async function() {
            const keyId = this.dataset.keyId;
            
            try {
                const response = await fetch(`/buy/${keyId}`, {
                    method: 'POST'
                });
                
                const data = await response.json();
                if (response.ok) {
                    document.getElementById('keyDisplay').textContent = data.key;
                    keyModal.show();
                    setTimeout(() => location.reload(), 3000);
                } else {
                    alert(data.error || 'Error purchasing key');
                }
            } catch (error) {
                alert('Error purchasing key');
            }
        });
    });
}); 