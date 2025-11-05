/**
 * AI Text Extraction functionality using our Python script
 * Calls the backend AI extractor to parse user info
 */

/**
 * Call Python script to extract user information
 */
async function extractUserInfo(text) {
    try {
        // Call our Python script via a simple API endpoint
        const response = await fetch('/api/extract', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ text: text })
        });

        if (!response.ok) {
            throw new Error(`Server returned ${response.status}`);
        }

        const data = await response.json();
        return data;
    } catch (error) {
        console.error('Error calling extraction API:', error);
        throw error;
    }
}

/**
 * Fill the form with extracted data
 */
function fillForm(data) {
    if (data.login) {
        document.getElementById('login').value = data.login;
    }
    if (data.full_name) {
        document.getElementById('name').value = data.full_name;
    }
    if (data.email) {
        document.getElementById('email').value = data.email;
    }
}

/**
 * Show status message
 */
function showStatus(message, type = 'info') {
    const statusDiv = document.getElementById('extractionStatus');
    statusDiv.className = `extraction-status ${type}`;
    statusDiv.textContent = message;
    statusDiv.style.display = 'block';
    
    if (type === 'success') {
        setTimeout(() => {
            statusDiv.style.display = 'none';
        }, 3000);
    }
}

// Event listeners
document.addEventListener('DOMContentLoaded', function() {
    const extractBtn = document.getElementById('extractBtn');
    const clearBtn = document.getElementById('clearExtractBtn');
    const extractionInput = document.getElementById('extractionInput');
    // We keep a single reference to the form so we can trigger submissions from multiple paths.
    const form = document.getElementById('userForm');

    // Extract button click
    extractBtn.addEventListener('click', async function() {
        const text = extractionInput.value.trim();
        
        if (!text) {
            showStatus('Please paste some text to extract', 'error');
            return;
        }

        extractBtn.disabled = true;
        extractBtn.textContent = '⏳ Extracting...';
        showStatus('Processing with AI...', 'info');

        try {
            const extracted = await extractUserInfo(text);
            fillForm(extracted);
            showStatus('✅ Data extracted successfully! Generating password...', 'success');
            
            // Auto-generate password and create query
            setTimeout(async () => {
                const password = generateRandomPassword(12);
                document.getElementById('generatedPassword').value = password;
                
                // Trigger form submission to generate query based on the freshly extracted data
                const event = new Event('submit');
                form.dispatchEvent(event);
                
                showStatus('✅ Extraction complete! Password generated and query created.', 'success');
            }, 1000);
            
        } catch (error) {
            console.error('Extraction failed:', error);
            showStatus('❌ Failed to extract data. Make sure the server is running.', 'error');
        } finally {
            extractBtn.disabled = false;
            extractBtn.textContent = '🤖 Extract with AI';
        }
    });

    // Clear button click
    clearBtn.addEventListener('click', function() {
        extractionInput.value = '';
        document.getElementById('extractionStatus').style.display = 'none';
    });

    // Allow Enter key in textarea (Shift+Enter for new line)
    extractionInput.addEventListener('keydown', function(e) {
        if (e.key === 'Enter' && !e.shiftKey) {
            e.preventDefault();
            extractBtn.click();
        }
    });
});
