// Generate random password
function generateRandomPassword(length = 12) {
    const charset = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*';
    let password = '';
    for (let i = 0; i < length; i++) {
        password += charset.charAt(Math.floor(Math.random() * charset.length));
    }
    return password;
}

// Call Python script to generate real bcrypt hash
async function generatePasswordHash(password) {
    try {
        const response = await fetch('/hash', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ password: password })
        });
        
        if (response.ok) {
            const data = await response.json();
            return data.hash;
        } else {
            throw new Error('Failed to generate hash');
        }
    } catch (error) {
        console.error('Hashing failed:', error);
        return `$2a$12$PLACEHOLDER_HASH_FOR_${password.substring(0, 8)}_REPLACE_WITH_REAL_HASH`;
    }
}

async function generateCompleteQuery(userData) {
    const passwordHash = await generatePasswordHash(userData.password);
    
    const completeQuery = `SELECT * FROM public."user" WHERE login='${userData.login}';

INSERT INTO "public"."user" 
    ("id", "version", "login", "name", "password", "enabled", "account_expired", "account_locked", "password_expired", "email", "password_renew_hash", "preferred_language") 
VALUES 
    (nextval('hibernate_sequence'), 0, '${userData.login}', '${userData.name}', '${passwordHash}', ${userData.enabled}, false, false, false, '${userData.email}', null, '${userData.language}');

INSERT INTO "public"."user_role" 
    ("user_id", "role_id") 
VALUES 
    (lastval(), ${userData.roleId});

SELECT * FROM public."user" WHERE login='${userData.login}';`;
    
    return completeQuery;
}

function displayResults(completeQuery, password) {
    // Show credentials in login:password format
    const login = document.getElementById('login').value;
    document.getElementById('passwordDisplay').textContent = `${login}:${password}`;
    document.getElementById('completeQuery').value = completeQuery;
    
    document.getElementById('results').classList.remove('hidden');
    document.getElementById('results').scrollIntoView({ behavior: 'smooth' });
}

function copyToClipboard(text, button) {
    const doFeedback = () => {
        if (!button) return;
        const originalText = button.textContent;
        button.textContent = 'Copied!';
        button.classList.add('copied');
        setTimeout(() => {
            button.textContent = originalText;
            button.classList.remove('copied');
        }, 1500);
    };

    const useNavigator = navigator.clipboard && (window.isSecureContext || location.hostname === 'localhost');
    if (useNavigator) {
        navigator.clipboard.writeText(text).then(doFeedback).catch(err => {
            console.warn('Clipboard API failed, falling back:', err);
            fallbackCopy(text) && doFeedback();
        });
        return;
    }
    // Fallback for non-secure contexts or older browsers
    fallbackCopy(text) && doFeedback();
}

function fallbackCopy(text) {
    try {
        const ta = document.createElement('textarea');
        ta.value = text;
        // Avoid scrolling to bottom
        ta.style.position = 'fixed';
        ta.style.top = '-1000px';
        ta.style.left = '-1000px';
        document.body.appendChild(ta);
        ta.focus();
        ta.select();
        const ok = document.execCommand('copy');
        document.body.removeChild(ta);
        if (!ok) throw new Error('execCommand copy returned false');
        return true;
    } catch (e) {
        console.error('Fallback copy failed:', e);
        alert('Failed to copy to clipboard');
        return false;
    }
}

document.addEventListener('DOMContentLoaded', function() {
    const form = document.getElementById('userForm');
    const generatePasswordBtn = document.getElementById('generatePasswordBtn');
    const envSel = document.getElementById('dbEnv');
    const appSel = document.getElementById('appKey');
    
    // Generate password button handler
    generatePasswordBtn.addEventListener('click', function() {
        const generatedPassword = generateRandomPassword();
        document.getElementById('generatedPassword').value = generatedPassword;
    });
    
    form.addEventListener('submit', function(e) {
        e.preventDefault();
        
        const formData = new FormData(form);
        const password = document.getElementById('generatedPassword').value;
        
        const userData = {
            login: formData.get('login'),
            name: formData.get('name'),
            email: formData.get('email'),
            password: password,
            enabled: formData.get('enabled') === 'true',
            language: formData.get('language').toUpperCase(),
            roleId: formData.get('roleId')
        };
        
        generateCompleteQuery(userData).then(completeQuery => {
            displayResults(completeQuery, password);
        });
    });
    
    // Add copy button functionality
    document.addEventListener('click', function(e) {
        if (e.target.classList.contains('copy-btn') || e.target.classList.contains('copy-btn-inline')) {
            e.preventDefault();
            e.stopPropagation();
            const targetId = e.target.getAttribute('data-target');
            let textToCopy;
            
            if (targetId === 'passwordDisplay') {
                textToCopy = document.getElementById(targetId).textContent;
            } else {
                textToCopy = document.getElementById(targetId).value;
            }
            
            copyToClipboard(textToCopy, e.target);
        }
    });

    // Trigger new password + query on environment selection
    if (envSel) {
        envSel.addEventListener('change', async function() {
            await regenerateForEnvSelection();
        });
    }
    // Optional: also regenerate when app changes (after env list updates, inline script dispatches env change)
    if (appSel) {
        appSel.addEventListener('change', async function() {
            // Do nothing here; env change will trigger regeneration
        });
    }
    
    // Send to Database button functionality
    const sendToDbBtn = document.getElementById('sendToDbBtn');
    if (sendToDbBtn) {
        sendToDbBtn.addEventListener('click', async function() {
            const query = document.getElementById('completeQuery').value;
            
            if (!query.trim()) {
                showDbStatus('No query to execute. Generate a query first.', 'error');
                return;
            }
            
            sendToDbBtn.disabled = true;
            sendToDbBtn.textContent = '⏳ Creating User...';
            showDbStatus('Executing SQL query...', 'info');
            
            try {
                const login = document.getElementById('login').value;
                const result = await sendToDatabase(query, login);
                
                if (result.status === 'success') {
                    let message = `✅ User "${login}" created successfully in database!`;
                    
                    // Display user data if available
                    if (result.user) {
                        message += '\n\n' + formatUserData(result.user, result);
                    }
                    
                    showDbStatus(message, 'success');
                } else {
                    showDbStatus(`❌ Database error: ${result.message}`, 'error');
                }
            } catch (error) {
                showDbStatus(`❌ Failed to create user: ${error.message}`, 'error');
            } finally {
                sendToDbBtn.disabled = false;
                sendToDbBtn.textContent = 'Send to Database';
            }
        });
    }

    // Check user existence button
    const checkUserBtn = document.getElementById('checkUserBtn');
    if (checkUserBtn) {
        checkUserBtn.addEventListener('click', async function() {
            const appSel = document.getElementById('appKey');
            const envSel = document.getElementById('dbEnv');
            const app = appSel ? appSel.value : undefined;
            const env = envSel ? envSel.value : undefined;
            const login = document.getElementById('login').value.trim();
            const email = document.getElementById('email').value.trim();

            if (!login && !email) {
                showUserStatus('Please enter login or email to check.', 'error');
                return;
            }
            checkUserBtn.disabled = true;
            const original = checkUserBtn.textContent;
            checkUserBtn.textContent = '⏳ Checking...';
            showUserStatus('Checking user in database...', 'info');
            try {
                const result = await checkUserExists(app, env, login || undefined, email || undefined);
                if (result.status === 'success') {
                    const messages = [];
                    let hasConflict = false;

                    // Check login
                    if (login) {
                        if (result.login_check.exists) {
                            const u = result.login_check.user || {};
                            messages.push(`❌ Login "${login}" already exists: ${u.name || ''} (${u.email || ''})`);
                            hasConflict = true;
                        } else {
                            messages.push(`✅ Login "${login}" is available`);
                        }
                    }

                    // Check email
                    if (email) {
                        if (result.email_check.exists) {
                            const u = result.email_check.user || {};
                            messages.push(`❌ Email "${email}" already exists: ${u.name || ''} (${u.login || ''})`);
                            hasConflict = true;
                        } else {
                            messages.push(`✅ Email "${email}" is available`);
                        }
                    }

                    // Show combined results
                    showUserStatus(messages.join('\n'), hasConflict ? 'error' : 'success');
                } else {
                    // Handle specific error types
                    if (result.error_type === 'connection_error') {
                        showUserStatus(`🔌 ${result.message}`, 'error');
                    } else {
                        showUserStatus(`❌ Error: ${result.message || 'Unknown error'}`, 'error');
                    }
                }
            } catch (e) {
                showUserStatus(`❌ Failed: ${e.message}`, 'error');
            } finally {
                checkUserBtn.disabled = false;
                checkUserBtn.textContent = original;
            }
        });
    }
});

// Database integration functions
async function sendToDatabase(query, login) {
    try {
        const envSel = document.getElementById('dbEnv');
        const env = envSel ? envSel.value : undefined;
        const appSel = document.getElementById('appKey');
        const app = appSel ? appSel.value : undefined;
        const response = await fetch('/api/db/execute', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ 
                query: query,
                login: login,
                app: app,
                env: env
            })
        });
        
        const data = await response.json();
        return data;
    } catch (error) {
        console.error('Database error:', error);
        throw error;
    }
}

function showDbStatus(message, type = 'info') {
    const statusDiv = document.getElementById('dbStatus');
    statusDiv.className = `db-status ${type}`;
    statusDiv.innerHTML = message;
}

function showUserStatus(message, type = 'info') {
    const statusDiv = document.getElementById('userCheckStatus');
    if (!statusDiv) return;
    statusDiv.className = `db-status ${type}`;
    statusDiv.innerHTML = message.replace(/\n/g, '<br>');
}

async function checkUserExists(app, env, login, email) {
    const res = await fetch('/api/db/user_exists', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ app, env, login, email })
    });
    if (!res.ok) {
        const txt = await res.text();
        throw new Error(`HTTP ${res.status}: ${txt}`);
    }
    return res.json();
}

function getUserDataFromForm(passwordOverride) {
    const form = document.getElementById('userForm');
    const formData = new FormData(form);
    return {
        login: formData.get('login'),
        name: formData.get('name'),
        email: formData.get('email'),
        password: passwordOverride ?? document.getElementById('generatedPassword').value,
        enabled: formData.get('enabled') === 'true',
        language: (formData.get('language') || '').toUpperCase(),
        roleId: formData.get('roleId')
    };
}

async function regenerateForEnvSelection() {
    // Always create a fresh password on env change
    const newPassword = generateRandomPassword();
    const passInput = document.getElementById('generatedPassword');
    if (passInput) passInput.value = newPassword;

    // If the main fields are present, regenerate the SQL preview
    const userData = getUserDataFromForm(newPassword);
    if (userData.login && userData.name && userData.email) {
        try {
            const completeQuery = await generateCompleteQuery(userData);
            displayResults(completeQuery, newPassword);
        } catch (e) {
            console.warn('Failed to regenerate query on env change:', e);
        }
    }
}

function formatUserData(user, result) {
    const formatDate = (dateStr) => {
        if (!dateStr) return 'N/A';
        return new Date(dateStr).toLocaleString();
    };

    const renderDetail = (key, value) => `
        <div class="detail-item">
            <span class="detail-key">${key}</span>
            <span class="detail-value">${value}</span>
        </div>`;

    const auditInfo = result ? `
        <div class="detail-section">
            <h4 class="detail-header">Result</h4>
            <div class="detail-grid">
                ${renderDetail('Application:', result.app || 'N/A')}
                ${renderDetail('Environment:', result.env || 'N/A')}
                ${renderDetail('Database:', result.database || 'N/A')}
                ${renderDetail('Host:', `${result.host || 'N/A'}:${result.port || '5432'}`)}
                ${renderDetail('Timestamp:', new Date().toLocaleString())}
            </div>
        </div>` : '';

    const userInfo = `
        <div class="detail-section">
            <h4 class="detail-header">Created User Details</h4>
            <div class="detail-grid">
                ${renderDetail('ID:', user.id || 'N/A')}
                ${renderDetail('Login:', user.login || 'N/A')}
                ${renderDetail('Name:', user.name || 'N/A')}
                ${renderDetail('Email:', user.email || 'N/A')}
                ${renderDetail('Enabled:', user.enabled ? 'Yes' : 'No')}
                ${renderDetail('Language:', user.preferred_language || 'N/A')}
                ${renderDetail('Created:', formatDate(user.created_at))}
            </div>
        </div>`;

    return `${auditInfo}${userInfo}`;
}
