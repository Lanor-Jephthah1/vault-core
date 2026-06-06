// --- State ---
let masterKey = null;
let vaultData = []; // Array of entry objects

// --- DOM Elements ---
const lockScreen = document.getElementById('lock-screen');
const vaultScreen = document.getElementById('vault-screen');
const authForm = document.getElementById('auth-form');
const masterPasswordInput = document.getElementById('master-password');
const authError = document.getElementById('auth-error');
const lockBtn = document.getElementById('lock-btn');
const authMessage = document.getElementById('auth-message');

const passwordsBody = document.getElementById('passwords-body');
const emptyState = document.getElementById('empty-state');
const showAddModalBtn = document.getElementById('show-add-modal-btn');
const runAuditBtn = document.getElementById('run-audit-btn');

const addModal = document.getElementById('add-modal');
const closeModalBtn = document.getElementById('close-modal-btn');
const addEntryForm = document.getElementById('add-entry-form');
const generateBtn = document.getElementById('generate-btn');

// --- Initialization ---
// Check if vault exists
function hasVault() {
    return localStorage.getItem('vaultcore_salt') !== null && 
           localStorage.getItem('vaultcore_data') !== null;
}

if (!hasVault()) {
    authMessage.textContent = "Welcome to VaultCore. Create a Master Password to initialize your new secure vault.";
}

// --- Authentication & Encryption ---
authForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const password = masterPasswordInput.value;
    authError.classList.add('hidden');
    
    try {
        if (hasVault()) {
            // Unlock existing vault
            const saltBase64 = localStorage.getItem('vaultcore_salt');
            const encryptedDataStr = localStorage.getItem('vaultcore_data');
            const encryptedData = JSON.parse(encryptedDataStr);
            
            const salt = CryptoUtils.base64ToBuffer(saltBase64);
            masterKey = await CryptoUtils.deriveKey(password, salt);
            
            const decryptedJson = await CryptoUtils.decryptData(masterKey, encryptedData);
            vaultData = JSON.parse(decryptedJson);
        } else {
            // Create new vault
            const salt = CryptoUtils.generateRandomBytes(16);
            masterKey = await CryptoUtils.deriveKey(password, salt);
            vaultData = [];
            
            localStorage.setItem('vaultcore_salt', CryptoUtils.bufferToBase64(salt));
            await saveVault();
        }
        
        // Success
        masterPasswordInput.value = '';
        showVault();
        renderVault();
    } catch (err) {
        authError.textContent = err.message;
        authError.classList.remove('hidden');
    }
});

lockBtn.addEventListener('click', () => {
    masterKey = null;
    vaultData = [];
    passwordsBody.innerHTML = '';
    vaultScreen.classList.remove('active');
    vaultScreen.classList.add('hidden');
    lockScreen.classList.remove('hidden');
    setTimeout(() => lockScreen.classList.add('active'), 10);
    authMessage.textContent = "Enter your Master Password to unlock your vault.";
});

async function saveVault() {
    if (!masterKey) return;
    const jsonStr = JSON.stringify(vaultData);
    const encrypted = await CryptoUtils.encryptData(masterKey, jsonStr);
    localStorage.setItem('vaultcore_data', JSON.stringify(encrypted));
}

// --- View Management ---
function showVault() {
    lockScreen.classList.remove('active');
    lockScreen.classList.add('hidden');
    vaultScreen.classList.remove('hidden');
    setTimeout(() => vaultScreen.classList.add('active'), 10);
}

// --- Rendering Vault ---
function renderVault() {
    passwordsBody.innerHTML = '';
    if (vaultData.length === 0) {
        emptyState.classList.remove('hidden');
        document.getElementById('passwords-table').classList.add('hidden');
        return;
    }
    
    emptyState.classList.add('hidden');
    document.getElementById('passwords-table').classList.remove('hidden');
    
    vaultData.forEach((entry, index) => {
        const tr = document.createElement('tr');
        
        let statusHtml = '<span class="status-badge status-pending">Unchecked</span>';
        if (entry.pwned === false) {
            statusHtml = '<span class="status-badge status-safe">Safe</span>';
        } else if (entry.pwned === true) {
            statusHtml = '<span class="status-badge status-pwned">Compromised</span>';
        }
        
        tr.innerHTML = `
            <td><strong>${escapeHtml(entry.name)}</strong></td>
            <td>${escapeHtml(entry.username)}</td>
            <td class="pwd-cell">••••••••</td>
            <td class="status-cell">${statusHtml}</td>
            <td>
                <button class="copy-btn" data-index="${index}">Copy</button>
                <button class="copy-btn delete-btn" style="color:var(--danger)" data-index="${index}">Delete</button>
            </td>
        `;
        passwordsBody.appendChild(tr);
    });

    // Attach listeners
    document.querySelectorAll('.copy-btn:not(.delete-btn)').forEach(btn => {
        btn.addEventListener('click', (e) => {
            const idx = e.target.getAttribute('data-index');
            const pwd = vaultData[idx].password;
            navigator.clipboard.writeText(pwd);
            e.target.textContent = "Copied!";
            setTimeout(() => e.target.textContent = "Copy", 2000);
        });
    });

    document.querySelectorAll('.delete-btn').forEach(btn => {
        btn.addEventListener('click', async (e) => {
            if (confirm("Are you sure you want to delete this entry?")) {
                const idx = e.target.getAttribute('data-index');
                vaultData.splice(idx, 1);
                await saveVault();
                renderVault();
            }
        });
    });
}

// --- Adding Entries ---
showAddModalBtn.addEventListener('click', () => {
    addModal.classList.remove('hidden');
});

closeModalBtn.addEventListener('click', () => {
    addModal.classList.add('hidden');
    addEntryForm.reset();
});

generateBtn.addEventListener('click', () => {
    document.getElementById('entry-password').value = CryptoUtils.generatePassword(16);
});

addEntryForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const name = document.getElementById('entry-name').value;
    const username = document.getElementById('entry-username').value;
    const password = document.getElementById('entry-password').value;
    
    vaultData.push({
        name, username, password, pwned: null
    });
    
    await saveVault();
    addModal.classList.add('hidden');
    addEntryForm.reset();
    renderVault();
});

// --- HaveIBeenPwned API Integration ---
runAuditBtn.addEventListener('click', async () => {
    runAuditBtn.textContent = "Auditing...";
    runAuditBtn.disabled = true;
    
    for (let i = 0; i < vaultData.length; i++) {
        const entry = vaultData[i];
        try {
            const hash = await CryptoUtils.sha1Hash(entry.password);
            const prefix = hash.substring(0, 5);
            const suffix = hash.substring(5);
            
            const response = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`);
            const text = await response.text();
            
            // The API returns a list of suffixes and counts
            const lines = text.split('\n');
            let isPwned = false;
            
            for (let line of lines) {
                const parts = line.split(':');
                if (parts[0] === suffix) {
                    isPwned = true;
                    break;
                }
            }
            
            entry.pwned = isPwned;
        } catch (err) {
            console.error("Audit error", err);
        }
    }
    
    await saveVault();
    renderVault();
    
    runAuditBtn.textContent = "Run Security Audit";
    runAuditBtn.disabled = false;
});

// Basic XSS escape
function escapeHtml(unsafe) {
    return unsafe
         .replace(/&/g, "&amp;")
         .replace(/</g, "&lt;")
         .replace(/>/g, "&gt;")
         .replace(/"/g, "&quot;")
         .replace(/'/g, "&#039;");
}
