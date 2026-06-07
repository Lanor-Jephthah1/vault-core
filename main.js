// --- State ---
let masterKey = null;
let vaultData = []; // Array of entry objects
let serverSalt = null;
let serverEncryptedData = null;
let isInitializing = false;

// Filter/Search State
let currentCategory = 'all';
let searchQuery = '';

// Inactivity Timer State
let lastActivityTime = Date.now();

// --- DOM Elements ---
const lockScreen = document.getElementById('lock-screen');
const vaultScreen = document.getElementById('vault-screen');
const authForm = document.getElementById('auth-form');
const masterPasswordInput = document.getElementById('master-password');
const authError = document.getElementById('auth-error');
const lockBtn = document.getElementById('lock-btn');
const authMessage = document.getElementById('auth-message');
const resetBtn = document.getElementById('reset-btn');

const passwordsBody = document.getElementById('passwords-body');
const emptyState = document.getElementById('empty-state');
const showAddModalBtn = document.getElementById('show-add-modal-btn');
const runAuditBtn = document.getElementById('run-audit-btn');

const addModal = document.getElementById('add-modal');
const closeModalBtn = document.getElementById('close-modal-btn');
const addEntryForm = document.getElementById('add-entry-form');

// Dynamic Form Elements in Modal
const entryCategorySelect = document.getElementById('entry-category');
const groupName = document.getElementById('group-name');
const labelName = document.getElementById('label-name');
const entryName = document.getElementById('entry-name');

const groupUsername = document.getElementById('group-username');
const labelUsername = document.getElementById('label-username');
const entryUsername = document.getElementById('entry-username');

const groupCardHolder = document.getElementById('group-card-holder');
const groupCardExpiry = document.getElementById('group-card-expiry');
const groupNoteContent = document.getElementById('group-note-content');

const groupPassword = document.getElementById('group-password');
const labelPassword = document.getElementById('label-password');
const entryPassword = document.getElementById('entry-password');

// Password Generator Panel
const generateBtn = document.getElementById('generate-btn');
const generatorOptions = document.getElementById('generator-options');
const genLength = document.getElementById('gen-length');
const lengthVal = document.getElementById('length-val');
const applyGenBtn = document.getElementById('apply-gen-btn');

// Strength Meter
const strengthContainer = document.getElementById('strength-container');
const strengthBar = document.getElementById('strength-bar');
const strengthText = document.getElementById('strength-text');

// Header settings
const autoLockSelect = document.getElementById('auto-lock-select');

// Sidebar Export/Import
const exportBtn = document.getElementById('export-btn');
const importBtn = document.getElementById('import-btn');
const importFileInput = document.getElementById('import-file-input');

// Search
const searchBar = document.getElementById('search-bar');

// --- Initialization ---
async function fetchVault() {
    try {
        const res = await fetch('/api/vault');
        if (!res.ok) return false;
        const data = await res.json();
        if (data.salt && data.data) {
            serverSalt = data.salt;
            serverEncryptedData = data.data;
            return true;
        }
    } catch (e) {
        console.error("Server error", e);
    }
    return false;
}

// Initial check
fetchVault().then(exists => {
    if (!exists) {
        isInitializing = true;
        authMessage.textContent = "Welcome to VaultCore. Create a Master Password to initialize your new secure database vault.";
    } else {
        isInitializing = false;
    }
});

// --- Dynamic Modal Form Adjustment based on Category ---
entryCategorySelect.addEventListener('change', () => {
    const cat = entryCategorySelect.value;
    
    // Reset defaults
    entryUsername.required = false;
    entryPassword.required = false;
    
    groupUsername.classList.remove('hidden');
    groupPassword.classList.remove('hidden');
    groupCardHolder.classList.add('hidden');
    groupCardExpiry.classList.add('hidden');
    groupNoteContent.classList.add('hidden');
    
    labelName.textContent = "Name or URL";
    labelUsername.textContent = "Username / Email";
    labelPassword.textContent = "Password";
    
    entryName.placeholder = "e.g. GitHub or github.com";
    entryUsername.placeholder = "";
    entryPassword.placeholder = "";

    if (cat === 'login') {
        entryUsername.required = true;
        entryPassword.required = true;
    } else if (cat === 'card') {
        labelName.textContent = "Card Label (e.g. Personal Credit)";
        labelUsername.textContent = "Card Number";
        labelPassword.textContent = "CVV / PIN";
        entryName.placeholder = "e.g. Chase Visa";
        entryUsername.placeholder = "16-digit card number";
        entryPassword.placeholder = "3-4 digit code";
        entryUsername.required = true;
        entryPassword.required = true;
        
        groupCardHolder.classList.remove('hidden');
        groupCardExpiry.classList.remove('hidden');
    } else if (cat === 'note') {
        labelName.textContent = "Note Title";
        entryName.placeholder = "e.g. WiFi Password or Recovery Keys";
        groupUsername.classList.add('hidden');
        groupPassword.classList.add('hidden');
        groupNoteContent.classList.remove('hidden');
    } else if (cat === 'server') {
        labelName.textContent = "Server Name";
        labelUsername.textContent = "IP / Hostname";
        labelPassword.textContent = "Password / SSH Key";
        entryName.placeholder = "e.g. Production DB";
        entryUsername.placeholder = "e.g. 192.168.1.50";
        entryUsername.required = true;
        entryPassword.required = true;
    }
});

// Helper: Card Number Masking
function maskCardNumber(num) {
    if (!num) return '';
    const clean = num.replace(/\s+/g, '');
    if (clean.length < 4) return clean;
    return '•••• ' + clean.slice(-4);
}

// --- Master Password Strength Meter logic ---
masterPasswordInput.addEventListener('input', () => {
    if (!isInitializing) {
        strengthContainer.classList.add('hidden');
        return;
    }
    
    const pwd = masterPasswordInput.value;
    if (!pwd) {
        strengthContainer.classList.add('hidden');
        return;
    }
    
    strengthContainer.classList.remove('hidden');
    
    let score = 0;
    if (pwd.length >= 8) score++;
    if (/[A-Z]/.test(pwd)) score++;
    if (/[a-z]/.test(pwd)) score++;
    if (/[0-9]/.test(pwd)) score++;
    if (/[^A-Za-z0-9]/.test(pwd)) score++;
    
    let width = (score / 5) * 100;
    let color = 'var(--danger)';
    let label = 'Very Weak';
    
    if (score === 3 || score === 4) {
        color = 'var(--warning)';
        label = 'Medium';
    } else if (score === 5) {
        color = 'var(--accent)';
        label = 'Strong';
    } else if (score === 2) {
        color = 'var(--danger)';
        label = 'Weak';
    }
    
    strengthBar.style.width = width + '%';
    strengthBar.style.background = color;
    strengthText.textContent = `Password Strength: ${label}`;
});

// --- Authentication & Encryption ---
authForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const password = masterPasswordInput.value;
    authError.classList.add('hidden');
    
    try {
        const exists = await fetchVault();
        
        if (exists) {
            // Unlock existing vault
            const salt = CryptoUtils.base64ToBuffer(serverSalt);
            masterKey = await CryptoUtils.deriveKey(password, salt);
            
            const decryptedJson = await CryptoUtils.decryptData(masterKey, serverEncryptedData);
            vaultData = JSON.parse(decryptedJson);
        } else {
            // Create new vault
            const salt = CryptoUtils.generateRandomBytes(16);
            masterKey = await CryptoUtils.deriveKey(password, salt);
            vaultData = [];
            
            serverSalt = CryptoUtils.bufferToBase64(salt);
            await saveVault();
            isInitializing = false;
        }
        
        // Success
        masterPasswordInput.value = '';
        strengthContainer.classList.add('hidden');
        showVault();
        renderVault();
    } catch (err) {
        authError.textContent = err.message || "Invalid master password or corrupted data.";
        authError.classList.remove('hidden');
    }
});

// Reset Vault Logic (with ADMIN_KEY support)
resetBtn.addEventListener('click', async () => {
    const key = prompt("WARNING: This will permanently delete your entire encrypted vault. If you have configured an ADMIN_KEY environment variable, please enter it now to authorize deletion (leave blank otherwise):");
    if (key === null) return; // Cancelled
    
    const headers = {};
    if (key) {
        headers['X-Admin-Key'] = key;
    }
    
    try {
        const res = await fetch('/api/vault', { 
            method: 'DELETE',
            headers: headers
        });
        
        if (res.status === 401 || res.status === 403) {
            alert("Reset failed: Unauthorized. The Admin Key entered was incorrect.");
            return;
        }
        
        if (!res.ok) {
            const data = await res.json();
            throw new Error(data.error || "Server error");
        }
        
        serverSalt = null;
        serverEncryptedData = null;
        vaultData = [];
        masterKey = null;
        
        authError.classList.add('hidden');
        authMessage.textContent = "Vault completely wiped. Enter a new Master Password to initialize a fresh vault.";
        isInitializing = true;
        
        // Return to lock screen if they were logged in
        lockBtn.click();
    } catch (err) {
        alert("Reset failed: " + err.message);
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
    
    // Check if vault currently exists in backend to set isInitializing state
    fetchVault().then(exists => {
        isInitializing = !exists;
    });
});

async function saveVault() {
    if (!masterKey) return;
    const jsonStr = JSON.stringify(vaultData);
    const encrypted = await CryptoUtils.encryptData(masterKey, jsonStr);
    
    await fetch('/api/vault', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            salt: serverSalt,
            data: encrypted
        })
    });
}

// --- View Management ---
function showVault() {
    lockScreen.classList.remove('active');
    lockScreen.classList.add('hidden');
    vaultScreen.classList.remove('hidden');
    setTimeout(() => vaultScreen.classList.add('active'), 10);
    resetInactivityTimer();
}

// --- Rendering Vault ---
function renderVault() {
    passwordsBody.innerHTML = '';
    
    // Map entries to their original index for correct mutations (copy/delete)
    let filteredEntries = vaultData.map((entry, originalIndex) => ({ ...entry, originalIndex }));
    
    // Filter by category
    if (currentCategory !== 'all') {
        filteredEntries = filteredEntries.filter(e => (e.category || 'login') === currentCategory);
    }
    
    // Filter by search query
    if (searchQuery.trim() !== '') {
        const q = searchQuery.toLowerCase();
        filteredEntries = filteredEntries.filter(e => 
            (e.name && e.name.toLowerCase().includes(q)) || 
            (e.username && e.username.toLowerCase().includes(q))
        );
    }
    
    if (filteredEntries.length === 0) {
        emptyState.classList.remove('hidden');
        document.getElementById('passwords-table').classList.add('hidden');
        return;
    }
    
    emptyState.classList.add('hidden');
    document.getElementById('passwords-table').classList.remove('hidden');
    
    filteredEntries.forEach(entry => {
        const tr = document.createElement('tr');
        const cat = entry.category || 'login';
        
        let statusHtml = '<span class="status-badge status-pending">Unchecked</span>';
        if (entry.pwned === false) {
            statusHtml = '<span class="status-badge status-safe">Safe</span>';
        } else if (entry.pwned === true) {
            statusHtml = '<span class="status-badge status-pwned">Compromised</span>';
        }
        
        const catLabel = cat.toUpperCase();
        let nameHtml = `
            <strong>${escapeHtml(entry.name)}</strong>
            <span style="font-size:0.75rem; color:var(--text-secondary); display:block;">${catLabel}</span>
        `;
        
        let usernameHtml = escapeHtml(entry.username || '');
        let pwdHtml = '••••••••';
        let actionsHtml = `
            <button class="copy-btn" data-index="${entry.originalIndex}" data-type="name">Copy URL</button>
            <button class="copy-btn" data-index="${entry.originalIndex}" data-type="username">Copy Username</button>
            <button class="copy-btn" data-index="${entry.originalIndex}" data-type="password">Copy Password</button>
            <button class="copy-btn delete-btn" style="color:var(--danger)" data-index="${entry.originalIndex}">Delete</button>
        `;
        
        if (cat === 'card') {
            usernameHtml = maskCardNumber(entry.username);
            pwdHtml = '•••';
            actionsHtml = `
                <button class="copy-btn" data-index="${entry.originalIndex}" data-type="username">Copy Card No.</button>
                <button class="copy-btn" data-index="${entry.originalIndex}" data-type="password">Copy CVV/PIN</button>
                <button class="copy-btn delete-btn" style="color:var(--danger)" data-index="${entry.originalIndex}">Delete</button>
            `;
        } else if (cat === 'note') {
            usernameHtml = '<span style="color:var(--text-secondary)">—</span>';
            pwdHtml = '••••••••';
            statusHtml = '<span class="status-badge status-safe">Secure Note</span>';
            actionsHtml = `
                <button class="copy-btn" data-index="${entry.originalIndex}" data-type="password">Copy Note</button>
                <button class="copy-btn delete-btn" style="color:var(--danger)" data-index="${entry.originalIndex}">Delete</button>
            `;
        } else if (cat === 'server') {
            actionsHtml = `
                <button class="copy-btn" data-index="${entry.originalIndex}" data-type="name">Copy Server</button>
                <button class="copy-btn" data-index="${entry.originalIndex}" data-type="username">Copy IP</button>
                <button class="copy-btn" data-index="${entry.originalIndex}" data-type="password">Copy Password</button>
                <button class="copy-btn delete-btn" style="color:var(--danger)" data-index="${entry.originalIndex}">Delete</button>
            `;
        }
        
        tr.innerHTML = `
            <td title="${escapeHtml(entry.name)}">${nameHtml}</td>
            <td title="${escapeHtml(entry.username || '')}">${usernameHtml}</td>
            <td class="pwd-cell">${pwdHtml}</td>
            <td class="status-cell">${statusHtml}</td>
            <td>${actionsHtml}</td>
        `;
        passwordsBody.appendChild(tr);
    });

    // Attach listeners
    document.querySelectorAll('.copy-btn:not(.delete-btn)').forEach(btn => {
        btn.addEventListener('click', (e) => {
            resetInactivityTimer();
            const idx = e.target.getAttribute('data-index');
            const type = e.target.getAttribute('data-type');
            
            let value = vaultData[idx].password;
            if (type === 'username') value = vaultData[idx].username;
            else if (type === 'name') {
                value = vaultData[idx].name;
                // Extract just the URL/Domain from inside the parentheses if it exists
                const urlMatch = value.match(/\(([^)]+)\)$/);
                if (urlMatch) {
                    value = urlMatch[1];
                }
            }
            
            navigator.clipboard.writeText(value);
            
            const originalText = e.target.textContent;
            e.target.textContent = "Copied!";
            setTimeout(() => e.target.textContent = originalText, 2000);
        });
    });

    document.querySelectorAll('.delete-btn').forEach(btn => {
        btn.addEventListener('click', async (e) => {
            resetInactivityTimer();
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
    resetInactivityTimer();
    addModal.classList.remove('hidden');
});

closeModalBtn.addEventListener('click', () => {
    resetInactivityTimer();
    addModal.classList.add('hidden');
    generatorOptions.classList.add('hidden');
    addEntryForm.reset();
    
    // Trigger category reset
    entryCategorySelect.value = 'login';
    entryCategorySelect.dispatchEvent(new Event('change'));
});

addEntryForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    resetInactivityTimer();
    
    const cat = entryCategorySelect.value;
    const name = entryName.value;
    
    let username = "";
    let password = "";
    let cardholder = "";
    let expiry = "";
    
    if (cat === 'login' || cat === 'server') {
        username = entryUsername.value;
        password = entryPassword.value;
    } else if (cat === 'card') {
        username = entryUsername.value; // Card Number
        password = entryPassword.value; // CVV / PIN
        cardholder = document.getElementById('entry-card-holder').value;
        expiry = document.getElementById('entry-card-expiry').value;
    } else if (cat === 'note') {
        password = document.getElementById('entry-note-content').value; // Store Note in password
    }
    
    vaultData.push({
        name, username, category: cat, password, cardholder, expiry, pwned: null
    });
    
    await saveVault();
    addModal.classList.add('hidden');
    generatorOptions.classList.add('hidden');
    addEntryForm.reset();
    
    // Reset category
    entryCategorySelect.value = 'login';
    entryCategorySelect.dispatchEvent(new Event('change'));
    
    renderVault();
});

// --- Custom Interactive Password Generator logic ---
generateBtn.addEventListener('click', (e) => {
    e.stopPropagation();
    resetInactivityTimer();
    generatorOptions.classList.toggle('hidden');
    if (!generatorOptions.classList.contains('hidden')) {
        generatePreview();
    }
});

genLength.addEventListener('input', () => {
    lengthVal.textContent = genLength.value;
    generatePreview();
});

// Regenerate live when any option toggles
['gen-upper', 'gen-lower', 'gen-digits', 'gen-symbols'].forEach(id => {
    document.getElementById(id).addEventListener('change', generatePreview);
});

applyGenBtn.addEventListener('click', () => {
    resetInactivityTimer();
    generatorOptions.classList.add('hidden');
});

function generatePreview() {
    const length = parseInt(genLength.value);
    const useUpper = document.getElementById('gen-upper').checked;
    const useLower = document.getElementById('gen-lower').checked;
    const useDigits = document.getElementById('gen-digits').checked;
    const useSymbols = document.getElementById('gen-symbols').checked;
    
    let chars = "";
    if (useUpper) chars += "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    if (useLower) chars += "abcdefghijklmnopqrstuvwxyz";
    if (useDigits) chars += "0123456789";
    if (useSymbols) chars += "!@#$%^&*()_+~`|}{[]:;?><,./-=";
    
    if (chars === "") {
        document.getElementById('entry-password').value = "";
        return;
    }
    
    let password = "";
    const randomValues = new Uint32Array(length);
    crypto.getRandomValues(randomValues);
    for (let i = 0; i < length; i++) {
        password += chars[randomValues[i] % chars.length];
    }
    
    document.getElementById('entry-password').value = password;
}

// --- Live Search ---
searchBar.addEventListener('input', () => {
    resetInactivityTimer();
    searchQuery = searchBar.value;
    renderVault();
});

// --- Category Filtering ---
document.querySelectorAll('.category-item').forEach(item => {
    item.addEventListener('click', (e) => {
        resetInactivityTimer();
        document.querySelectorAll('.category-item').forEach(i => i.classList.remove('active'));
        e.target.classList.add('active');
        currentCategory = e.target.getAttribute('data-category');
        renderVault();
    });
});

// --- Auto-Lock Mechanism ---
function resetInactivityTimer() {
    lastActivityTime = Date.now();
}

// Reset activity timer on any of these events
['mousedown', 'mousemove', 'keypress', 'scroll', 'touchstart'].forEach(evt => {
    document.addEventListener(evt, resetInactivityTimer, true);
});

// Periodic inactivity check
setInterval(() => {
    if (!masterKey) return; // Already locked
    
    const timeoutValue = autoLockSelect.value;
    if (timeoutValue === 'never') return;
    
    const timeoutMs = parseInt(timeoutValue) * 60 * 1000;
    const elapsed = Date.now() - lastActivityTime;
    
    if (elapsed >= timeoutMs) {
        lockBtn.click();
    }
}, 1000);

// Auto-lock when browser tab becomes hidden
document.addEventListener('visibilitychange', () => {
    if (document.hidden && masterKey) {
        lockBtn.click();
    }
});

// --- Encrypted Backup Export / Import ---
exportBtn.addEventListener('click', async () => {
    resetInactivityTimer();
    if (!masterKey) return;
    try {
        const jsonStr = JSON.stringify(vaultData);
        const encrypted = await CryptoUtils.encryptData(masterKey, jsonStr);
        
        const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(encrypted));
        const downloadAnchor = document.createElement('a');
        downloadAnchor.setAttribute("href", dataStr);
        downloadAnchor.setAttribute("download", "vault_backup.json");
        document.body.appendChild(downloadAnchor);
        downloadAnchor.click();
        downloadAnchor.remove();
    } catch (err) {
        alert("Export failed: " + err.message);
    }
});

importBtn.addEventListener('click', () => {
    resetInactivityTimer();
    importFileInput.click();
});

importFileInput.addEventListener('change', (e) => {
    const file = e.target.files[0];
    if (!file) return;
    
    const reader = new FileReader();
    reader.onload = async (evt) => {
        try {
            const encryptedObj = JSON.parse(evt.target.result);
            if (!encryptedObj.iv || !encryptedObj.cipherText) {
                throw new Error("Invalid backup file structure.");
            }
            
            const decryptedJson = await CryptoUtils.decryptData(masterKey, encryptedObj);
            const importedData = JSON.parse(decryptedJson);
            
            if (!Array.isArray(importedData)) {
                throw new Error("Invalid backup content.");
            }
            
            let addedCount = 0;
            importedData.forEach(imp => {
                const exists = vaultData.some(v => 
                    v.name === imp.name && 
                    v.username === imp.username && 
                    v.password === imp.password
                );
                if (!exists) {
                    vaultData.push(imp);
                    addedCount++;
                }
            });
            
            await saveVault();
            renderVault();
            alert(`Successfully imported ${addedCount} new entries!`);
        } catch (err) {
            alert("Import failed. Make sure the backup was created with the same Master Password. Error: " + err.message);
        }
        importFileInput.value = ''; // Reset
    };
    reader.readAsText(file);
});

// --- HaveIBeenPwned API Integration ---
runAuditBtn.addEventListener('click', async () => {
    resetInactivityTimer();
    runAuditBtn.textContent = "Auditing...";
    runAuditBtn.disabled = true;
    
    for (let i = 0; i < vaultData.length; i++) {
        const entry = vaultData[i];
        if (entry.category === 'note') {
            entry.pwned = false; // Notes are safe from password breach checks
            continue;
        }
        try {
            const hash = await CryptoUtils.sha1Hash(entry.password);
            const prefix = hash.substring(0, 5);
            const suffix = hash.substring(5);
            
            const response = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`);
            const text = await response.text();
            
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
