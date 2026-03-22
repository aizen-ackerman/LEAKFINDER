const API_BASE_URL = 'http://localhost:8080';

// Immediately ensure the user is authenticated. If not, send them to the login page.
(async function enforceAuthRedirect() {
    try {
        const token = await getAuthToken();
        if (!token) {
            console.warn('[Script] No auth token found — redirecting to /login.html');
            // Give a tiny delay so any pending network logs can flush, then redirect
            setTimeout(() => { window.location.href = '/login.html'; }, 50);
        }
    } catch (e) {
        console.error('[Script] Error while checking auth token:', e);
        setTimeout(() => { window.location.href = '/login.html'; }, 50);
    }
})();

// ============================================
// CLERK AUTHENTICATION INTEGRATION
// ============================================

// Wait for Clerk to load
async function ensureClerkLoaded() {
    let attempts = 0;
    while (!window.Clerk && attempts < 50) {
        await new Promise(r => setTimeout(r, 100));
        attempts++;
    }
    return !!window.Clerk;
}

async function getAuthToken() {
    try {
        // 1) If developer saved a mock token (fallback for offline/dev), use it
        const devToken = localStorage.getItem('dev_token');
        if (devToken) {
            console.warn('[Script] Using dev token from localStorage (development fallback)');
            return devToken;
        }

        // 2) Try Clerk client if available
        const clerkReady = await ensureClerkLoaded();
        if (!clerkReady) {
            console.warn('[Script] Clerk did not load after timeout');
            return null;
        }

        // Try to get token from Clerk session
        if (window.Clerk?.session?.getToken) {
            const token = await window.Clerk.session.getToken();
            if (token) {
                console.log('[Script] ✅ Clerk token obtained, length:', token.length);
                return token;
            }
        }

        console.warn('[Script] Clerk session not available or no token');
        return null;
    } catch (error) {
        console.error('[Script] Error getting Clerk token:', error);
        return null;
    }
}

// Helper function to build headers with auth token
async function getAuthHeaders() {
    const headers = {
        'Content-Type': 'application/json',
    };
    
    const token = await getAuthToken();
    if (token) {
        headers['Authorization'] = `Bearer ${token}`;
        console.log('[Script] ✅ Authorization header set with Clerk token');
    } else {
        console.warn('[Script] ⚠️ No auth token available - request may fail with 401');
    }
    
    return headers;
}

// ============================================

// Tab switching
document.querySelectorAll('.tab-btn').forEach(btn => {
    btn.addEventListener('click', () => {
        const tab = btn.dataset.tab;
        
        // Update buttons
        document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        
        // Update content
        document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
        document.getElementById(`${tab}-tab`).classList.add('active');
    });
});

// Scan URL
document.getElementById('scan-url-btn').addEventListener('click', () => {
    const url = document.getElementById('url-input').value.trim();
    if (!url) {
        showError('Please enter a URL');
        return;
    }
    scanUrl(url);
});

// Store original filename for display
let currentFileName = null;

// File input change handler
document.getElementById('file-input').addEventListener('change', (e) => {
    const file = e.target.files[0];
    const fileNameDisplay = document.getElementById('file-name-display');
    const fileInputText = document.getElementById('file-input-text');
    const scanBtn = document.getElementById('scan-file-btn');
    
    if (file) {
        currentFileName = file.name; // Store original filename
        fileNameDisplay.textContent = `Selected: ${file.name} (${(file.size / 1024).toFixed(2)} KB)`;
        fileNameDisplay.style.display = 'block';
        fileInputText.textContent = file.name;
        scanBtn.disabled = false;
    } else {
        currentFileName = null;
        fileNameDisplay.style.display = 'none';
        fileInputText.textContent = 'Choose File';
        scanBtn.disabled = true;
    }
});

// Scan File
document.getElementById('scan-file-btn').addEventListener('click', async () => {
    const fileInput = document.getElementById('file-input');
    const file = fileInput.files[0];
    
    if (!file) {
        showError('Please select a file to scan');
        return;
    }
    
    await scanUploadedFile(file);
});

// Enter key support
document.getElementById('url-input').addEventListener('keypress', (e) => {
    if (e.key === 'Enter') {
        document.getElementById('scan-url-btn').click();
    }
});

async function scanUrl(url) {
    showLoading(true);
    hideError();
    hideResults();

    try {
        // Add timeout to prevent hanging
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 120000); // 2 minute timeout

        const headers = await getAuthHeaders();

        console.log('[Script] Sending URL scan request to /api/scan/url');

        const response = await fetch(`${API_BASE_URL}/api/scan/url`, {
            method: 'POST',
            headers: headers,
            body: JSON.stringify({ url }),
            signal: controller.signal
        });

        clearTimeout(timeoutId);

        console.log('[Script] Response status:', response.status, response.statusText);

        if (!response.ok) {
            let errorMsg = 'Scan failed';
            try {
                const errorData = await response.json();
                errorMsg = errorData.error || errorMsg;
            } catch (e) {
                errorMsg = `HTTP ${response.status}: ${response.statusText}`;
            }
            
            // Special handling for auth errors
            if (response.status === 401) {
                errorMsg = 'Unauthorized - Please log in with Clerk first';
                console.error('[Script] 401 Unauthorized - user not authenticated');
            } else if (response.status === 403) {
                errorMsg = 'Access Forbidden - Authentication failed';
                console.error('[Script] 403 Forbidden - token validation failed');
            }
            
            throw new Error(errorMsg);
        }

        const data = await response.json();
        displayResults(data);
    } catch (error) {
        if (error.name === 'AbortError') {
            showError('Scan timed out after 2 minutes. The website may be slow or unreachable.');
        } else {
            showError(`Error: ${error.message}`);
        }
    } finally {
        showLoading(false);
    }
}

async function scanUploadedFile(file) {
    showLoading(true);
    hideError();
    hideResults();

    try {
        // Read file as base64 to avoid JSON encoding issues
        const fileContent = await readFileAsBase64(file);

        // Add timeout to prevent hanging
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 60000); // 1 minute timeout

        const headers = await getAuthHeaders();

        console.log('[Script] Sending file scan request to /api/upload/scan with headers:', Object.keys(headers));

        const response = await fetch(`${API_BASE_URL}/api/upload/scan`, {
            method: 'POST',
            headers: headers,
            body: JSON.stringify({
                fileName: file.name,
                fileContent: fileContent,
                isBase64: true
            }),
            signal: controller.signal
        });

        clearTimeout(timeoutId);

        console.log('[Script] Response status:', response.status, response.statusText);

        if (!response.ok) {
            let errorMsg = 'Scan failed';
            try {
                const errorData = await response.json();
                errorMsg = errorData.error || errorMsg;
            } catch (e) {
                errorMsg = `HTTP ${response.status}: ${response.statusText}`;
            }
            
            // Special handling for auth errors
            if (response.status === 401) {
                errorMsg = 'Unauthorized - Please log in with Clerk first';
                console.error('[Script] 401 Unauthorized - user not authenticated');
            } else if (response.status === 403) {
                errorMsg = 'Access Forbidden - Authentication failed';
                console.error('[Script] 403 Forbidden - token validation failed');
            }
            
            throw new Error(errorMsg);
        }

        const data = await response.json();
        displayResults(data);
    } catch (error) {
        if (error.name === 'AbortError') {
            showError('Scan timed out after 1 minute. The file may be too large.');
        } else {
            showError(`Error: ${error.message}`);
        }
    } finally {
        showLoading(false);
    }
}

function readFileAsBase64(file) {
    return new Promise((resolve, reject) => {
        const reader = new FileReader();
        reader.onload = (e) => {
            // Remove data URL prefix (e.g., "data:text/plain;base64,")
            const base64 = e.target.result.split(',')[1] || e.target.result;
            resolve(base64);
        };
        reader.onerror = (e) => reject(new Error('Failed to read file'));
        reader.readAsDataURL(file);
    });
}

async function scanFile(filePath) {
    showLoading(true);
    hideError();
    hideResults();

    try {
        // Add timeout to prevent hanging
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 60000); // 1 minute timeout

        const headers = await getAuthHeaders();

        console.log('[Script] Sending file path scan request to /api/scan/file');

        const response = await fetch(`${API_BASE_URL}/api/scan/file`, {
            method: 'POST',
            headers: headers,
            body: JSON.stringify({ filePath }),
            signal: controller.signal
        });

        clearTimeout(timeoutId);

        console.log('[Script] Response status:', response.status, response.statusText);

        if (!response.ok) {
            let errorMsg = 'Scan failed';
            try {
                const errorData = await response.json();
                errorMsg = errorData.error || errorMsg;
            } catch (e) {
                errorMsg = `HTTP ${response.status}: ${response.statusText}`;
            }
            
            // Special handling for auth errors
            if (response.status === 401) {
                errorMsg = 'Unauthorized - Please log in with Clerk first';
                console.error('[Script] 401 Unauthorized - user not authenticated');
            } else if (response.status === 403) {
                errorMsg = 'Access Forbidden - Authentication failed';
                console.error('[Script] 403 Forbidden - token validation failed');
            }
            
            throw new Error(errorMsg);
        }

        const data = await response.json();
        displayResults(data);
    } catch (error) {
        if (error.name === 'AbortError') {
            showError('Scan timed out after 1 minute. The file may be too large or inaccessible.');
        } else {
            showError(`Error: ${error.message}`);
        }
    } finally {
        showLoading(false);
    }
}

function displayResults(data) {
    // Update summary - use original filename if available, otherwise extract from path
    let displayName = data.url;
    if (currentFileName) {
        displayName = currentFileName;
    } else if (data.url && data.url.includes('/')) {
        // Extract filename from path
        displayName = data.url.substring(data.url.lastIndexOf('/') + 1);
        // If it's a temp file, try to get original name from URL if stored
        if (displayName.startsWith('scan_')) {
            displayName = data.url; // Fallback to full path if temp file
        }
    }
    document.getElementById('target-url').textContent = displayName;
    document.getElementById('total-checks').textContent = data.summary.total;
    document.getElementById('passed-count').textContent = data.summary.passed;
    document.getElementById('failed-count').textContent = data.summary.failed;
    document.getElementById('high-count').textContent = data.summary.high;
    document.getElementById('medium-count').textContent = data.summary.medium;
    document.getElementById('low-count').textContent = data.summary.low;

    // Display checks
    const checksList = document.getElementById('checks-list');
    checksList.innerHTML = '';

    data.checks.forEach(check => {
        const checkItem = document.createElement('div');
        checkItem.className = 'check-item';

        const status = check.passed ? 'passed' : 'failed';
        const statusText = check.passed ? '✓ PASSED' : '✗ FAILED';

        checkItem.innerHTML = `
            <div class="check-header">
                <div class="check-name">${escapeHtml(check.name)}</div>
                <div class="check-status ${status}">
                    ${statusText}
                    <span class="severity-badge ${check.severity}">${check.severity}</span>
                </div>
            </div>
            <ul class="issues-list">
                ${check.issues.map(issue => `<li class="issue-item">${escapeHtml(issue)}</li>`).join('')}
            </ul>
        `;

        checksList.appendChild(checkItem);
    });

    showResults();
}

function showLoading(show) {
    const loading = document.getElementById('loading');
    if (show) {
        loading.classList.remove('hidden');
    } else {
        loading.classList.add('hidden');
    }
}

function showResults() {
    document.getElementById('results-section').classList.remove('hidden');
    document.getElementById('results-section').scrollIntoView({ behavior: 'smooth', block: 'start' });
}

function hideResults() {
    document.getElementById('results-section').classList.add('hidden');
}

function showError(message) {
    const errorDiv = document.getElementById('error-message');
    errorDiv.textContent = message;
    errorDiv.classList.remove('hidden');
    errorDiv.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

function hideError() {
    document.getElementById('error-message').classList.add('hidden');
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}
