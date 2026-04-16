// ============================================================================
// Configuration
// ============================================================================
const ENCRYPTION_KEY = 'YOUR_32_BYTE_HEX_KEY_HERE'; // Replace with your actual key
const FALLBACK_URL = 'https://lovbook.net';

// ============================================================================
// Main Request Handler
// ============================================================================
addEventListener('fetch', event => {
  event.respondWith(handleRequest(event.request));
});

async function handleRequest(request) {
  const startTime = Date.now();
  const url = new URL(request.url);

  // Handle robots.txt for Stripe bots
  if (url.pathname === '/robots.txt') {
    return handleRobotsTxt();
  }

  try {
    let redirectUrl = FALLBACK_URL;
    const encryptedHex = url.searchParams.get('id');

    if (encryptedHex) {
      try {
        // Decrypt the URL
        const decryptedUrl = await decryptAESGCM(encryptedHex, ENCRYPTION_KEY);
        if (decryptedUrl) {
          redirectUrl = decryptedUrl;
        }
      } catch (e) {
        // Decryption failed, use fallback
        console.error('Decryption error:', e);
      }
    }

    // Generate redirect page
    const htmlResponse = generateRedirectPage(redirectUrl);

    return new Response(htmlResponse, {
      status: 200,
      headers: {
        'Content-Type': 'text/html;charset=UTF-8',
        'Cache-Control': 'no-cache, no-store, must-revalidate',
        'Pragma': 'no-cache',
        'Expires': '0',
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'SAMEORIGIN',
        'Server-Timing': `total;dur=${Date.now() - startTime}`
      }
    });

  } catch (error) {
    // Fallback to main site on any error
    return new Response(null, {
      status: 303,
      headers: {
        'Location': FALLBACK_URL,
        'Cache-Control': 'no-cache, no-store'
      }
    });
  }
}

// ============================================================================
// AES-GCM Decryption
// ============================================================================
async function decryptAESGCM(encryptedHex, keyHex) {
  try {
    // Convert hex strings to Uint8Array
    const encryptedData = hexToUint8Array(encryptedHex);
    
    // Extract IV (first 12 bytes) and ciphertext
    const iv = encryptedData.slice(0, 12);
    const ciphertext = encryptedData.slice(12);
    
    // Import the key
    const keyData = hexToUint8Array(keyHex);
    const cryptoKey = await crypto.subtle.importKey(
      'raw',
      keyData,
      { name: 'AES-GCM' },
      false,
      ['decrypt']
    );
    
    // Decrypt
    const decryptedBuffer = await crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: iv
      },
      cryptoKey,
      ciphertext
    );
    
    // Convert to string
    const decoder = new TextDecoder();
    return decoder.decode(decryptedBuffer);
    
  } catch (e) {
    throw new Error('Decryption failed: ' + e.message);
  }
}

// ============================================================================
// Utility Functions
// ============================================================================
function hexToUint8Array(hexString) {
  // Remove any spaces or non-hex characters
  const cleanHex = hexString.replace(/[^0-9a-fA-F]/g, '');
  
  // Convert hex string to byte array
  const bytes = new Uint8Array(cleanHex.length / 2);
  for (let i = 0; i < cleanHex.length; i += 2) {
    bytes[i / 2] = parseInt(cleanHex.substr(i, 2), 16);
  }
  return bytes;
}

// ============================================================================
// Robots.txt Handler
// ============================================================================
function handleRobotsTxt() {
  const robotsTxt = `# Allow Stripe verification bots
User-agent: Stripe
Allow: /

# Allow all other bots
User-agent: *
Allow: /

`;

  return new Response(robotsTxt, {
    status: 200,
    headers: {
      'Content-Type': 'text/plain;charset=UTF-8',
      'Cache-Control': 'public, max-age=86400'
    }
  });
}

// ============================================================================
// HTML Page Generator
// ============================================================================
function generateRedirectPage(redirectUrl) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta name="robots" content="noindex, nofollow">
  <title>Redirecting to Secure Checkout - Lovbook</title>
  <style>
    *, *::before, *::after {
      margin: 0;
      padding: 0;
      box-sizing: border-box;
    }

    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
      background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 2rem;
      -webkit-font-smoothing: antialiased;
    }

    .card {
      background: #ffffff;
      border-radius: 20px;
      padding: 3rem 2.5rem;
      text-align: center;
      max-width: 420px;
      width: 100%;
      box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
      animation: slideUp 0.5s cubic-bezier(0.16, 1, 0.3, 1);
    }

    @keyframes slideUp {
      from {
        opacity: 0;
        transform: translateY(30px);
      }
      to {
        opacity: 1;
        transform: translateY(0);
      }
    }

    .spinner-container {
      width: 64px;
      height: 64px;
      margin: 0 auto 2rem;
      position: relative;
    }

    .spinner {
      width: 64px;
      height: 64px;
      border: 4px solid #f0f0f5;
      border-top-color: #667eea;
      border-radius: 50%;
      animation: spin 0.8s linear infinite;
    }

    @keyframes spin {
      to { transform: rotate(360deg); }
    }

    .spinner-bg {
      position: absolute;
      width: 64px;
      height: 64px;
      border-radius: 50%;
      background: linear-gradient(135deg, rgba(102, 126, 234, 0.1), rgba(118, 75, 162, 0.1));
      animation: pulse 2s ease-in-out infinite;
    }

    @keyframes pulse {
      0%, 100% { transform: scale(1); opacity: 0.5; }
      50% { transform: scale(1.1); opacity: 0.8; }
    }

    h1 {
      font-size: 24px;
      font-weight: 600;
      color: #1d1d1f;
      margin-bottom: 0.75rem;
      letter-spacing: -0.025em;
    }

    p {
      font-size: 15px;
      color: #86868b;
      line-height: 1.6;
      margin-bottom: 2rem;
    }

    .secure-badge {
      display: inline-flex;
      align-items: center;
      gap: 0.5rem;
      padding: 0.75rem 1.25rem;
      background: #f5f5f7;
      border-radius: 12px;
      font-size: 13px;
      color: #6b7280;
      font-weight: 500;
    }

    .lock-icon {
      width: 16px;
      height: 16px;
      color: #10b981;
    }

    .progress-bar {
      width: 100%;
      height: 4px;
      background: #e8e8ed;
      border-radius: 99px;
      margin-top: 2rem;
      overflow: hidden;
    }

    .progress-fill {
      height: 100%;
      background: linear-gradient(90deg, #667eea 0%, #764ba2 100%);
      border-radius: 99px;
      animation: progress 2s ease-out;
      width: 0%;
    }

    @keyframes progress {
      to { width: 100%; }
    }

    @media (max-width: 480px) {
      .card {
        padding: 2rem 1.5rem;
      }
      h1 {
        font-size: 20px;
      }
    }
  </style>
</head>
<body>
  <div class="card" role="main" aria-live="polite">
    <div class="spinner-container">
      <div class="spinner-bg"></div>
      <div class="spinner" role="status" aria-label="Loading"></div>
    </div>
    
    <h1>Redirecting to Secure Checkout</h1>
    <p>Please wait while we securely connect you to our payment processor. This will only take a moment.</p>
    
    <div class="secure-badge">
      <svg class="lock-icon" viewBox="0 0 16 16" fill="none" xmlns="http://www.w3.org/2000/svg">
        <path d="M8 1L14 3.5v5c0 3.5-2.5 6.5-6 7.5-3.5-1-6-4-6-7.5v-5L8 1z" stroke="currentColor" stroke-width="1.5" stroke-linejoin="round"/>
        <path d="M6 7.5L7.5 9L10 6.5" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>
      </svg>
      <span>Secured by Stripe</span>
    </div>
    
    <div class="progress-bar">
      <div class="progress-fill" id="progress"></div>
    </div>
  </div>

  <script>
    (function() {
      'use strict';
      
      // Natural redirect timing
      var redirectDelay = 1200;
      var redirectUrl = "${redirectUrl}";
      
      // Validate URL before redirect
      try {
        var testUrl = new URL(redirectUrl);
        
        // Smooth redirect after delay
        setTimeout(function() {
          window.location.replace(redirectUrl);
        }, redirectDelay);
        
      } catch (e) {
        // Invalid URL, redirect to fallback
        setTimeout(function() {
          window.location.replace("${FALLBACK_URL}");
        }, redirectDelay);
      }
      
    })();
  </script>
</body>
</html>`;
}