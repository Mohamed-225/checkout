// ============================================================================
// Configuration
// ============================================================================
const ENCRYPTION_KEY = '10c8de5542be4a8d8a67d551f56706cb'; // Replace with your actual key
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
function getSafeRedirectTarget(candidateUrl, fallbackUrl) {
  try {
    const parsedUrl = new URL(candidateUrl);
    if (parsedUrl.protocol === 'https:' || parsedUrl.protocol === 'http:') {
      return parsedUrl.toString();
    }
  } catch (e) {
    // Ignore invalid URLs and fall back safely
  }

  return fallbackUrl;
}

function escapeHtml(value) {
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function generateRedirectPage(redirectUrl) {
  const safeFallbackUrl = getSafeRedirectTarget(FALLBACK_URL, FALLBACK_URL);
  const safeRedirectUrl = getSafeRedirectTarget(redirectUrl, safeFallbackUrl);
  const safeRedirectHref = escapeHtml(safeRedirectUrl);

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta name="robots" content="noindex, nofollow">
  <meta name="color-scheme" content="light only">
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
      color: #1f2937;
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
      color: #111827;
      margin-bottom: 0.75rem;
      letter-spacing: -0.025em;
    }

    p {
      font-size: 15px;
      color: #4b5563;
      line-height: 1.6;
      margin-bottom: 1.25rem;
    }

    .secure-badge {
      display: inline-flex;
      align-items: center;
      gap: 0.5rem;
      padding: 0.75rem 1.25rem;
      background: #f5f5f7;
      border-radius: 12px;
      font-size: 13px;
      color: #374151;
      font-weight: 600;
    }

    .lock-icon {
      width: 16px;
      height: 16px;
      color: #047857;
    }

    .manual-link {
      display: inline-block;
      margin-top: 1.5rem;
      color: #1d4ed8;
      font-weight: 600;
      text-underline-offset: 2px;
    }

    .manual-link:focus-visible {
      outline: 3px solid #1d4ed8;
      outline-offset: 3px;
      border-radius: 6px;
    }

    .progress-bar {
      width: 100%;
      height: 4px;
      background: #e5e7eb;
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

    .sr-only {
      position: absolute;
      width: 1px;
      height: 1px;
      padding: 0;
      margin: -1px;
      overflow: hidden;
      clip: rect(0, 0, 0, 0);
      white-space: nowrap;
      border: 0;
    }

    @media (prefers-reduced-motion: reduce) {
      *, *::before, *::after {
        animation-duration: 0.01ms !important;
        animation-iteration-count: 1 !important;
        transition-duration: 0.01ms !important;
        scroll-behavior: auto !important;
      }
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
  <main class="card" aria-labelledby="redirect-title">
    <div class="spinner-container" aria-hidden="true">
      <div class="spinner-bg"></div>
      <div class="spinner"></div>
    </div>

    <p class="sr-only" id="redirect-status" role="status" aria-live="polite">
      Redirecting you securely. You can also continue manually using the link below.
    </p>

    <h1 id="redirect-title">Redirecting to Secure Checkout</h1>
    <p>Please wait while we securely connect you to our payment processor. This will only take a moment.</p>

    <div class="secure-badge" aria-label="Secure checkout powered by Stripe">
      <svg class="lock-icon" viewBox="0 0 16 16" fill="none" xmlns="http://www.w3.org/2000/svg" aria-hidden="true" focusable="false">
        <path d="M8 1L14 3.5v5c0 3.5-2.5 6.5-6 7.5-3.5-1-6-4-6-7.5v-5L8 1z" stroke="currentColor" stroke-width="1.5" stroke-linejoin="round"/>
        <path d="M6 7.5L7.5 9L10 6.5" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>
      </svg>
      <span>Secured by Stripe</span>
    </div>

    <a class="manual-link" href="${safeRedirectHref}">Continue now</a>

    <div class="progress-bar" aria-hidden="true">
      <div class="progress-fill" id="progress"></div>
    </div>

    <noscript>
      <p>JavaScript is disabled. Use the link above to continue to checkout.</p>
    </noscript>
  </main>

  <script>
    (function() {
      'use strict';

      var redirectDelay = 3000;
      var redirectUrl = ${JSON.stringify(safeRedirectUrl)};
      var fallbackUrl = ${JSON.stringify(safeFallbackUrl)};
      var nextUrl = fallbackUrl;

      try {
        var parsedUrl = new URL(redirectUrl);
        if (parsedUrl.protocol === 'https:' || parsedUrl.protocol === 'http:') {
          nextUrl = parsedUrl.toString();
        }
      } catch (e) {
        nextUrl = fallbackUrl;
      }

      setTimeout(function() {
        window.location.replace(nextUrl);
      }, redirectDelay);
    })();
  </script>
</body>
</html>`;
}