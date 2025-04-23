addEventListener('fetch', event => {
  event.respondWith(handleRequest(event.request));
});

/**
 * Handle incoming requests
 * @param {Request} request - The incoming request
 * @returns {Response} The redirect response
 */
async function handleRequest(request) {
  // Start performance measurement
  const startTime = Date.now();
  
  try {
    // Parse the URL and get the 'id' parameter
    const url = new URL(request.url);
    const base64Value = url.searchParams.get('id');
    
    // Set default redirect to kengster.org
    let redirectUrl = 'https://kengster.org';
    
    // Only process if id parameter exists and isn't empty
    if (base64Value && base64Value.length > 0) {
      try {
        // Decode the Base64 string
        const decodedValue = atob(base64Value);
        
        // Basic URL validation (must start with http:// or https://)
        if (/^https?:\/\//i.test(decodedValue)) {
          redirectUrl = decodedValue;
        }
      } catch (error) {
        // Invalid Base64 - use default redirect
        // No logging in high-performance path
      }
    }
    
    // Create and return the redirect response
    return new Response(null, {
      status: 303,
      headers: {
        'Location': redirectUrl,
        'Cache-Control': 'no-cache, no-store',
        'Server-Timing': `total;dur=${Date.now() - startTime}`
      }
    });
  } catch (error) {
    // Fallback for any unexpected errors
    return new Response(null, {
      status: 303,
      headers: {
        'Location': 'https://kengster.org',
        'Cache-Control': 'no-cache, no-store'
      }
    });
  }
}
