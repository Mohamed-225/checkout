addEventListener('fetch', event => {
  event.respondWith(handleRequest(event.request));
});

async function handleRequest(request) {
  const startTime = Date.now();
  let redirectUrl = 'https://lovbook.net';

  try {
    const url = new URL(request.url);
    const base64Value = url.searchParams.get('id');

    if (base64Value) {
      try {
        const decodedValue = atob(base64Value);
        const targetUrl = new URL(decodedValue);
        
        if (targetUrl.hostname === 'www.mollie.com') {
          redirectUrl = decodedValue;
        }
      } catch (e) {
      }
    }

    const htmlResponse = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="referrer" content="origin">
<meta http-equiv="refresh" content="0;url=${redirectUrl}">
<title>Redirect</title>
</head>
<body>
<script>window.location.replace("${redirectUrl}");</script>
</body>
</html>`;

    return new Response(htmlResponse, {
      status: 200,
      headers: {
        'Content-Type': 'text/html;charset=UTF-8',
        'Cache-Control': 'no-cache, no-store',
        'Server-Timing': `total;dur=${Date.now() - startTime}`
      }
    });

  } catch (error) {
    return new Response(null, {
      status: 303,
      headers: {
        'Location': 'https://lovbook.net',
        'Cache-Control': 'no-cache, no-store'
      }
    });
  }
}