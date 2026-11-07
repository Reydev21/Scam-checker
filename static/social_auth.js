(function () {
  const slot = document.querySelector('.google-signin-slot');
  if (!slot) return;

  function showError(message) {
    const target = document.getElementById('social-auth-message');
    if (!target) return;
    target.textContent = message;
    target.hidden = false;
  }

  function initializeGoogleButton() {
    if (!window.google || !google.accounts || !google.accounts.id) return false;
    google.accounts.id.initialize({
      client_id: slot.dataset.clientId,
      nonce: slot.dataset.nonce,
      callback: async (response) => {
        try {
          const result = await fetch('/auth/google/credential', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            credentials: 'same-origin',
            body: JSON.stringify({
              credential: response.credential || '',
              gsi_error: response.error || '',
              gsi_error_description: response.error_description || ''
            })
          });
          const payload = await result.json();
          if (!result.ok) throw new Error(payload.error || 'Google sign-in failed.');
          window.location.assign(payload.next);
        } catch (error) {
          showError(error.message || 'Google sign-in failed. Please try again.');
        }
      }
    });
    google.accounts.id.renderButton(slot, {
      type: 'standard',
      theme: 'outline',
      size: 'large',
      text: slot.dataset.text || 'signin_with',
      shape: 'rectangular',
      width: Math.min(slot.parentElement.clientWidth || 380, 400)
    });
    return true;
  }

  const sdk = document.createElement('script');
  sdk.src = 'https://accounts.google.com/gsi/client';
  sdk.async = true;
  sdk.onload = () => {
    if (!initializeGoogleButton()) showError('Hindi ma-load ang Google Sign-In. I-refresh ang page at subukan ulit.');
  };
  sdk.onerror = () => showError('Hindi ma-load ang Google Sign-In. Tingnan ang internet connection at subukan ulit.');
  document.head.appendChild(sdk);
})();
