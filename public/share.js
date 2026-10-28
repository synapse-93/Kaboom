(async () => {
  const token = location.pathname.split('/').filter(Boolean).pop();
  const title = document.getElementById('share-title');
  const detail = document.getElementById('share-detail');
  try {
    const response = await fetch('/api/share/' + encodeURIComponent(token));
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || 'This link is unavailable.');
    title.textContent = data.name;
    detail.textContent = 'Ready to download · Expires ' + new Date(data.expiresAt).toLocaleString();
    const button = document.getElementById('download-button');
    button.href = data.downloadUrl;
    button.addEventListener('click', async event => {
      event.preventDefault();
      if (button.getAttribute('aria-disabled') === 'true') return;
      const previousText = button.textContent;
      button.textContent = 'Preparing download…';
      button.setAttribute('aria-disabled', 'true');
      button.classList.add('is-loading');
      const pieces = [];
      try {
        for (let offset = 0; offset < data.size; offset += 3 * 1024 * 1024) {
          detail.textContent = 'Downloading ' + Math.min(100, Math.round(offset / data.size * 100)) + '%…';
          const part = await fetch(data.downloadUrl + '?offset=' + offset);
          if (!part.ok) {
            const error = await part.json().catch(() => ({}));
            throw new Error(error.error || 'The download could not be completed.');
          }
          pieces.push(await part.blob());
        }
        const objectUrl = URL.createObjectURL(new Blob(pieces, { type: 'application/octet-stream' }));
        const save = document.createElement('a');
        save.href = objectUrl;
        save.download = data.name;
        document.body.append(save);
        save.click();
        save.remove();
        window.setTimeout(() => URL.revokeObjectURL(objectUrl), 60000);
        detail.textContent = 'Download ready.';
      } catch (error) {
        detail.textContent = error.message;
      } finally {
        button.textContent = previousText;
        button.removeAttribute('aria-disabled');
        button.classList.remove('is-loading');
      }
    });
    button.hidden = false;
  } catch (error) {
    title.textContent = 'Link unavailable';
    detail.textContent = error.message;
  }
})();
