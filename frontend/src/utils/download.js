// Shared "save this Blob as a file" helper - the browser has no direct API for
// triggering a download from in-memory data, so this is the standard workaround
// (temporary object URL + a hidden, immediately-clicked anchor).

export function downloadBlob(blob, filename) {
  const url = window.URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.setAttribute('download', filename);
  document.body.appendChild(link);
  link.click();
  window.URL.revokeObjectURL(url);
  document.body.removeChild(link);
}

/** Extract a filename from a Content-Disposition response header, falling back if absent/malformed. */
export function filenameFromContentDisposition(contentDisposition, fallback) {
  if (!contentDisposition) return fallback;
  const matches = contentDisposition.match(/filename="(.+)"/);
  return matches ? matches[1] : fallback;
}
