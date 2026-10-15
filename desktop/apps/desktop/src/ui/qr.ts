/**
 * The daemon returns the pairing QR as an SVG string. It is rendered through an <img> with a
 * data: URL (scripts in SVG-as-image never execute, and the markup is never parsed into the page
 * DOM). The string is additionally sanity-checked and size-capped.
 */
const MAX_SVG_BYTES = 256 * 1024;

export function qrImageSrc(svg: string): string | null {
  if (svg.length === 0 || svg.length > MAX_SVG_BYTES) return null;
  if (!/^\s*(<\?xml[^>]*\?>\s*)?<svg[\s>]/i.test(svg)) return null;
  if (/<script|<foreignObject|\son[a-z]+\s*=|javascript:/i.test(svg)) return null;
  const bytes = new TextEncoder().encode(svg);
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return `data:image/svg+xml;base64,${btoa(bin)}`;
}

export function qrImage(svg: string): HTMLImageElement | null {
  const src = qrImageSrc(svg);
  if (src === null) return null;
  const img = document.createElement("img");
  img.className = "qr";
  img.setAttribute("alt", "기기 추가용 QR 코드");
  img.setAttribute("width", "240");
  img.setAttribute("height", "240");
  img.setAttribute("data-qr", "1");
  img.src = src;
  return img;
}
