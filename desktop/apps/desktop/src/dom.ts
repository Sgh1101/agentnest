/**
 * Tiny DOM builder. Text is always attached with createTextNode / textContent, so daemon- or
 * agent-provided strings can never be parsed as markup. There is intentionally no way to set
 * innerHTML, outerHTML, srcdoc, href or src through `h` (a source-scan test enforces that the
 * rest of the code base does not use them either).
 */
export type Child = Node | string | number | null | undefined | false;
export type Attr = string | number | boolean | EventListener | null | undefined;
export type Props = Record<string, Attr>;

const BLOCKED_ATTRS = new Set(["innerhtml", "outerhtml", "srcdoc", "href", "src", "style", "xlink:href", "formaction"]);

export function append(parent: Node, children: readonly Child[]): void {
  for (const c of children) {
    if (c === null || c === undefined || c === false) continue;
    parent.appendChild(typeof c === "string" || typeof c === "number" ? document.createTextNode(String(c)) : c);
  }
}

export function h<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  props?: Props | null,
  ...children: Child[]
): HTMLElementTagNameMap[K] {
  const el = document.createElement(tag);
  if (props) {
    for (const [key, value] of Object.entries(props)) {
      if (value === undefined || value === null || value === false) continue;
      if (key.length > 2 && key.startsWith("on")) {
        if (typeof value === "function") el.addEventListener(key.slice(2).toLowerCase(), value);
        continue;
      }
      if (BLOCKED_ATTRS.has(key.toLowerCase())) continue;
      if (key === "class") el.className = String(value);
      else el.setAttribute(key, value === true ? "" : String(value));
    }
  }
  append(el, children);
  return el;
}

export function clear(el: Element): void {
  while (el.firstChild) el.removeChild(el.firstChild);
}

export function replaceChildren(el: Element, children: readonly Child[]): void {
  clear(el);
  append(el, children);
}
