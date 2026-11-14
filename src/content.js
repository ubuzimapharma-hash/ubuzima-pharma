import sanitizeHtml from "sanitize-html";

const articleHtmlOptions = {
  allowedTags: [
    "a", "blockquote", "br", "caption", "div", "em", "h1", "h2", "h3", "hr", "img",
    "li", "ol", "p", "s", "span", "strong", "strike", "table", "tbody", "td", "th",
    "thead", "tr", "u", "ul"
  ],
  allowedAttributes: {
    a: ["href", "name", "target", "rel"],
    img: ["src", "alt", "width", "height"],
    ol: ["start"],
    td: ["colspan", "rowspan"],
    th: ["colspan", "rowspan"],
    "*": ["style"]
  },
  allowedStyles: {
    "*": {
      "background-color": [/^#[0-9a-f]{3,8}$/i, /^rgb\(\s*\d+\s*,\s*\d+\s*,\s*\d+\s*\)$/i],
      color: [/^#[0-9a-f]{3,8}$/i, /^rgb\(\s*\d+\s*,\s*\d+\s*,\s*\d+\s*\)$/i],
      "font-family": [/^(Arial|Georgia|Tahoma|Verdana|DM Sans|Manrope)(, ?(sans-serif|serif))?$/i],
      "font-size": [/^\d{1,2}(px|pt|em|rem|%)$/],
      "line-height": [/^(1(\.\d+)?|2)$/],
      "margin-left": [/^\d{1,3}px$/],
      "text-align": [/^(left|right|center|justify)$/],
      "text-decoration": [/^(underline|line-through)$/]
    }
  },
  allowedSchemes: ["https", "http", "mailto"],
  allowedSchemesAppliedToAttributes: ["href", "src"],
  allowProtocolRelative: false,
  transformTags: {
    a: sanitizeHtml.simpleTransform("a", { rel: "noopener noreferrer" }, true)
  }
};

export function sanitizeArticleHtml(value) {
  return sanitizeHtml(String(value || ""), articleHtmlOptions).trim();
}

export function articleHtmlHasText(value) {
  return sanitizeHtml(String(value || ""), { allowedTags: [], allowedAttributes: {} }).trim().length > 0;
}
