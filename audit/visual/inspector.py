"""In-page visual inspection.

One JavaScript pass that measures how the page actually looks:
typography, colour contrast, palette, above-the-fold content, image
quality, overlapping elements and intrusive overlays.
"""

INSPECT_JS = r"""
() => {
  const vw = window.innerWidth;
  const vh = window.innerHeight;

  const parse = (c) => {
    const m = c && c.match(/rgba?\(([^)]+)\)/);
    if (!m) return null;
    const p = m[1].split(",").map((v) => parseFloat(v));
    return { r: p[0], g: p[1], b: p[2], a: p.length > 3 ? p[3] : 1 };
  };

  const lum = (c) => {
    const f = (v) => {
      v /= 255;
      return v <= 0.03928 ? v / 12.92 : Math.pow((v + 0.055) / 1.055, 2.4);
    };
    return 0.2126 * f(c.r) + 0.7152 * f(c.g) + 0.0722 * f(c.b);
  };

  const ratio = (a, b) => {
    const l1 = lum(a), l2 = lum(b);
    return (Math.max(l1, l2) + 0.05) / (Math.min(l1, l2) + 0.05);
  };

  const blend = (top, bottom) => ({
    r: top.r * top.a + bottom.r * (1 - top.a),
    g: top.g * top.a + bottom.g * (1 - top.a),
    b: top.b * top.a + bottom.b * (1 - top.a),
    a: 1,
  });

  // Effective background; null when an image/gradient makes it unknowable.
  const background = (el) => {
    const stack = [];
    let node = el;
    while (node && node.nodeType === 1) {
      const cs = getComputedStyle(node);
      if (cs.backgroundImage && cs.backgroundImage !== "none") return null;
      const bg = parse(cs.backgroundColor);
      if (bg && bg.a > 0) {
        stack.push(bg);
        if (bg.a >= 1) break;
      }
      node = node.parentElement;
    }
    let base = { r: 255, g: 255, b: 255, a: 1 };
    for (let i = stack.length - 1; i >= 0; i--) base = blend(stack[i], base);
    return base;
  };

  const visible = (el) => {
    const cs = getComputedStyle(el);
    if (cs.display === "none" || cs.visibility === "hidden") return false;
    if (parseFloat(cs.opacity) === 0) return false;
    const r = el.getBoundingClientRect();
    return r.width > 1 && r.height > 1;
  };

  const sel = (el) => {
    if (el.id) return "#" + el.id;
    let s = el.tagName.toLowerCase();
    if (el.classList.length) s += "." + [...el.classList].slice(0, 2).join(".");
    return s;
  };

  const out = {
    viewport: { width: vw, height: vh },
    scroll: {
      width: document.documentElement.scrollWidth,
      height: document.documentElement.scrollHeight,
    },
    fonts: {},
    sizes: {},
    textColors: {},
    bgColors: {},
    smallText: [],
    lowContrast: [],
    contrastChecked: 0,
    longLines: [],
    brokenImages: [],
    upscaledImages: [],
    distortedImages: [],
    overlays: [],
    overlaps: [],
    hero: {},
    textChars: 0,
    foldChars: 0,
    lineHeightTight: [],
    justified: 0,
  };

  // ---------- text walk ----------
  const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
  const seen = new Set();
  const leafBoxes = [];
  let node;
  while ((node = walker.nextNode())) {
    const text = node.textContent.trim();
    if (text.length < 2) continue;
    const el = node.parentElement;
    if (!el || seen.has(el)) continue;
    if (["SCRIPT", "STYLE", "NOSCRIPT"].includes(el.tagName)) continue;
    if (!visible(el)) continue;
    seen.add(el);

    const cs = getComputedStyle(el);
    const rect = el.getBoundingClientRect();
    const size = parseFloat(cs.fontSize);
    const family = cs.fontFamily.split(",")[0].replace(/["']/g, "").trim();
    const weight = text.length;

    out.textChars += weight;
    if (rect.top < vh && rect.bottom > 0) out.foldChars += weight;

    out.fonts[family] = (out.fonts[family] || 0) + weight;
    const sizeKey = Math.round(size);
    out.sizes[sizeKey] = (out.sizes[sizeKey] || 0) + weight;

    const fg = parse(cs.color);
    if (fg) {
      const key = `${Math.round(fg.r / 16)},${Math.round(fg.g / 16)},${Math.round(fg.b / 16)}`;
      out.textColors[key] = (out.textColors[key] || 0) + weight;
    }

    if (size < 12 && out.smallText.length < 8)
      out.smallText.push(`${sel(el)} (${size}px): ${text.slice(0, 40)}`);

    // contrast
    if (fg && fg.a > 0.1) {
      const bg = background(el);
      if (bg) {
        out.contrastChecked++;
        const fgOnBg = fg.a < 1 ? blend(fg, bg) : fg;
        const cr = ratio(fgOnBg, bg);
        const bold = parseInt(cs.fontWeight, 10) >= 700;
        const large = size >= 24 || (size >= 18.66 && bold);
        const need = large ? 3 : 4.5;
        if (cr < need && out.lowContrast.length < 40)
          out.lowContrast.push({
            selector: sel(el),
            ratio: Math.round(cr * 100) / 100,
            need,
            text: text.slice(0, 40),
          });
      }
    }

    // line length / leading on real paragraphs
    if (["P", "LI", "DIV", "SPAN"].includes(el.tagName) && text.length > 120) {
      const cpl = rect.width / (size * 0.5);
      if (cpl > 100 && out.longLines.length < 5)
        out.longLines.push(`${sel(el)} (~${Math.round(cpl)} chars/line)`);
      const lh = parseFloat(cs.lineHeight);
      if (!isNaN(lh) && lh / size < 1.2 && out.lineHeightTight.length < 5)
        out.lineHeightTight.push(`${sel(el)} (line-height ${(lh / size).toFixed(2)})`);
      if (cs.textAlign === "justify") out.justified++;
    }

    if (["H1", "H2", "H3", "A", "BUTTON", "P"].includes(el.tagName) && leafBoxes.length < 400)
      leafBoxes.push({ el, rect });
  }

  // background palette
  document.querySelectorAll("body *").forEach((el) => {
    if (!visible(el)) return;
    const bg = parse(getComputedStyle(el).backgroundColor);
    if (bg && bg.a > 0.5) {
      const key = `${Math.round(bg.r / 16)},${Math.round(bg.g / 16)},${Math.round(bg.b / 16)}`;
      out.bgColors[key] = (out.bgColors[key] || 0) + 1;
    }
  });

  // ---------- images ----------
  document.querySelectorAll("img").forEach((img) => {
    if (!visible(img)) return;
    const r = img.getBoundingClientRect();
    const name = (img.currentSrc || img.src || "").split("/").pop().slice(0, 60) || sel(img);
    if (img.complete && img.naturalWidth === 0) {
      out.brokenImages.push(name);
      return;
    }
    if (!img.naturalWidth) return;
    const dpr = window.devicePixelRatio || 1;
    if (img.naturalWidth < r.width * dpr * 0.7 && r.width > 120)
      out.upscaledImages.push(`${name} (${img.naturalWidth}px shown at ${Math.round(r.width)}px)`);
    const fit = getComputedStyle(img).objectFit;
    if (fit === "fill" || fit === "") {
      const natural = img.naturalWidth / img.naturalHeight;
      const shown = r.width / r.height;
      if (Math.abs(natural - shown) / natural > 0.12 && r.width > 60 && r.height > 60)
        out.distortedImages.push(`${name} (natural ${natural.toFixed(2)}, shown ${shown.toFixed(2)})`);
    }
  });

  // ---------- overlays / sticky blockers ----------
  document.querySelectorAll("body *").forEach((el) => {
    const cs = getComputedStyle(el);
    if (cs.position !== "fixed" && cs.position !== "sticky") return;
    if (!visible(el)) return;
    const r = el.getBoundingClientRect();
    const area = (Math.min(r.right, vw) - Math.max(r.left, 0)) *
                 (Math.min(r.bottom, vh) - Math.max(r.top, 0));
    const share = area / (vw * vh);
    if (share > 0.15)
      out.overlays.push({ selector: sel(el), share: Math.round(share * 100), position: cs.position });
  });

  // ---------- overlapping text ----------
  for (let i = 0; i < leafBoxes.length && out.overlaps.length < 6; i++) {
    for (let j = i + 1; j < leafBoxes.length; j++) {
      const a = leafBoxes[i], b = leafBoxes[j];
      if (a.el.contains(b.el) || b.el.contains(a.el)) continue;
      const x = Math.min(a.rect.right, b.rect.right) - Math.max(a.rect.left, b.rect.left);
      const y = Math.min(a.rect.bottom, b.rect.bottom) - Math.max(a.rect.top, b.rect.top);
      if (x > 8 && y > 8) {
        const smaller = Math.min(a.rect.width * a.rect.height, b.rect.width * b.rect.height);
        if ((x * y) / smaller > 0.4) {
          out.overlaps.push(`${sel(a.el)} overlaps ${sel(b.el)}`);
          break;
        }
      }
    }
  }

  // ---------- above the fold ----------
  const h1 = [...document.querySelectorAll("h1")].find(visible);
  out.hero.h1InFold = !!h1 && h1.getBoundingClientRect().top < vh;
  out.hero.h1Size = h1 ? parseFloat(getComputedStyle(h1).fontSize) : 0;

  const ctaRe = /(contact|book|buy|get|start|order|shop|call|quote|request|sign|try|demo|subscribe|learn|scopri|contatt|acquist|richied|prenota|chiama|preventiv)/i;
  const cta = [...document.querySelectorAll("a, button, input[type=submit]")].find((el) => {
    if (!visible(el)) return false;
    const r = el.getBoundingClientRect();
    if (r.top >= vh || r.bottom <= 0) return false;
    const cs = getComputedStyle(el);
    const bg = parse(cs.backgroundColor);
    const looksButton = (bg && bg.a > 0.5) || parseFloat(cs.borderTopWidth) > 0 ||
      /btn|button|cta/i.test(el.className || "");
    return looksButton && ctaRe.test(el.innerText || el.value || "");
  });
  out.hero.ctaInFold = !!cta;

  out.hero.mediaInFold = [...document.querySelectorAll("img, video, picture, svg, canvas")].some((el) => {
    if (!visible(el)) return false;
    const r = el.getBoundingClientRect();
    return r.top < vh && r.bottom > 0 && r.width > vw * 0.25 && r.height > 120;
  });

  out.hero.navLinks = document.querySelectorAll("nav a, header a").length;

  return out;
}
"""


def inspect_page(page):

    return page.evaluate(INSPECT_JS)
