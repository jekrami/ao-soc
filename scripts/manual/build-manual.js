/**
 * Builds the PDF and Word editions of the AO-SOC user manuals.
 *
 * Copyright (c) 2026 Ekrami-Labs. All rights reserved.
 * Written by J.Ekrami, co-written with Claude (Opus 5).
 *
 * The Markdown manual is the source of record; the PDF and the .docx are
 * generated from it and carry the same version-tagged name (§10.5), so
 * `USER-MANUAL_v1.0.md` produces `USER-MANUAL_v1.0.pdf` and
 * `USER-MANUAL_v1.0.docx` beside it. Images are embedded in both, so each
 * output is a single self-contained file.
 *
 * A manual whose Markdown opens with <div dir="rtl"> is laid out right to
 * left (the Persian edition). Code blocks and commands stay left to right.
 *
 * Usage (from this folder, after `npm install`):
 *   node build-manual.js                 build the newest version of each edition
 *                                        in docs/user-manual (older versions stay
 *                                        on disk and are not re-exported)
 *   node build-manual.js <file.md> ...   build only the given manuals
 *
 * The PDF is printed by a locally installed Edge or Chrome (no download).
 * Set BROWSER_PATH to point at a specific Chromium-based browser binary.
 */
'use strict';

const fs = require('fs');
const path = require('path');
const { pathToFileURL } = require('url');
const { marked, Marked } = require('marked');
const docx = require('docx');

const MANUAL_DIR = path.resolve(__dirname, '../../docs/user-manual');

// Page geometry — A4 with 2 cm margins.
const PAGE = { width: 11906, height: 16838, margin: 1134 };        // DXA
const CONTENT_WIDTH = PAGE.width - 2 * PAGE.margin;                 // 9638 DXA
const MAX_IMAGE_W = Math.floor((CONTENT_WIDTH / 1440) * 96);        // px at 96 dpi
const MAX_IMAGE_H = 820;                                            // px, leaves room for a caption

const ARABIC_SCRIPT = /[\u0600-\u06FF\u0750-\u077F\u08A0-\u08FF\uFB50-\uFDFF\uFE70-\uFEFF]/;

// Persian face (SIL Open Font License) \u2014 see fonts/README.md. The PDF embeds
// these files, so a Persian PDF renders identically on a machine that has no
// Persian font installed.
const FA_FONT = 'Vazirmatn';
const FA_FONT_FILES = [
  ['Vazirmatn-Regular.ttf', 400],
  ['Vazirmatn-Medium.ttf', 500],
  ['Vazirmatn-SemiBold.ttf', 600],
  ['Vazirmatn-Bold.ttf', 700],
];

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

function readManual(file) {
  const md = fs.readFileSync(file, 'utf8');
  const rtl = /^\s*<div dir="rtl">/.test(md);
  const title = (md.match(/^#\s+(.+)$/m) || [, path.basename(file, '.md')])[1].trim();
  const version = (path.basename(file).match(/_v(\d+\.\d+)\.md$/) || [, '?'])[1];
  return { file, md, rtl, title, version, dir: path.dirname(file) };
}

function pngSize(file) {
  const buf = fs.readFileSync(file);
  if (buf.toString('ascii', 1, 4) !== 'PNG') throw new Error(`Not a PNG: ${file}`);
  return { buf, width: buf.readUInt32BE(16), height: buf.readUInt32BE(20) };
}

function fitImage(width, height) {
  const scale = Math.min(1, MAX_IMAGE_W / width, MAX_IMAGE_H / height);
  return { width: Math.round(width * scale), height: Math.round(height * scale) };
}

function toPersianDigits(s) {
  return String(s).replace(/\d/g, d => '۰۱۲۳۴۵۶۷۸۹'[d]);
}

// ---------------------------------------------------------------------------
// PDF — Markdown → HTML → headless Edge/Chrome print
// ---------------------------------------------------------------------------

function htmlFor(manual) {
  // A CLI flag such as `-SkipInstall` is a legal break opportunity right after
  // its hyphen, and in an RTL line the orphaned "-" lands far from the word it
  // belongs to. A word joiner inside inline code removes those breaks.
  const md = new Marked({
    renderer: {
      // marked passes a string here in v12 and a token object from v13 on
      codespan(token) {
        const text = typeof token === 'string' ? token : token.text;
        return `<code>${text.replace(/-(?=\S)/g, '-⁠')}</code>`;
      },
    },
  });
  const body = md.parse(manual.md);
  const font = manual.rtl ? `'${FA_FONT}', Tahoma, sans-serif` : "'Segoe UI', Calibri, Arial, sans-serif";
  const faces = manual.rtl ? FA_FONT_FILES.map(([file, weight]) => `
  @font-face { font-family: '${FA_FONT}'; font-weight: ${weight}; font-style: normal;
               src: url('${pathToFileURL(path.join(__dirname, 'fonts', file)).href}') format('truetype'); }`).join('') : '';
  return `<!doctype html>
<html lang="${manual.rtl ? 'fa' : 'en'}" dir="${manual.rtl ? 'rtl' : 'ltr'}">
<head>
<meta charset="utf-8">
<base href="${pathToFileURL(manual.dir).href}/">
<title>${manual.title}</title>
<style>${faces}
  @page { size: A4; margin: 20mm 18mm 22mm; }
  body { font-family: ${font}; font-size: ${manual.rtl ? '11.5pt' : '10.5pt'};
         line-height: ${manual.rtl ? '1.85' : '1.65'}; letter-spacing: 0; color: #1b1f24; margin: 0; }
  h1 { font-size: 22pt; color: #0b3d91; border-bottom: 3px solid #0b3d91; padding-bottom: 6px; margin: 0 0 14px; }
  h2 { font-size: 15pt; color: #0b3d91; border-bottom: 1px solid #c9d3e3; padding-bottom: 4px; margin-top: 0;
       break-before: page; }
  h3 { font-size: 12.5pt; color: #13315c; margin: 18px 0 6px; break-after: avoid; }
  h4 { font-size: 11pt; color: #13315c; margin: 14px 0 4px; break-after: avoid; }
  p { margin: 6px 0; }
  hr { display: none; }
  img { display: block; max-width: 100%; max-height: 215mm; margin: 8px auto; border: 1px solid #c9d3e3;
        border-radius: 4px; break-inside: avoid; }
  table { border-collapse: collapse; width: 100%; margin: 8px 0; font-size: 9.5pt; break-inside: auto; }
  tr { break-inside: avoid; }
  thead:not(:has(th:not(:empty))) { display: none; }
  th { background: #e8eef8; color: #13315c; text-align: start; }
  th, td { border: 1px solid #c9d3e3; padding: 4px 7px; vertical-align: top; }
  /* isolate, not embed: an inline code span that starts with "-" (a CLI flag)
     otherwise loses its leading character to the surrounding RTL run */
  code { font-family: Consolas, 'Courier New', monospace; font-size: 9pt; background: #f1f3f6;
         padding: 1px 4px; border-radius: 3px; direction: ltr; unicode-bidi: isolate; }
  pre { background: #f1f3f6; border: 1px solid #dde2ea; border-radius: 4px; padding: 8px 10px;
        direction: ltr; text-align: left; white-space: pre-wrap; break-inside: avoid; }
  pre code { background: none; padding: 0; }
  blockquote { margin: 10px 0; padding: 6px 12px; background: #fff8e6; border-inline-start: 4px solid #f0a500;
               break-inside: avoid; }
  blockquote p { margin: 3px 0; }
  a { color: #0b5cd6; text-decoration: none; }
  ul, ol { padding-inline-start: 22px; margin: 6px 0; }
  li { margin: 2px 0; }
</style>
</head>
<body>${body}</body>
</html>`;
}

async function launchBrowser() {
  const { chromium } = require('playwright-core');
  if (process.env.BROWSER_PATH) return chromium.launch({ executablePath: process.env.BROWSER_PATH });
  for (const channel of ['msedge', 'chrome']) {
    try { return await chromium.launch({ channel }); } catch { /* try the next one */ }
  }
  throw new Error('No Edge or Chrome found. Install one, or set BROWSER_PATH to a Chromium-based browser.');
}

async function buildPdf(manual, browser, out) {
  const html = path.join(manual.dir, `.${path.basename(out, '.pdf')}.tmp.html`);
  fs.writeFileSync(html, htmlFor(manual));
  try {
    const page = await browser.newPage();
    await page.goto(pathToFileURL(html).href, { waitUntil: 'load' });
    const label = manual.rtl
      ? `${manual.title} · نسخهٔ ${toPersianDigits(manual.version.replace('.', '٫'))} · © J.Ekrami-Labs`
      : `${manual.title} · v${manual.version} · © J.Ekrami-Labs`;
    await page.pdf({
      path: out,
      format: 'A4',
      printBackground: true,
      displayHeaderFooter: true,
      headerTemplate: '<span></span>',
      footerTemplate: `<div style="width:100%;font-size:8px;color:#667;padding:0 18mm;display:flex;
        justify-content:space-between;direction:${manual.rtl ? 'rtl' : 'ltr'};font-family:Tahoma,'Segoe UI',sans-serif">
        <span>${label}</span><span dir="ltr"><span class="pageNumber"></span> / <span class="totalPages"></span></span></div>`,
      margin: { top: '20mm', bottom: '22mm', left: '18mm', right: '18mm' },
    });
    await page.close();
  } finally {
    fs.rmSync(html, { force: true });
  }
}

// ---------------------------------------------------------------------------
// Word — Markdown tokens → docx objects
// ---------------------------------------------------------------------------

const {
  Document, Packer, Paragraph, TextRun, ImageRun, Table, TableRow, TableCell, HeadingLevel,
  AlignmentType, WidthType, ShadingType, BorderStyle, LevelFormat, Footer, PageNumber,
} = docx;

class DocxBuilder {
  constructor(manual) {
    this.m = manual;
    this.rtl = manual.rtl;
    // Vazirmatn is the Persian face the PDF embeds; Word uses it when the
    // reader has it installed and substitutes otherwise, so Tahoma — present
    // on every Windows machine and correct for Persian — is the fallback.
    this.font = manual.rtl ? FA_FONT : 'Calibri';
    this.csFont = manual.rtl ? FA_FONT : 'Tahoma';
    this.listInstance = 0;
  }

  // One run of text. Latin text inside a right-to-left paragraph stays a
  // left-to-right run; only Arabic-script text is marked as right to left.
  run(text, style = {}) {
    const isRtl = this.rtl && ARABIC_SCRIPT.test(text);
    const mono = style.code;
    return new TextRun({
      text,
      bold: style.bold,
      italics: style.italic,
      color: style.color || (mono ? '8B1E3F' : undefined),
      size: style.size || (mono ? 18 : undefined),
      rightToLeft: isRtl,
      font: mono ? { ascii: 'Consolas', hAnsi: 'Consolas', cs: this.csFont }
                 : { ascii: this.font, hAnsi: this.font, cs: this.csFont, hint: 'cs' },
      shading: mono ? { type: ShadingType.CLEAR, fill: 'F1F3F6', color: 'auto' } : undefined,
    });
  }

  // Inline tokens → runs (text, strong, em, codespan, link, br, image).
  inline(tokens, style = {}) {
    const out = [];
    for (const t of tokens || []) {
      switch (t.type) {
        case 'strong': out.push(...this.inline(t.tokens, { ...style, bold: true })); break;
        case 'em': out.push(...this.inline(t.tokens, { ...style, italic: true })); break;
        case 'codespan': out.push(this.run(unescape(t.text), { ...style, code: true })); break;
        case 'link': out.push(...this.inline(t.tokens, { ...style, color: '0B5CD6' })); break;
        case 'br': out.push(new TextRun({ break: 1 })); break;
        case 'image': break;                              // images are handled as their own paragraph
        case 'html': break;
        case 'escape': out.push(this.run(t.text, style)); break;
        case 'text':
          if (t.tokens) out.push(...this.inline(t.tokens, style));
          else out.push(this.run(unescape(t.text), style));
          break;
        default:
          if (t.text) out.push(this.run(unescape(t.text), style));
      }
    }
    return out;
  }

  // START, never RIGHT: in a bidirectional paragraph OOXML reads RIGHT as
  // "end of text", which in RTL is the visual left.
  para(children, opts = {}) {
    return new Paragraph({
      children,
      bidirectional: this.rtl && !opts.ltr,
      alignment: this.rtl || opts.ltr ? AlignmentType.START : undefined,
      spacing: { after: opts.after ?? 100, line: this.rtl ? 330 : 300 },
      ...opts.extra,
    });
  }

  images(tokens) {
    return (tokens || []).filter(t => t.type === 'image');
  }

  imageParagraphs(images) {
    const out = [];
    for (const img of images) {
      const alt = unescape(img.text || '');
      const file = path.resolve(this.m.dir, decodeURI(img.href));
      const { buf, width, height } = pngSize(file);
      out.push(new Paragraph({
        alignment: AlignmentType.CENTER,
        keepNext: true,
        spacing: { before: 120, after: 40 },
        children: [new ImageRun({ type: 'png', data: buf, transformation: fitImage(width, height),
                                  altText: { title: alt, description: alt, name: alt } })],
      }));
      if (alt) {
        out.push(this.para([this.run(alt, { italic: true, size: 17, color: '5B6573' })],
          { after: 160, extra: { alignment: AlignmentType.CENTER } }));
      }
    }
    return out;
  }

  heading(t) {
    const level = [null, HeadingLevel.TITLE, HeadingLevel.HEADING_1, HeadingLevel.HEADING_2,
                   HeadingLevel.HEADING_3, HeadingLevel.HEADING_4][t.depth] || HeadingLevel.HEADING_4;
    return new Paragraph({
      heading: level,
      bidirectional: this.rtl,
      alignment: this.rtl ? AlignmentType.START : undefined,
      pageBreakBefore: t.depth === 2,
      keepNext: true,
      keepLines: true,
      children: this.inline(t.tokens),
    });
  }

  code(t) {
    return t.text.split('\n').map((line, i, all) => new Paragraph({
      alignment: AlignmentType.START,
      bidirectional: false,
      spacing: { before: i === 0 ? 80 : 0, after: i === all.length - 1 ? 120 : 0, line: 260 },
      shading: { type: ShadingType.CLEAR, fill: 'F1F3F6', color: 'auto' },
      keepLines: true,
      keepNext: i < all.length - 1,
      children: [new TextRun({ text: line || ' ', size: 18,
                               font: { ascii: 'Consolas', hAnsi: 'Consolas', cs: this.csFont } })],
    }));
  }

  table(t) {
    const cols = t.header.length;
    // Column widths follow the longest cell in each column, with a floor so
    // short columns (a number, a badge) still have room.
    const weight = Array.from({ length: cols }, (_, c) => Math.max(
      6, ...[t.header, ...t.rows].map(r => Math.min(60, (r[c]?.text || '').length))));
    const total = weight.reduce((a, b) => a + b, 0);
    const widths = weight.map(w => Math.floor((w / total) * CONTENT_WIDTH));
    widths[cols - 1] += CONTENT_WIDTH - widths.reduce((a, b) => a + b, 0);

    const border = { style: BorderStyle.SINGLE, size: 4, color: 'C9D3E3' };
    const cell = (c, i, header) => new TableCell({
      width: { size: widths[i], type: WidthType.DXA },
      shading: header ? { type: ShadingType.CLEAR, fill: 'E8EEF8', color: 'auto' } : undefined,
      margins: { top: 60, bottom: 60, left: 100, right: 100 },
      borders: { top: border, bottom: border, left: border, right: border },
      children: [this.para(this.inline(c.tokens, header ? { bold: true, size: 19 } : { size: 19 }), { after: 0 })],
    });
    return new Table({
      width: { size: CONTENT_WIDTH, type: WidthType.DXA },
      columnWidths: widths,
      visuallyRightToLeft: this.rtl,
      rows: [
        ...(t.header.every(c => !c.text.trim()) ? []
          : [new TableRow({ tableHeader: true, children: t.header.map((c, i) => cell(c, i, true)) })]),
        ...t.rows.map(r => new TableRow({ cantSplit: true, children: r.map((c, i) => cell(c, i, false)) })),
      ],
    });
  }

  // Word's own list numbering lives in numbering.xml, which carries no bidi:
  // in a Persian document it renders a Latin "1." on the wrong side and drags
  // in a fallback bullet font. So in RTL the marker is written as an ordinary
  // run with Persian digits; the Latin document keeps real Word lists.
  list(t, level = 0) {
    const out = [];
    const reference = t.ordered ? 'ordered' : 'bullet';
    const instance = t.ordered ? ++this.listInstance : 0;
    let index = Number(t.start || 1);
    for (const item of t.items) {
      let first = true;
      const marker = t.ordered ? `${toPersianDigits(index++)}.  ` : '•  ';
      for (const child of item.tokens) {
        if (child.type === 'list') { out.push(...this.list(child, level + 1)); continue; }
        if (child.type === 'space') continue;
        const inl = child.tokens || [{ type: 'text', text: child.text || '' }];
        const imgs = this.images(inl);
        const runs = this.inline(inl);
        if (runs.length) {
          const marked = this.rtl && first ? [this.run(marker, { bold: t.ordered }), ...runs] : runs;
          out.push(new Paragraph({
            children: marked,
            bidirectional: this.rtl,
            alignment: this.rtl ? AlignmentType.START : undefined,
            spacing: { after: 60, line: this.rtl ? 330 : 300 },
            numbering: !this.rtl && first ? { reference, level, instance } : undefined,
            indent: this.rtl ? { start: 360 * (level + 1), hanging: first ? 360 : 0 }
                             : (first ? undefined : { start: 720 * (level + 1) }),
          }));
          first = false;
        }
        out.push(...this.imageParagraphs(imgs));
      }
    }
    return out;
  }

  blockquote(t) {
    const out = [];
    for (const child of t.tokens) {
      if (child.type === 'space') continue;
      out.push(this.para(this.inline(child.tokens || [{ type: 'text', text: child.text }]), {
        after: 80,
        extra: {
          shading: { type: ShadingType.CLEAR, fill: 'FFF8E6', color: 'auto' },
          border: { [this.rtl ? 'right' : 'left']: { style: BorderStyle.SINGLE, size: 24, color: 'F0A500', space: 8 } },
          indent: { start: 200, end: 200 },
        },
      }));
    }
    return out;
  }

  blocks(tokens) {
    const out = [];
    for (const t of tokens) {
      switch (t.type) {
        case 'heading': out.push(this.heading(t)); break;
        case 'paragraph': {
          const imgs = this.images(t.tokens);
          const runs = this.inline(t.tokens);
          const textLeft = runs.length && t.tokens.some(x => x.type !== 'image' && (x.text || '').trim());
          if (textLeft) out.push(this.para(runs));
          out.push(...this.imageParagraphs(imgs));
          break;
        }
        case 'code': out.push(...this.code(t)); break;
        case 'table': out.push(this.table(t), this.para([], { after: 120 })); break;
        case 'list': out.push(...this.list(t)); break;
        case 'blockquote': out.push(...this.blockquote(t)); break;
        case 'hr': case 'space': case 'html': break;       // <div dir> wrappers and rules
        default: if (t.text) out.push(this.para([this.run(t.text)]));
      }
    }
    return out;
  }

  document() {
    const tokens = marked.lexer(this.m.md);
    const footerText = this.rtl
      ? `${this.m.title} · نسخهٔ ${toPersianDigits(this.m.version.replace('.', '٫'))} · © J.Ekrami-Labs`
      : `${this.m.title} · v${this.m.version} · © J.Ekrami-Labs`;
    const headingStyle = (id, size, color, before, after) => ({
      id, name: id, basedOn: 'Normal', next: 'Normal', quickFormat: true,
      run: { size, bold: true, color, font: { ascii: this.font, hAnsi: this.font, cs: this.csFont, hint: 'cs' },
             sizeComplexScript: size, boldComplexScript: true },
      paragraph: { spacing: { before, after } },
    });
    return new Document({
      creator: 'J.Ekrami',
      title: this.m.title,
      description: `Generated from ${path.basename(this.m.file)} by scripts/manual/build-manual.js`,
      styles: {
        default: {
          document: {
            run: { size: 21, font: { ascii: this.font, hAnsi: this.font, cs: this.csFont, hint: 'cs' },
                   sizeComplexScript: 21, rightToLeft: this.rtl },
            paragraph: { bidirectional: this.rtl, alignment: this.rtl ? AlignmentType.START : undefined },
          },
        },
        paragraphStyles: [
          headingStyle('Title', 44, '0B3D91', 0, 240),
          headingStyle('Heading1', 32, '0B3D91', 0, 200),
          headingStyle('Heading2', 26, '13315C', 280, 120),
          headingStyle('Heading3', 23, '13315C', 220, 100),
          headingStyle('Heading4', 22, '13315C', 180, 80),
        ],
      },
      numbering: {
        config: [
          { reference: 'bullet', levels: [0, 1, 2].map(level => ({
              level, format: LevelFormat.BULLET, text: ['•', '◦', '▪'][level], alignment: AlignmentType.START,
              style: { paragraph: { indent: { start: 360 * (level + 1) + 360, hanging: 360 } } } })) },
          { reference: 'ordered', levels: [0, 1, 2].map(level => ({
              level, format: LevelFormat.DECIMAL,
              text: `%${level + 1}.`, alignment: AlignmentType.START,
              style: { paragraph: { indent: { start: 360 * (level + 1) + 360, hanging: 360 } } } })) },
        ],
      },
      sections: [{
        properties: {
          page: { size: { width: PAGE.width, height: PAGE.height },
                  margin: { top: PAGE.margin, bottom: PAGE.margin, left: PAGE.margin, right: PAGE.margin } },
        },
        footers: {
          default: new Footer({
            children: [new Paragraph({
              bidirectional: this.rtl,
              alignment: AlignmentType.CENTER,
              children: [
                this.run(`${footerText} · `, { size: 16, color: '667788' }),
                new TextRun({ children: [PageNumber.CURRENT], size: 16, color: '667788' }),
              ],
            })],
          }),
        },
        children: this.blocks(tokens),
      }],
    });
  }
}

function unescape(s) {
  return String(s)
    .replace(/&amp;/g, '&').replace(/&lt;/g, '<').replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"').replace(/&#39;/g, "'");
}

/**
 * docx-js writes its own Heading1–3 styles (Word's template blue) beside the
 * ones defined here, leaving two definitions of the same styleId in
 * styles.xml. Keep the last definition of each — ours — and drop the earlier
 * duplicate, so the heading a reader sees is the heading this file describes.
 */
function dropDuplicateStyles(xml) {
  const seen = new Map();
  const re = /<w:style\b[^>]*w:styleId="([^"]+)"[\s\S]*?<\/w:style>/g;
  for (let m; (m = re.exec(xml));) {
    const list = seen.get(m[1]) || [];
    list.push(m[0]);
    seen.set(m[1], list);
  }
  let out = xml;
  for (const [, list] of seen) {
    for (const dup of list.slice(0, -1)) out = out.replace(dup, '');
  }
  return out;
}

/**
 * docx-js has no section-level `bidi` option, so the flag never reaches the
 * XML. Without it, anything that carries no direction of its own — a table
 * added later, a renderer's default — falls back to left-to-right. OOXML
 * requires <w:bidi/> to be the FIRST child of <w:sectPr>; appended anywhere
 * else it is ignored. The guard makes this safe to run twice.
 */
async function postProcessDocx(buffer, { rtl }) {
  const JSZip = require('jszip');
  const zip = await JSZip.loadAsync(buffer);
  const name = 'word/document.xml';
  const xml = await zip.file(name).async('string');
  const patched = rtl ? xml.replace(/(<w:sectPr[^>]*>)(?!<w:bidi\/>)/g, '$1<w:bidi/>') : xml;
  const styles = dropDuplicateStyles(await zip.file('word/styles.xml').async('string'));

  // Rebuild rather than re-serialise in place: [Content_Types].xml must be the
  // FIRST entry in the archive or Word can refuse the whole package, and a
  // plain regenerate does not guarantee that order.
  const out = new JSZip();
  const names = Object.keys(zip.files).filter(n => !zip.files[n].dir);
  const ordered = ['[Content_Types].xml', ...names.filter(n => n !== '[Content_Types].xml')];
  for (const n of ordered) {
    if (n === name) out.file(n, patched);
    else if (n === 'word/styles.xml') out.file(n, styles);
    else out.file(n, await zip.file(n).async('nodebuffer'));
  }
  return {
    buffer: await out.generateAsync({ type: 'nodebuffer', compression: 'DEFLATE' }),
    sections: (patched.match(/<w:bidi\/>/g) || []).length,
  };
}

async function buildDocx(manual, out) {
  const packed = await Packer.toBuffer(new DocxBuilder(manual).document());
  const { buffer } = await postProcessDocx(packed, { rtl: manual.rtl });
  fs.writeFileSync(out, buffer);
}

// ---------------------------------------------------------------------------

// The newest version of each edition (USER-MANUAL, USER-MANUAL-fa, …). Older
// versions stay on disk as the record of what was published; only the
// current one is exported.
function latestManuals() {
  const newest = new Map();
  for (const f of fs.readdirSync(MANUAL_DIR)) {
    const m = f.match(/^(USER-MANUAL.*)_v(\d+)\.(\d+)\.md$/);
    if (!m) continue;
    const rank = Number(m[2]) * 1000 + Number(m[3]);
    if (!newest.has(m[1]) || newest.get(m[1]).rank < rank) newest.set(m[1], { rank, file: path.join(MANUAL_DIR, f) });
  }
  return [...newest.values()].map(v => v.file);
}

async function main() {
  const args = process.argv.slice(2);
  const files = args.length ? args.map(f => path.resolve(f)) : latestManuals();
  if (!files.length) throw new Error(`No USER-MANUAL*_vX.Y.md found in ${MANUAL_DIR}`);

  const browser = await launchBrowser();
  try {
    for (const file of files) {
      const manual = readManual(file);
      const base = file.replace(/\.md$/, '');
      await buildPdf(manual, browser, `${base}.pdf`);
      await buildDocx(manual, `${base}.docx`);
      for (const ext of ['pdf', 'docx']) {
        const kb = Math.round(fs.statSync(`${base}.${ext}`).size / 1024);
        console.log(`${path.basename(base)}.${ext}  ${kb} KB${manual.rtl ? '  (RTL)' : ''}`);
      }
    }
  } finally {
    await browser.close();
  }
}

main().catch(err => { console.error(err); process.exit(1); });
