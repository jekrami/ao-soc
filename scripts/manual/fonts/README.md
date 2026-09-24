# Persian font for the manual builder

**Vazirmatn** by Saber Rastikerdar — <https://github.com/rastikerdar/vazirmatn>.
Licensed under the SIL Open Font License 1.1 (`OFL.txt`), which permits
embedding in documents and commercial use.

`build-manual.js` embeds these files in the Persian PDF through `@font-face`,
so the exported PDF renders correctly on a machine with no Persian font
installed. The Persian `.docx` names Vazirmatn as its font but does not carry
it: Word uses the installed font and substitutes when it is missing, so anyone
editing that file should install Vazirmatn first (double-click each `.ttf`).

Four weights are kept because the manual uses them: Regular (body), Medium and
SemiBold (spare weights for emphasis), and Bold (headings).
