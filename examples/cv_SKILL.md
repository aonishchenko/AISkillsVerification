---
name: cv-formatter
description: >
  Converts any CV / resume content into a specific professional DOCX format used by Oleksiy Onishchenko.
  Use this skill whenever the user asks to: format a CV, reformat a resume, create a new CV version,
  tailor a CV for a job description, or produce any .docx resume output. Triggers on phrases like
  "format my CV", "create a CV version", "tailor my resume", "make a docx CV", "apply CV format",
  or any time a CV/resume is being produced as a file output.
---

# CV Formatter Skill

Produces a `.docx` CV in a specific format using `python-docx`. All formatting is applied
programmatically — **do not use Word styles, themes, or templates**. Every property is set
explicitly in code.

---

## Format Specification

### Fonts
| Element | Font | Size | Weight | Style |
|---|---|---|---|---|
| Name | Times New Roman | 14pt | Bold | - |
| Contact line | Times New Roman | 10pt | Regular | - |
| Section headers | Times New Roman | 12pt | Bold | - |
| Company name | Times New Roman | 11pt | Bold | - |
| Job title + dates | Times New Roman | 11pt | Bold | Italic |
| Location (on company line) | Times New Roman | 11pt | Regular | - |
| Intro paragraph | Times New Roman | 11pt | Regular | - |
| Bullet points | Times New Roman | 11pt | Regular | - |
| Education / footer lines | Times New Roman | 11pt | Regular (label bold) | - |

### Alignment
- **Name**: centered
- **Contact line**: centered
- **Section headers**: left
- **All body text** (intros, bullets): justified
- **Company / title lines**: left (with right-aligned tab for location/dates)

### Spacing
| Element | space_before | space_after | line_spacing |
|---|---|---|---|
| Name | 0 | 1pt | default |
| Contact | 0 | 5pt | default |
| Section header | 1pt (SUMMARY) / 5pt (PROFESSIONAL EXPERIENCE) / 2pt (EDUCATION) | 4pt (SUMMARY) / 1pt (others) | default |
| Summary para 1 | 1pt | 2pt | default |
| Summary para 2 | 1pt | 1pt | default |
| Company line | 1pt | 1pt | default |
| Title line | 1pt | 1pt | default |
| Intro paragraph | 1pt | 1pt | default |
| Bullet point | 1pt | 1pt | default |
| Education lines | 1pt | 1pt | default |
| **Section gap** (empty separator) | 0 | 0 | **exact 4pt** |

> ⚠️ Section gaps MUST use `lineRule=exact` with `line=80` twips (4pt x 20). Simply setting
> font size to 4pt is not enough — Word will default to the document line height. You must set
> the XML `w:spacing` element directly.

### Page Margins
- Top: 0.8 in, Bottom: 0.7 in, Left: 0.85 in, Right: 0.85 in

### Tab Stops
Company name lines and title lines use a **right-aligned tab stop at 6.8 inches** to push
location/dates flush to the right text border (8.5" page - 0.85" left margin - 0.85" right margin = 6.8").

> ⚠️ Never use 6.5 inches — that leaves a visible gap before the right margin.

### Dashes
> ⚠️ **Never use em dashes ( - ).** Always use a regular hyphen `-` everywhere in the document,
> including bullet text, intro paragraphs, summary, and any other content.

---

## Document Structure

```
NAME (centered, 14pt bold)
Contact line (centered, 10pt)
[section gap]
SUMMARY (12pt bold)
[section gap]
Summary paragraph 1 (justified, 11pt)
Summary paragraph 2 (justified, 11pt)
[section gap]
PROFESSIONAL EXPERIENCE (12pt bold)
[section gap]
COMPANY NAME [tab] LOCATION   <- bold company, regular location
Job Title [tab] Dates         <- bold italic both
Intro paragraph (justified)
- Bullet one
- Bullet two
...
[section gap]
COMPANY NAME [tab] LOCATION
...
[section gap]
EDUCATION (12pt bold)
[section gap]
UNIVERSITY NAME - Degree, Year
[section gap]
LANGUAGES: [bold label] full text
[section gap]
OTHER EDUCATION: [bold label] full text
[section gap]
AWARDS: [bold label standalone]
Award line 1
Award line 2
```

### Key structural rules
- Bullets are **plain paragraphs** starting with `"- "` — NOT Word list/numbering styles.
- Company line: bold run + `\t` run + regular run (location). Tab stop set via XML.
- Title line: bold+italic run + `\t` run + bold+italic run (dates). Same tab stop.
- LANGUAGES / OTHER EDUCATION / AWARDS labels: **bold run** + regular run in same paragraph.
  Exception: AWARDS label is its own bold paragraph, awards text follows as plain paragraphs.
- No horizontal rules. No borders. No tables.
- No Word styles used beyond Normal (which is overridden to Times New Roman 11pt).

---

## Complete Python Implementation

Install dependency: `pip install python-docx`

```python
from docx import Document
from docx.shared import Pt, Inches
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.oxml.ns import qn
from docx.oxml import OxmlElement

doc = Document()

# -- Page margins -------------------------------------------------------------
for section in doc.sections:
    section.top_margin    = Inches(0.8)
    section.bottom_margin = Inches(0.7)
    section.left_margin   = Inches(0.85)
    section.right_margin  = Inches(0.85)

# -- Override Normal style ----------------------------------------------------
style = doc.styles['Normal']
style.font.name = 'Times New Roman'
style.font.size = Pt(11)
style.paragraph_format.space_before = Pt(0)
style.paragraph_format.space_after  = Pt(0)

# -- Helpers ------------------------------------------------------------------

def set_tab_right(para, position_inches=6.8):
    """Right-aligned tab stop flush to right text border."""
    pPr = para._p.get_or_add_pPr()
    tabs = OxmlElement('w:tabs')
    tab  = OxmlElement('w:tab')
    tab.set(qn('w:val'), 'right')
    tab.set(qn('w:pos'), str(int(position_inches * 1440)))
    tabs.append(tab)
    pPr.append(tabs)

def add_section_gap():
    """Empty paragraph at EXACTLY 4pt line height. Must use lineRule=exact."""
    p = doc.add_paragraph()
    pPr = p._p.get_or_add_pPr()
    spacing = OxmlElement('w:spacing')
    spacing.set(qn('w:line'),     '80')    # 4pt x 20 twips
    spacing.set(qn('w:lineRule'), 'exact')
    spacing.set(qn('w:before'),   '0')
    spacing.set(qn('w:after'),    '0')
    pPr.append(spacing)
    r = p.add_run('')
    r.font.name = 'Times New Roman'
    r.font.size = Pt(4)
    return p

def add_para(text, bold=False, italic=False, size_pt=11,
             align=None, sb=None, sa=None,
             bold_prefix=None, regular_suffix=None):
    """
    General paragraph builder.
    - bold_prefix + regular_suffix: for mixed bold/regular in one paragraph
      (used for LANGUAGES:, OTHER EDUCATION:, AWARDS:)
    """
    p = doc.add_paragraph()
    if align == 'center':
        p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    elif align == 'justify':
        p.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
    if sb is not None:
        p.paragraph_format.space_before = Pt(sb)
    if sa is not None:
        p.paragraph_format.space_after  = Pt(sa)

    if bold_prefix is not None:
        r1 = p.add_run(bold_prefix)
        r1.bold      = True
        r1.font.name = 'Times New Roman'
        r1.font.size = Pt(size_pt)
        r2 = p.add_run(regular_suffix)
        r2.bold      = False
        r2.font.name = 'Times New Roman'
        r2.font.size = Pt(size_pt)
    else:
        run = p.add_run(text)
        run.bold      = bold
        run.italic    = italic
        run.font.name = 'Times New Roman'
        run.font.size = Pt(size_pt)
    return p

def add_company_line(company, location):
    """COMPANY NAME [tab] Location - bold company, regular location."""
    p = doc.add_paragraph()
    p.paragraph_format.space_before = Pt(1)
    p.paragraph_format.space_after  = Pt(1)
    set_tab_right(p)
    r1 = p.add_run(company);    r1.bold = True;  r1.font.name = 'Times New Roman'; r1.font.size = Pt(11)
    r2 = p.add_run('\t');                         r2.font.name = 'Times New Roman'; r2.font.size = Pt(11)
    r3 = p.add_run(location);   r3.bold = False; r3.font.name = 'Times New Roman'; r3.font.size = Pt(11)

def add_title_line(title, dates):
    """Job Title [tab] Dates - bold italic both sides."""
    p = doc.add_paragraph()
    p.paragraph_format.space_before = Pt(1)
    p.paragraph_format.space_after  = Pt(1)
    set_tab_right(p)
    for text in [title, '\t', dates]:
        r = p.add_run(text)
        r.bold      = True
        r.italic    = True
        r.font.name = 'Times New Roman'
        r.font.size = Pt(11)

def add_bullet(text):
    """Plain paragraph with '- ' prefix. NOT a Word list style."""
    add_para('- ' + text, size_pt=11, align='justify', sb=1, sa=1)

def add_intro(text):
    """Role intro paragraph - regular, justified."""
    add_para(text, size_pt=11, align='justify', sb=1, sa=1)

# -- Header -------------------------------------------------------------------
add_para('FULL NAME HERE', bold=True, size_pt=14, align='center', sb=0, sa=1)
add_para('City, Country | +XX XXX XXX XXX | email@example.com | linkedin.com/in/profile',
         size_pt=10, align='center', sb=0, sa=5)

add_section_gap()

# -- Summary ------------------------------------------------------------------
add_para('SUMMARY', bold=True, size_pt=12, sb=1, sa=4)
add_section_gap()
add_para('First summary paragraph...', size_pt=11, align='justify', sb=1, sa=2)
add_para('Second summary paragraph...', size_pt=11, align='justify', sb=1, sa=1)
add_section_gap()

# -- Professional Experience --------------------------------------------------
add_para('PROFESSIONAL EXPERIENCE', bold=True, size_pt=12, sb=5, sa=1)
add_section_gap()

add_company_line('COMPANY NAME', 'CITY, COUNTRY')
add_title_line('Job Title', 'Mon YYYY - Mon YYYY')
add_intro('Short intro paragraph describing scope of role.')
add_bullet('Bullet one - achievement with metric.')
add_bullet('Bullet two - achievement with metric.')

add_section_gap()

add_company_line('PREVIOUS COMPANY', 'CITY, COUNTRY')
add_title_line('Job Title', 'Mon YYYY - Mon YYYY')
add_intro('Short intro paragraph.')
add_bullet('Bullet one.')
add_bullet('Bullet two.')

add_section_gap()

# -- Education ----------------------------------------------------------------
add_para('EDUCATION', bold=True, size_pt=12, sb=2, sa=2)
add_section_gap()
add_para('UNIVERSITY NAME - Degree, Year', size_pt=11, sb=1, sa=1)
add_section_gap()
add_para(None, sb=1, sa=1, bold_prefix='LANGUAGES: ',
         regular_suffix='Language 1 - level; Language 2 - level.',
         size_pt=11)
add_section_gap()
add_para(None, sb=1, sa=1, bold_prefix='OTHER EDUCATION: ',
         regular_suffix='Describe continuous learning areas.',
         size_pt=11)
add_section_gap()
add_para('AWARDS:', bold=True, size_pt=11, sb=1, sa=1)
add_para('Mon-YYYY Description of award.', size_pt=11, sb=1, sa=1)
add_para('Mon-YYYY Description of award.', size_pt=11, sb=1, sa=1)

# -- Save ---------------------------------------------------------------------
doc.save('output_cv.docx')
```

---

## Content Rules (Editorial Style)

These rules govern **what to write**, not just how to format it.

### Summary
- **Two paragraphs only.** Never more.
- Para 1: Years of experience + team scale (X-Y people) + geography + revenue/business impact number.
- Para 2: Dense run of functional keywords - no bullets, no label, no "Core competencies:" header.
  Just a natural sentence listing domains. Example:
  *"Strategic planning and technical direction, AI/LLM and agentic product delivery, engineering org design..."*
- **Engineering Manager variant only**: insert a `Technical foundation:` bold-label line between
  para 1 and para 2, listing tech stack as `Go - Java - Python - Kubernetes - AWS - ...`

### Experience Bullets
- Start with strong action verb.
- Include a metric or outcome wherever possible.
- **Do not list technologies** in bullets unless the technology IS the point of the bullet.
- Show process ownership explicitly: skills matrix, performance reviews, interview process, etc.
  - these are concrete and valued.
- Pre-sales/RFP participation: always include at role level if applicable, not only in summary.

### Role structure
- Each role: company line -> title line -> 1 intro sentence -> 3-6 bullets.
- Older roles (10+ years ago) get collapsed: one combined title entry (e.g.
  `Engineering Manager / QA Manager / Engineer`) with a single date range and 3-4 bullets max.
- No separate "Earlier Experience" catch-all section.

### Education & Other
- `LANGUAGES:` bold label + regular text, all in one paragraph.
- `OTHER EDUCATION:` bold label + regular text - use for continuous learning, not formal degrees.
- `AWARDS:` bold standalone label, then each award as its own plain paragraph (no bullets).
- No `INTERESTS:` section. No `TECHNICAL STACK:` section (for Director-level CVs).

### Titles
- Keep job titles exactly as they appear on the employment record. Do not reframe or upgrade them.

---

## Checklist Before Saving

- [ ] All fonts are Times New Roman (no Arial, Calibri, or fallback fonts)
- [ ] Name is 14pt bold centered
- [ ] Contact line is 10pt centered
- [ ] Section headers are 12pt bold, left-aligned
- [ ] Company names are 11pt bold with right-tab location
- [ ] Titles are 11pt bold italic with right-tab dates
- [ ] Tab stop is at 6.8 inches (right text border)
- [ ] All body text is 11pt regular
- [ ] All section gaps use `lineRule=exact` at 80 twips (4pt)
- [ ] No em dashes anywhere - only regular hyphens
- [ ] No horizontal rules or borders anywhere
- [ ] No Word list styles - bullets are plain paragraphs with `- ` prefix
- [ ] No TECHNICAL SKILLS or INTERESTS sections
- [ ] Summary is exactly 2 paragraphs (3 for EM variant with tech stack)
- [ ] AWARDS are plain paragraphs, not bulleted
