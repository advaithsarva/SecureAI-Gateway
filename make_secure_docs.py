import os
import docx
from docx import Document
from docx.shared import Inches, Pt, RGBColor
from docx.enum.text import WD_ALIGN_PARAGRAPH

def md_to_docx(md_path, docx_path, title):
    doc = Document()
    
    # Set Margins
    for section in doc.sections:
        section.top_margin = Inches(1)
        section.bottom_margin = Inches(1)
        section.left_margin = Inches(1)
        section.right_margin = Inches(1)

    # Document Header Title
    h = doc.add_heading(title, level=0)
    h.paragraph_format.space_after = Pt(14)
    for run in h.runs:
        run.font.name = 'Calibri'
        run.font.color.rgb = RGBColor(11, 25, 45)

    with open(md_path, 'r', encoding='utf-8') as f:
        lines = f.readlines()

    for line in lines:
        line_s = line.strip()
        if not line_s:
            continue
        
        if line_s.startswith('# '):
            h1 = doc.add_heading(line_s[2:], level=1)
            h1.paragraph_format.space_before = Pt(14)
            h1.paragraph_format.space_after = Pt(6)
            for r in h1.runs:
                r.font.name = 'Calibri'
                r.font.color.rgb = RGBColor(15, 45, 80)
        elif line_s.startswith('## '):
            h2 = doc.add_heading(line_s[3:], level=2)
            h2.paragraph_format.space_before = Pt(10)
            h2.paragraph_format.space_after = Pt(4)
            for r in h2.runs:
                r.font.name = 'Calibri'
                r.font.color.rgb = RGBColor(25, 75, 120)
        elif line_s.startswith('### '):
            h3 = doc.add_heading(line_s[4:], level=3)
            h3.paragraph_format.space_before = Pt(8)
            h3.paragraph_format.space_after = Pt(3)
            for r in h3.runs:
                r.font.name = 'Calibri'
                r.font.color.rgb = RGBColor(40, 100, 150)
        elif line_s.startswith('- ') or line_s.startswith('* '):
            p = doc.add_paragraph(style='List Bullet')
            p.paragraph_format.space_after = Pt(3)
            parts = line_s[2:].split('**')
            for i, part in enumerate(parts):
                r = p.add_run(part)
                r.font.name = 'Calibri'
                r.font.size = Pt(10.5)
                if i % 2 == 1:
                    r.bold = True
        elif line_s.startswith('> '):
            p = doc.add_paragraph()
            p.paragraph_format.left_indent = Inches(0.4)
            p.paragraph_format.space_before = Pt(4)
            p.paragraph_format.space_after = Pt(6)
            r = p.add_run(line_s[2:])
            r.font.name = 'Calibri'
            r.font.size = Pt(10)
            r.font.italic = True
            r.font.color.rgb = RGBColor(70, 70, 70)
        else:
            p = doc.add_paragraph()
            p.paragraph_format.space_after = Pt(4)
            parts = line_s.split('**')
            for i, part in enumerate(parts):
                r = p.add_run(part)
                r.font.name = 'Calibri'
                r.font.size = Pt(10.5)
                if i % 2 == 1:
                    r.bold = True

    doc.save(docx_path)
    print(f"Created docx: {docx_path}")

if __name__ == "__main__":
    secure_dir = r"C:\Users\advai\OneDrive\Desktop\secure"
    docs_src = r"C:\Projects\SecureAI-Gateway\docs"
    
    # 1. Project Master Notes & Defense Guide
    md_notes = os.path.join(docs_src, "PROJECT_NOTES_AND_DEFENSE_GUIDE.md")
    out_notes = os.path.join(secure_dir, "SecureAI_Gateway_Project_Notes_and_Viva_Guide.docx")
    md_to_docx(md_notes, out_notes, "SecureAI Gateway: Project Notes & Viva Defense Guide")
    
    # 2. Speaker Defense Script
    md_speaker = os.path.join(docs_src, "SPEAKER_NOTES_10_SLIDES.md")
    out_speaker = os.path.join(secure_dir, "SecureAI_Gateway_Speaker_Defense_Script_10_Slides.docx")
    md_to_docx(md_speaker, out_speaker, "SecureAI Gateway: 10-Slide Speaker Defense Script")

    # 3. Canva 1-Click Import Deck
    md_canva = os.path.join(docs_src, "PRESENTATION_10_SLIDES_CANVA.md")
    out_canva = os.path.join(secure_dir, "SecureAI_Gateway_10_Slides_Canva_Import.docx")
    md_to_docx(md_canva, out_canva, "SecureAI Gateway: 10-Slide Presentation Text for Canva")
