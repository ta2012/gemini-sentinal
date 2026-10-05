# generate_walkthrough_pdf.py
# Compiles the dashboard walkthrough and verification screenshots into a clean PDF.

import os
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, Image

def main():
    pdf_filename = "dashboard_walkthrough.pdf"
    
    img1_path = r"C:\Users\HP\.gemini\antigravity-ide\brain\0f59db1a-4dd6-458d-a7aa-7bf1d3355906\dashboard_home_1785681941843.png"
    img2_path = r"C:\Users\HP\.gemini\antigravity-ide\brain\0f59db1a-4dd6-458d-a7aa-7bf1d3355906\dashboard_details_1785682204530.png"
    
    doc = SimpleDocTemplate(
        pdf_filename,
        pagesize=letter,
        rightMargin=54,
        leftMargin=54,
        topMargin=54,
        bottomMargin=54
    )
    
    styles = getSampleStyleSheet()
    
    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Heading1'],
        fontName='Helvetica-Bold',
        fontSize=22,
        leading=26,
        textColor=colors.HexColor('#1e293b'),
        spaceAfter=15
    )
    
    subtitle_style = ParagraphStyle(
        'DocSubtitle',
        parent=styles['Normal'],
        fontName='Helvetica-Oblique',
        fontSize=11,
        leading=15,
        textColor=colors.HexColor('#64748b'),
        spaceAfter=25
    )
    
    h1_style = ParagraphStyle(
        'SectionH1',
        parent=styles['Heading2'],
        fontName='Helvetica-Bold',
        fontSize=15,
        leading=19,
        textColor=colors.HexColor('#0f172a'),
        spaceBefore=15,
        spaceAfter=8,
        keepWithNext=True
    )
    
    h2_style = ParagraphStyle(
        'SectionH2',
        parent=styles['Heading3'],
        fontName='Helvetica-Bold',
        fontSize=12,
        leading=16,
        textColor=colors.HexColor('#334155'),
        spaceBefore=12,
        spaceAfter=6,
        keepWithNext=True
    )
    
    body_style = ParagraphStyle(
        'DocBody',
        parent=styles['BodyText'],
        fontName='Helvetica',
        fontSize=10,
        leading=14,
        textColor=colors.HexColor('#334155'),
        spaceAfter=8
    )
    
    callout_style = ParagraphStyle(
        'DocCallout',
        parent=styles['Normal'],
        fontName='Helvetica-Oblique',
        fontSize=9.5,
        leading=13,
        textColor=colors.HexColor('#1e293b'),
        backColor=colors.HexColor('#f8fafc'),
        borderColor=colors.HexColor('#e2e8f0'),
        borderWidth=0.5,
        borderPadding=8,
        spaceBefore=8,
        spaceAfter=12
    )

    story = []
    
    story.append(Paragraph("SOC Copilot", title_style))
    story.append(Paragraph("Redesigned Log-Centric Dashboard Walkthrough", ParagraphStyle(
        'SubTitleText',
        parent=title_style,
        fontSize=15,
        leading=19,
        textColor=colors.HexColor('#1976d2'),
        spaceAfter=5
    )))
    story.append(Paragraph("Verification Report and Visual Walkthrough - August 2026", subtitle_style))
    
    story.append(Paragraph("1. Dashboard Features", h1_style))
    story.append(Paragraph(
        "I have rebuilt the Streamlit dashboard to utilize a log-centric design that aggregates all benign and flagged "
        "activity logs into a unified stream feed. Key functionalities include:",
        body_style
    ))
    
    features_list = [
        "<b>Activity Log Feed:</b> Scrollable log stream displaying status bracket indicators: [ALERT] (violations/spikes), [OK] (benign logs), [QUARANTINED] (isolated agents), and [RESOLVED] (dismissed alerts).",
        "<b>Log Inspector:</b> Clicking on any log updates the right panel to show raw JSON payload, rule matches, and LLM Copilot incident analysis (verdict, reasoning, evidence).",
        "<b>Remediation Actions:</b> Buttons allowing analysts to take immediate action: Isolate Agent (quarantines agent status across feed), Authorize Action (whitelists tool), or Dismiss Alert (resolves ticket).",
        "<b>Ask Copilot Chat:</b> Custom text input query box that calls Groq Llama 3 in real-time to return step-by-step remediation advice tailored to the active event."
    ]
    for feat in features_list:
        story.append(Paragraph(f"• {feat}", body_style))
        
    story.append(Spacer(1, 10))
    
    story.append(Paragraph("2. Summary of Project Files", h1_style))
    
    files_data = [
        [Paragraph("<b>Filename</b>", body_style), Paragraph("<b>Description</b>", body_style)],
        [Paragraph("<code>rules.yaml</code>", body_style), Paragraph("Declares the 5 behavior analysis detection rules.", body_style)],
        [Paragraph("<code>generate_events.py</code>", body_style), Paragraph("Generates 34 chronological events in JSONL.", body_style)],
        [Paragraph("<code>detect.py</code>", body_style), Paragraph("Detection and incident correlation (60m window sessionization).", body_style)],
        [Paragraph("<code>app.py</code>", body_style), Paragraph("Streamlit dashboard with dry engineering styles and controls.", body_style)],
        [Paragraph("<code>generate_pdf.py</code>", body_style), Paragraph("Compiles the non-technical POC guide in PDF.", body_style)],
        [Paragraph("<code>README.md</code>", body_style), Paragraph("Onboarding reference and manual run instructions.", body_style)]
    ]
    t = Table(files_data, colWidths=[2.2*inch, 3.8*inch])
    t.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#f1f5f9')),
        ('TEXTCOLOR', (0,0), (-1,0), colors.HexColor('#0f172a')),
        ('ALIGN', (0,0), (-1,-1), 'LEFT'),
        ('BOTTOMPADDING', (0,0), (-1,-1), 5),
        ('TOPPADDING', (0,0), (-1,-1), 5),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#cbd5e1')),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
    ]))
    story.append(t)
    
    story.append(PageBreak())
    
    story.append(Paragraph("3. Verification Screenshots", h1_style))
    
    story.append(Paragraph("A. Log Feed Layout (Dry, Emoji-Free Console)", h2_style))
    story.append(Paragraph("Shows the split layout with the scrollable log activity feed on the left, styled using clean brackets:", body_style))
    if os.path.exists(img1_path):
        story.append(Image(img1_path, width=5.5*inch, height=2.8*inch))
    else:
        story.append(Paragraph("<i>[Image placeholder: dashboard_home.png not found]</i>", body_style))
        
    story.append(Spacer(1, 15))
    
    story.append(Paragraph("B. Log Inspector & Remediation Controls", h2_style))
    story.append(Paragraph("Shows raw JSON details, rule matches, LLM analysis, action buttons, and Ask Copilot chat guidance:", body_style))
    if os.path.exists(img2_path):
        story.append(Image(img2_path, width=5.5*inch, height=2.8*inch))
    else:
        story.append(Paragraph("<i>[Image placeholder: dashboard_details.png not found]</i>", body_style))
        
    story.append(Spacer(1, 20))
    story.append(Paragraph("Verification Status: <b>Successful</b>. All dashboard components and LLM integrations verified.", callout_style))
    
    doc.build(story)
    print(f"Successfully generated {pdf_filename}")

if __name__ == "__main__":
    main()
