import os
import sys
from pptx import Presentation
from pptx.util import Inches, Pt
from pptx.dml.color import RGBColor
from pptx.enum.text import PP_ALIGN
from pptx.enum.shapes import MSO_SHAPE

def build_secure_ai_deck(output_pptx):
    prs = Presentation()
    prs.slide_width = Inches(13.333)
    prs.slide_height = Inches(7.5)
    blank_layout = prs.slide_layouts[6]

    # Cybersecurity Theme Colors
    C_BG = RGBColor(11, 15, 25)           # Deep Charcoal
    C_CARD = RGBColor(19, 26, 43)         # Cyber Surface Card
    C_CARD_BORDER = RGBColor(38, 52, 86)  # Subtle border
    C_CYAN = RGBColor(0, 242, 254)        # Neon Cyan
    C_PURPLE = RGBColor(79, 172, 254)     # Electric Blue / Purple
    C_WHITE = RGBColor(255, 255, 255)     # Crisp White
    C_MUTED = RGBColor(156, 163, 175)     # Slate Gray
    C_ALERT = RGBColor(255, 75, 75)       # Cyber Crimson (Threats)
    C_GREEN = RGBColor(0, 230, 118)       # Neon Emerald (Protection)
    C_GOLD = RGBColor(255, 179, 0)        # Amber

    def set_slide_bg(slide):
        bg = slide.shapes.add_shape(MSO_SHAPE.RECTANGLE, 0, 0, prs.slide_width, prs.slide_height)
        bg.fill.solid()
        bg.fill.fore_color.rgb = C_BG
        bg.line.fill.background()
        return bg

    def add_header(slide, tag_text, title_text, slide_num):
        tb = slide.shapes.add_textbox(Inches(0.8), Inches(0.4), Inches(8), Inches(0.4))
        p = tb.text_frame.paragraphs[0]
        p.text = tag_text.upper()
        p.font.size = Pt(10)
        p.font.bold = True
        p.font.color.rgb = C_CYAN
        
        tb_title = slide.shapes.add_textbox(Inches(0.8), Inches(0.75), Inches(10), Inches(0.8))
        p2 = tb_title.text_frame.paragraphs[0]
        p2.text = title_text
        p2.font.size = Pt(22)
        p2.font.bold = True
        p2.font.color.rgb = C_WHITE

        tb_num = slide.shapes.add_textbox(Inches(11.5), Inches(0.4), Inches(1), Inches(0.4))
        p3 = tb_num.text_frame.paragraphs[0]
        p3.text = f"{slide_num:02d} / 10"
        p3.alignment = PP_ALIGN.RIGHT
        p3.font.size = Pt(11)
        p3.font.bold = True
        p3.font.color.rgb = C_MUTED

    def add_card(slide, left, top, width, height, title, body_bullets, border_color=None, bg_color=None):
        card = slide.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, left, top, width, height)
        card.fill.solid()
        card.fill.fore_color.rgb = bg_color or C_CARD
        card.line.color.rgb = border_color or C_CARD_BORDER
        card.line.width = Pt(1.5)

        tf = card.text_frame
        tf.word_wrap = True
        tf.margin_left = Inches(0.25)
        tf.margin_right = Inches(0.25)
        tf.margin_top = Inches(0.22)
        tf.margin_bottom = Inches(0.2)

        p = tf.paragraphs[0]
        p.text = title
        p.font.size = Pt(14)
        p.font.bold = True
        p.font.color.rgb = border_color or C_CYAN
        p.space_after = Pt(10)

        for b in body_bullets:
            p_b = tf.add_paragraph()
            p_b.text = "• " + b
            p_b.font.size = Pt(11)
            p_b.font.color.rgb = C_MUTED
            p_b.space_after = Pt(6)

        return card

    # ==================== SLIDE 1: Title ====================
    s1 = prs.slides.add_slide(blank_layout)
    set_slide_bg(s1)

    pill = s1.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(0.8), Inches(1.1), Inches(4.5), Inches(0.38))
    pill.fill.solid(); pill.fill.fore_color.rgb = RGBColor(0, 40, 60); pill.line.color.rgb = C_CYAN
    pill.text_frame.paragraphs[0].text = "B.TECH CSE (AI & ML) • CAPSTONE PROJECT DEFENSE"
    pill.text_frame.paragraphs[0].font.size = Pt(9.5); pill.text_frame.paragraphs[0].font.bold = True; pill.text_frame.paragraphs[0].font.color.rgb = C_CYAN; pill.text_frame.paragraphs[0].alignment = PP_ALIGN.CENTER

    t_box = s1.shapes.add_textbox(Inches(0.8), Inches(1.7), Inches(11.5), Inches(2.0))
    p = t_box.text_frame.paragraphs[0]
    p.text = "SecureAI Gateway: An Adaptive Security Firewall for Generative AI"
    p.font.size = Pt(32); p.font.bold = True; p.font.color.rgb = C_WHITE; p.space_after = Pt(12)
    p_sub = t_box.text_frame.add_paragraph()
    p_sub.text = "Real-Time Prompt Injection Defense, PII Masking & Risk Governance for LLMs"
    p_sub.font.size = Pt(18); p_sub.font.color.rgb = C_CYAN

    add_card(s1, Inches(0.8), Inches(4.3), Inches(3.6), Inches(2.3), "Project & Candidate", [
        "Advaith Narayana Sarva",
        "Roll No: 23WU0102179",
        "B.Tech Computer Science (AI & ML)",
        "School of Technology, Woxsen University"
    ])

    add_card(s1, Inches(4.8), Inches(4.3), Inches(3.6), Inches(2.3), "Core Specialization", [
        "Generative AI Security & LLM Defense",
        "OWASP Top 10 for LLM Applications",
        "Hybrid Regex Heuristics + Scikit-Learn ML",
        "FastAPI & Streamlit SOC Dashboard"
    ])

    add_card(s1, Inches(8.8), Inches(4.3), Inches(3.6), Inches(2.3), "Empirical Results", [
        "450 Real-World Benchmark Cases",
        "99.33% Attack Detection Rate (Recall)",
        "99.67% Precision | 99.50% F1-Score",
        "100.0% PII Redaction Accuracy"
    ], border_color=C_GREEN)

    # ==================== SLIDE 2: Problem Statement ====================
    s2 = prs.slides.add_slide(blank_layout)
    set_slide_bg(s2)
    add_header(s2, "Executive Context • Threat Landscape", "The LLM Vulnerability Crisis: The Need for an AI Firewall", 2)

    add_card(s2, Inches(0.8), Inches(1.8), Inches(3.6), Inches(4.9), "💥 Prompt Injection Attacks", [
        "OWASP LLM01: Attackers hijack model instructions.",
        "System prompt overrides ('Ignore previous instructions and do X').",
        "Delimiter spoofing ('[SYSTEM OVERRIDE]', '<|im_start|>').",
        "Exfiltration of proprietary instructions, keys, and confidential guardrails."
    ], border_color=C_ALERT)

    add_card(s2, Inches(4.8), Inches(1.8), Inches(3.6), Inches(4.9), "🔓 Jailbreaks & Personas", [
        "Persona adoption attacks (DAN, Developer Mode, AIM).",
        "Policy-bypass hypothetical framing to trick safety filters.",
        "Obfuscation & base64 encoded payloads to bypass string matching.",
        "Generation of prohibited malware payloads or hate speech."
    ], border_color=C_ALERT)

    add_card(s2, Inches(8.8), Inches(1.8), Inches(3.6), Inches(4.9), "🕵️ PII & Credential Leakage", [
        "OWASP LLM06: Inadvertent submission of sensitive data to third-party models.",
        "Exposure of Indian mobile numbers (+91), PAN/Aadhaar/SSN IDs, emails.",
        "Accidental leakage of API keys (sk-..., ghp_...), server IPv4s, passwords.",
        "Direct violation of GDPR, HIPAA, and DPDP Act 2023."
    ], border_color=C_ALERT)

    # ==================== SLIDE 3: System Objectives & Scope ====================
    s3 = prs.slides.add_slide(blank_layout)
    set_slide_bg(s3)
    add_header(s3, "Architecture Mandate • Engineering Goals", "System Objectives: Building an Intelligent, Modular AI Gateway", 3)

    add_card(s3, Inches(0.8), Inches(1.8), Inches(3.6), Inches(4.9), "1. Zero Cloud Dependency", [
        "100% Local Execution: Operates entirely on local hardware without paid cloud credits or API dependencies.",
        "Dual AI Engine: Works with offline deterministic Mock LLM or local Ollama (Llama 3 / Mistral).",
        "Lightweight Latency: Sub-15ms average inspection overhead."
    ], border_color=C_CYAN)

    add_card(s3, Inches(4.8), Inches(1.8), Inches(3.6), Inches(4.9), "2. Multi-Layer Defense", [
        "Layer 1: Perimeter rate limiting & payload validation.",
        "Layer 2: Hybrid Prompt Injection & Jailbreak Scanner.",
        "Layer 3: Privacy Scanner & Entity Redactor.",
        "Layer 4: Central Risk Assessment Engine (ALLOW/SANITIZE/BLOCK).",
        "Layer 5: Output Filter (Canary leak protection).",
        "Layer 6: Secret-Free SQLite Audit Trail."
    ], border_color=C_CYAN)

    add_card(s3, Inches(8.8), Inches(1.8), Inches(3.6), Inches(4.9), "3. Scientific Rigor", [
        "Trained on 2,175 disjoint open-source samples.",
        "Evaluated on 450 real-world Hugging Face benchmark cases.",
        "Zero synthetic hallucinated metrics; strict SHA-256 deduplicated splits.",
        "Cloud alignment with Microsoft Defender for Cloud & Azure Foundry."
    ], border_color=C_GREEN)

    # ==================== SLIDE 4: 6-Layer Gateway Architecture ====================
    s4 = prs.slides.add_slide(blank_layout)
    set_slide_bg(s4)
    add_header(s4, "System Design • Dataflow Architecture", "The 6-Layer Security Gateway Architecture", 4)

    # Banner diagram
    banner = s4.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(0.8), Inches(1.8), Inches(11.6), Inches(1.1))
    banner.fill.solid(); banner.fill.fore_color.rgb = RGBColor(15, 30, 50); banner.line.color.rgb = C_CYAN
    tf_b = banner.text_frame; tf_b.paragraphs[0].text = "USER REQUEST ➔ FASTAPI GATEWAY ➔ INPUT SCAN ➔ RISK ENGINE ➔ LLM ➔ OUTPUT FILTER ➔ AUDIT"
    tf_b.paragraphs[0].font.size = Pt(13); tf_b.paragraphs[0].font.bold = True; tf_b.paragraphs[0].font.color.rgb = C_CYAN; tf_b.paragraphs[0].alignment = PP_ALIGN.CENTER
    p_b2 = tf_b.add_paragraph()
    p_b2.text = "Modular pipeline evaluating every byte before and after the language model executes."
    p_b2.font.size = Pt(10); p_b2.font.color.rgb = C_MUTED; p_b2.alignment = PP_ALIGN.CENTER

    add_card(s4, Inches(0.8), Inches(3.2), Inches(3.6), Inches(3.6), "Layers 1 & 2: Input Guard", [
        "Layer 1: Perimeter Rate Limiter (60 req/min sliding-window, null-byte rejection, 10KB size limit).",
        "Layer 2: Prompt Scanner (PI-001 to PI-010 regex heuristics + Base64 decoding + Scikit-Learn LinearSVC)."
    ])

    add_card(s4, Inches(4.8), Inches(3.2), Inches(3.6), Inches(3.6), "Layers 3 & 4: Privacy & Risk", [
        "Layer 3: Privacy Scanner & Entity Redactor (detects and masks PII/keys to [REDACTED_*]).",
        "Layer 4: Risk Engine (computes 0-100 risk score, outputs decision: ALLOW, SANITIZE, or BLOCK)."
    ])

    add_card(s4, Inches(8.8), Inches(3.2), Inches(3.6), Inches(3.6), "Layers 5 & 6: Output & SOC", [
        "Layer 5: Output Filter (blocks canary token leaks, system prompt disclosure, unsafe payloads).",
        "Layer 6: Audit Logger & Streamlit SOC Dashboard (real-time KPIs, threat monitoring, SQLite)."
    ])

    # ==================== SLIDE 5: Hybrid Detection Engine ====================
    s5 = prs.slides.add_slide(blank_layout)
    set_slide_bg(s5)
    add_header(s5, "Core Machine Learning • Layer 2 Mechanics", "Hybrid Injection Detection: Regex Heuristics + Scikit-Learn ML", 5)

    add_card(s5, Inches(0.8), Inches(1.8), Inches(5.6), Inches(4.9), "Fast Deterministic Heuristics (Regex)", [
        "10 Targeted Rules (PI-001 through PI-010 + PI-ENC-001):",
        "• Instruction Overrides: 'Ignore all previous directives...'",
        "• System Extraction: 'Repeat the system prompt above verbatim...'",
        "• Jailbreak Personas: DAN, Developer Mode, AIM, unrestricted AI.",
        "• Delimiter Spoofing: [SYSTEM OVERRIDE], <|im_start|>, ### System.",
        "• Obfuscation: Automatic Base64 payload decoding & zero-width character stripping.",
        "• Contextual Dampening: Prevents false alarms on legitimate educational queries ('What is a prompt injection attack?')."
    ], border_color=C_CYAN)

    add_card(s5, Inches(6.8), Inches(1.8), Inches(5.6), Inches(4.9), "Statistical ML Classifier (LinearSVC)", [
        "Trained on 2,175 Disjoint Samples (Zero overlap with test benchmark):",
        "• Dual Feature Union: Word-level TF-IDF (1-3 n-grams, 25k features) + Character n-grams (3-5 char_wb, 35k features).",
        "• Calibrated LinearSVC: 5-fold cross-validated probability calibration (CalibratedClassifierCV).",
        "• Generalization: Catches novel semantic variations that evade strict keyword regex patterns.",
        "• Ultra-Fast Inference: Executes in under 12 milliseconds on standard CPU hardware."
    ], border_color=C_GREEN)

    # ==================== SLIDE 6: Privacy Scanner & Redaction ====================
    s6 = prs.slides.add_slide(blank_layout)
    set_slide_bg(s6)
    add_header(s6, "Data Protection • Layer 3 Mechanics", "Privacy Scanner: Autonomous PII & Credential Masking", 6)

    add_card(s6, Inches(0.8), Inches(1.8), Inches(5.6), Inches(4.9), "Entities Detected & Sanitized", [
        "• Email Addresses: Sanitized to [REDACTED_EMAIL].",
        "• Indian Mobile Numbers: +91 and 10-digit formats sanitized to [REDACTED_PHONE].",
        "• National IDs: Indian PAN cards, Aadhaar numbers, and US SSNs sanitized to [REDACTED_ID].",
        "• Network Infrastructure: Private & public IPv4 addresses sanitized to [REDACTED_IP].",
        "• High-Risk API Keys: OpenAI (sk-...), GitHub (ghp_...), and JWT tokens sanitized to [REDACTED_API_KEY].",
        "• Passwords & Secrets: Hardcoded credentials sanitized to [REDACTED_PASSWORD]."
    ], border_color=C_GREEN)

    add_card(s6, Inches(6.8), Inches(1.8), Inches(5.6), Inches(4.9), "The 'SANITIZE' Decision Workflow", [
        "Autonomous Risk Tiering: Prompts with sensitive entities but zero malicious attack intent are assigned Medium Risk (Score 30-59).",
        "Pre-Model Masking: Raw sensitive tokens NEVER reach the LLM or third-party cloud APIs.",
        "Clean Model Input: The language model answers the query safely using the sanitized placeholder tokens.",
        "Audit Log Sanitization: Raw secrets are purged prior to SQLite storage, ensuring zero secret leakage in SOC audit trails.",
        "Benchmark Result: 100.0% Detection & Redaction Accuracy across 100 real-world PII evaluation cases."
    ], border_color=C_CYAN)

    # ==================== SLIDE 7: Real-World Benchmark Dataset ====================
    s7 = prs.slides.add_slide(blank_layout)
    set_slide_bg(s7)
    add_header(s7, "Scientific Rigor • Benchmark Design", "The 450-Case Real-World Evaluation Benchmark", 7)

    add_card(s7, Inches(0.8), Inches(1.8), Inches(11.6), Inches(1.3), "Curated from 4 Peer-Reviewed Hugging Face Datasets (Disjoint from Training)", [
        "1. deepset/prompt-injections | 2. jackhhao/jailbreak-classification | 3. Lakera/gandalf_ignore_instructions | 4. ai4privacy/pii-masking-200k",
        "Ground truth established via verified annotations with SHA-256 deduplication to guarantee 0% data leakage."
    ])

    add_card(s7, Inches(0.8), Inches(3.3), Inches(3.6), Inches(3.5), "Stratum 1 & 2: Benign (N=150)", [
        "100 Standard Benign: Everyday consumer, code, and math queries (Target: ALLOW).",
        "50 Difficult Benign: Legitimate queries containing roleplay cues ('Act as an interviewer') or security questions (Target: ALLOW)."
    ])

    add_card(s7, Inches(4.8), Inches(3.3), Inches(3.6), Inches(3.5), "Stratum 3 & 4: Attacks (N=200)", [
        "100 Direct Injections: Delimiter attacks and instruction overrides from Lakera/deepset (Target: BLOCK).",
        "100 Jailbreaks: Real in-the-wild DAN, Developer Mode, and persona overrides (Target: BLOCK)."
    ])

    add_card(s7, Inches(8.8), Inches(3.3), Inches(3.6), Inches(3.5), "Stratum 5: Privacy (N=100)", [
        "100 Sensitive Data: Real-world prompts containing verified PII, credit cards, IP addresses, and passwords from ai4privacy (Target: SANITIZE)."
    ])

    # ==================== SLIDE 8: Experimental Results ====================
    s8 = prs.slides.add_slide(blank_layout)
    set_slide_bg(s8)
    add_header(s8, "Empirical Evaluation • Experiment A vs B", "Experimental Results: 99.33% Attack Detection & 0.67% FPR", 8)

    # Big Metric Cards
    m1 = s8.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(0.8), Inches(1.8), Inches(2.7), Inches(1.4))
    m1.fill.solid(); m1.fill.fore_color.rgb = C_CARD; m1.line.color.rgb = C_GREEN
    m1.text_frame.paragraphs[0].text = "99.33%"
    m1.text_frame.paragraphs[0].font.size = Pt(28); m1.text_frame.paragraphs[0].font.bold = True; m1.text_frame.paragraphs[0].font.color.rgb = C_GREEN
    p_m1 = m1.text_frame.add_paragraph()
    p_m1.text = "ATTACK RECALL (298/300)"
    p_m1.font.size = Pt(9.5); p_m1.font.bold = True; p_m1.font.color.rgb = C_MUTED

    m2 = s8.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(3.8), Inches(1.8), Inches(2.7), Inches(1.4))
    m2.fill.solid(); m2.fill.fore_color.rgb = C_CARD; m2.line.color.rgb = C_CYAN
    m2.text_frame.paragraphs[0].text = "99.67%"
    m2.text_frame.paragraphs[0].font.size = Pt(28); m2.text_frame.paragraphs[0].font.bold = True; m2.text_frame.paragraphs[0].font.color.rgb = C_CYAN
    p_m2 = m2.text_frame.add_paragraph()
    p_m2.text = "PRECISION (298/299)"
    p_m2.font.size = Pt(9.5); p_m2.font.bold = True; p_m2.font.color.rgb = C_MUTED

    m3 = s8.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(6.8), Inches(1.8), Inches(2.7), Inches(1.4))
    m3.fill.solid(); m3.fill.fore_color.rgb = C_CARD; m3.line.color.rgb = C_PURPLE
    m3.text_frame.paragraphs[0].text = "99.50%"
    m3.text_frame.paragraphs[0].font.size = Pt(28); m3.text_frame.paragraphs[0].font.bold = True; m3.text_frame.paragraphs[0].font.color.rgb = C_PURPLE
    p_m3 = m3.text_frame.add_paragraph()
    p_m3.text = "F1-SCORE"
    p_m3.font.size = Pt(9.5); p_m3.font.bold = True; p_m3.font.color.rgb = C_MUTED

    m4 = s8.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(9.8), Inches(1.8), Inches(2.7), Inches(1.4))
    m4.fill.solid(); m4.fill.fore_color.rgb = C_CARD; m4.line.color.rgb = C_GOLD
    m4.text_frame.paragraphs[0].text = "0.67%"
    m4.text_frame.paragraphs[0].font.size = Pt(28); m4.text_frame.paragraphs[0].font.bold = True; m4.text_frame.paragraphs[0].font.color.rgb = C_GOLD
    p_m4 = m4.text_frame.add_paragraph()
    p_m4.text = "FALSE POSITIVE RATE (1/150)"
    p_m4.font.size = Pt(9.5); p_m4.font.bold = True; p_m4.font.color.rgb = C_MUTED

    add_card(s8, Inches(0.8), Inches(3.5), Inches(11.7), Inches(3.2), "Baseline Comparison & Latency Breakdown", [
        "Experiment A (Unprotected Baseline): Attack exposure rate was 100.0% (300/300 attacks reached model; 100/100 PII records leaked).",
        "Experiment B (Protected Gateway): Reduced successful attack/exposure rate from 100.0% to 0.67% (Delta improvement: +99.33%).",
        "False Positive Control: Only 1 benign query flagged out of 150 (99.33% Specificity on complex user inquiries).",
        "Processing Latency: Mean inspection latency of 12.75 ms (P95: 22.2 ms) — completely imperceptible to end users during streaming.",
        "Automated Test Suite: 16/16 comprehensive pytest test suites passing in under 10 seconds."
    ])

    # ==================== SLIDE 9: Streamlit SOC Dashboard ====================
    s9 = prs.slides.add_slide(blank_layout)
    set_slide_bg(s9)
    add_header(s9, "Operational Visibility • Security Monitoring", "Streamlit SOC Security Operations Dashboard", 9)

    add_card(s9, Inches(0.8), Inches(1.8), Inches(5.6), Inches(4.9), "6 Interactive Dashboard Modules", [
        "1. Overview KPI Hub: Real-time traffic breakdown (ALLOW, SANITIZE, BLOCK), average risk score, PII counts.",
        "2. Live Interactive Playground: Test prompts in real-time with instant visualization of matched rules, redacted entities & risk scores.",
        "3. Threat Monitoring: Real-time alert feed tracking high-risk prompt injection attempts and jailbreaks.",
        "4. Searchable Audit Logs: Secret-free SQLite database records with client IP, timestamp, matched rule IDs, and latency.",
        "5. Plotly Analytics: Hourly traffic trends, attack vector frequency distributions, and risk distribution charts.",
        "6. Live Policy Configuration: Dynamic switching of sensitivity presets (Strict, Balanced, Permissive)."
    ], border_color=C_CYAN)

    add_card(s9, Inches(6.8), Inches(1.8), Inches(5.6), Inches(4.9), "Enterprise & Cloud Architecture Alignment", [
        "Designed to mirror enterprise cloud security architectures:",
        "• Microsoft Foundry: Agentic security governance & runtime policy enforcement.",
        "• Microsoft Defender for Cloud: Automated threat alerting & anomalous payload inspection.",
        "• Microsoft Entra ID: X-API-Key role-based administrative endpoint authorization.",
        "• Azure Monitor / Log Analytics: Structured secret-free security telemetry.",
        "• Azure Key Vault: Centralized API credential and secret management."
    ], border_color=C_PURPLE)

    # ==================== SLIDE 10: Conclusion & Defense ====================
    s10 = prs.slides.add_slide(blank_layout)
    set_slide_bg(s10)
    add_header(s10, "Summary & Impact • Project Defense", "Conclusion: Securing the Generative AI Enterprise", 10)

    add_card(s10, Inches(0.8), Inches(1.8), Inches(5.6), Inches(4.9), "Key Engineering Accomplishments", [
        "Modular Multi-Layer Defense: Architected and implemented a complete 6-layer firewall protecting LLM applications.",
        "State-of-the-Art Performance: Achieved 99.33% attack recall and 99.67% precision across real-world benchmarks.",
        "Privacy by Design: 100% PII detection and autonomous redaction preventing sensitive data exposure.",
        "Production-Grade Software: 16 passing pytest suites, FastAPI REST architecture, and interactive Streamlit SOC UI.",
        "Open-Source & Locally Hosted: Operates 100% offline without recurring API costs or cloud dependencies."
    ], border_color=C_GREEN)

    add_card(s10, Inches(6.8), Inches(1.8), Inches(5.6), Inches(4.9), "Future Research Directions", [
        "• Multilingual LLM Defense: Expanding ML n-gram tokenizers to low-resource Indic languages (Hindi, Telugu, Tamil).",
        "• Multimodal Prompt Injection: Extending gateway inspection to vision-language models (adversarial image patches).",
        "• Adaptive Reinforcement Learning: Dynamically updating risk rule weights based on real-time feedback loops.",
        "• Hardware Acceleration: Compiling LinearSVC inference to ONNX runtime for sub-5ms enterprise throughput."
    ], border_color=C_CYAN)

    prs.save(output_pptx)
    print(f"SecureAI Gateway presentation created at: {output_pptx}")

if __name__ == "__main__":
    out = sys.argv[1] if len(sys.argv) > 1 else "SecureAI_Gateway_Presentation.pptx"
    build_secure_ai_deck(out)
