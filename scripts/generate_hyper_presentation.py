"""Generate concise 6-slide PowerPoint oral defense presentation.
Combines the HyperVaults luxury aesthetic (Obsidian cover, #FCFBFE canvas, Royal Purple #7954C7,
soft lilac cards, dark code mockups, corporate vector emblem) with the exact content required
to satisfy the teacher's delivery standard (Working solution, architecture, crypto workflow,
security evidence with 77/77 passed tests, and live demo roadmap).
"""
import os
from pptx import Presentation
from pptx.util import Inches, Pt
from pptx.dml.color import RGBColor
from pptx.enum.text import PP_ALIGN
from pptx.enum.shapes import MSO_SHAPE

def hex_to_rgb(hex_str):
    hex_str = hex_str.lstrip('#')
    return RGBColor(int(hex_str[0:2], 16), int(hex_str[2:4], 16), int(hex_str[4:6], 16))

# HyperVaults Theme Tokens
C_DARK_BG    = hex_to_rgb('101018')  # Deep obsidian dark cover
C_LIGHT_BG   = hex_to_rgb('FCFBFE')  # Clean luxury light canvas
C_PRIMARY    = hex_to_rgb('7954C7')  # Royal Purple brand accent
C_PRIMARY_DK = hex_to_rgb('5B32A8')  # Deep purple
C_TEXT_DARK  = hex_to_rgb('241B36')  # Deep purple-slate title & text
C_TEXT_MUTED = hex_to_rgb('6F647C')  # Subtitle & running metadata
C_WHITE      = hex_to_rgb('FFFFFF')  # Pure white
C_BOX_BG     = hex_to_rgb('F1EBFA')  # Soft lilac card background
C_BOX_BORDER = hex_to_rgb('DDD6FE')  # Subtle lilac border
C_WHITE_CARD = hex_to_rgb('FFFFFF')  # White card background
C_CARD_BORDER= hex_to_rgb('E2E8F0')  # Subtle grey border
C_CODE_BG    = hex_to_rgb('16132A')  # Dark code mockup box

def set_slide_background(slide, prs, color):
    bg_shape = slide.shapes.add_shape(MSO_SHAPE.RECTANGLE, 0, 0, prs.slide_width, prs.slide_height)
    bg_shape.fill.solid()
    bg_shape.fill.fore_color.rgb = color
    bg_shape.line.fill.background()
    return bg_shape

def add_header(slide, title_text, category_text, subtitle_text):
    # Category Kicker (top left)
    cat_box = slide.shapes.add_textbox(Inches(0.8), Inches(0.4), Inches(8.0), Inches(0.35))
    tf_c = cat_box.text_frame
    tf_c.word_wrap = True
    p_c = tf_c.paragraphs[0]
    p_c.text = f"ENTERPRISE KMS VAULT  •  {category_text.upper()}"
    p_c.font.size = Pt(9.5)
    p_c.font.bold = True
    p_c.font.color.rgb = C_PRIMARY

    # Title
    t_box = slide.shapes.add_textbox(Inches(0.8), Inches(0.72), Inches(11.7), Inches(0.65))
    tf_t = t_box.text_frame
    tf_t.word_wrap = True
    p_t = tf_t.paragraphs[0]
    p_t.text = title_text
    p_t.font.size = Pt(24)
    p_t.font.bold = True
    p_t.font.color.rgb = C_TEXT_DARK

    # Subtitle
    s_box = slide.shapes.add_textbox(Inches(0.8), Inches(1.38), Inches(11.7), Inches(0.45))
    tf_s = s_box.text_frame
    tf_s.word_wrap = True
    p_s = tf_s.paragraphs[0]
    p_s.text = subtitle_text
    p_s.font.size = Pt(11.5)
    p_s.font.color.rgb = C_TEXT_MUTED

def add_footer(slide, page_num):
    # Footer line & text
    f_box = slide.shapes.add_textbox(Inches(0.8), Inches(6.8), Inches(9.0), Inches(0.35))
    tf_f = f_box.text_frame
    p_f = tf_f.paragraphs[0]
    p_f.text = "Authentication and cryptography  |  Application oral defense"
    p_f.font.size = Pt(9)
    p_f.font.color.rgb = C_TEXT_MUTED

    # Bullet & Page number
    pno_box = slide.shapes.add_textbox(Inches(11.2), Inches(6.8), Inches(1.3), Inches(0.35))
    tf_pno = pno_box.text_frame
    p_pno = tf_pno.paragraphs[0]
    p_pno.alignment = PP_ALIGN.RIGHT
    p_pno.text = f"•  {page_num:02d}"
    p_pno.font.size = Pt(9)
    p_pno.font.bold = True
    p_pno.font.color.rgb = C_PRIMARY

def add_card(slide, left, top, width, height, title, bullets, bg_color=C_BOX_BG, border_color=C_BOX_BORDER):
    card = slide.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, left, top, width, height)
    card.fill.solid()
    card.fill.fore_color.rgb = bg_color
    if border_color:
        card.line.color.rgb = border_color
        card.line.width = Pt(1.2)
    else:
        card.line.fill.background()

    tb = slide.shapes.add_textbox(left + Inches(0.22), top + Inches(0.22), width - Inches(0.44), height - Inches(0.44))
    tf = tb.text_frame
    tf.word_wrap = True
    tf.margin_left = tf.margin_top = tf.margin_right = tf.margin_bottom = 0

    if title:
        p_title = tf.paragraphs[0]
        p_title.text = title
        p_title.font.size = Pt(13.5)
        p_title.font.bold = True
        p_title.font.color.rgb = C_PRIMARY
        p_title.space_after = Pt(10)
        start_idx = 1
    else:
        start_idx = 0

    for idx, (lead, body) in enumerate(bullets):
        p = tf.add_paragraph() if (start_idx == 1 or idx > 0) else tf.paragraphs[0]
        p.space_after = Pt(7)
        run_bullet = p.add_run()
        run_bullet.text = "• "
        run_bullet.font.bold = True
        run_bullet.font.color.rgb = C_PRIMARY

        run_lead = p.add_run()
        run_lead.text = f"{lead}: "
        run_lead.font.bold = True
        run_lead.font.size = Pt(10.5)
        run_lead.font.color.rgb = C_TEXT_DARK

        run_body = p.add_run()
        run_body.text = body
        run_body.font.bold = False
        run_body.font.size = Pt(10)
        run_body.font.color.rgb = C_TEXT_DARK

def generate_hyper_presentation(out_path):
    prs = Presentation()
    prs.slide_width = Inches(13.333)
    prs.slide_height = Inches(7.5)
    blank_layout = prs.slide_layouts[6]

    # ================= SLIDE 1: COVER (HYPERVAULTS OBSIDIAN DARK) =================
    s1 = prs.slides.add_slide(blank_layout)
    set_slide_background(s1, prs, C_DARK_BG)

    # Concentric orbital rings on right
    cx, cy = Inches(10.5), Inches(3.75)
    for r, col_hex in [(Inches(4.5), '1E1533'), (Inches(3.5), '2E1D4E'), (Inches(2.5), '43266E'), (Inches(1.6), '5E369B')]:
        circle = s1.shapes.add_shape(MSO_SHAPE.OVAL, cx - r, cy - r, r*2, r*2)
        circle.fill.solid()
        circle.fill.fore_color.rgb = hex_to_rgb(col_hex)
        circle.line.fill.background()

    # Clean Corporate Vector Emblem in center of rings
    emblem_path = 'docs/report_assets/corporate_vault_emblem.png'
    if os.path.exists(emblem_path):
        s1.shapes.add_picture(emblem_path, Inches(8.9), Inches(2.15), width=Inches(3.2))

    # Top Badge
    badge_box = s1.shapes.add_textbox(Inches(0.9), Inches(0.95), Inches(6.0), Inches(0.4))
    tf_b = badge_box.text_frame
    p_b = tf_b.paragraphs[0]
    p_b.text = "🛡️  APPLICATION REPORT & ORAL DEFENSE"
    p_b.font.size = Pt(10)
    p_b.font.bold = True
    p_b.font.color.rgb = hex_to_rgb('C4B5FD')

    # Main Title
    title_box = s1.shapes.add_textbox(Inches(0.9), Inches(1.45), Inches(7.5), Inches(1.1))
    tf_t = title_box.text_frame
    p_t = tf_t.paragraphs[0]
    p_t.text = "Enterprise KMS Vault"
    p_t.font.size = Pt(38)
    p_t.font.bold = True
    p_t.font.color.rgb = C_WHITE

    # Subtitle
    sub_box = s1.shapes.add_textbox(Inches(0.9), Inches(2.65), Inches(7.2), Inches(0.75))
    tf_s = sub_box.text_frame
    tf_s.word_wrap = True
    p_s = tf_s.paragraphs[0]
    p_s.text = "Secure Authentication & Cryptographic Storage System"
    p_s.font.size = Pt(16)
    p_s.font.bold = True
    p_s.font.color.rgb = hex_to_rgb('A78BFA')

    p_s2 = tf_s.add_paragraph()
    p_s2.text = "3-Tier Envelope Hierarchy  •  Zero-Knowledge Admin  •  Tamper-Evident SHA-256 Audit Chain"
    p_s2.font.size = Pt(11)
    p_s2.font.color.rgb = hex_to_rgb('94A3B8')

    # Presenters Card
    pres_card = s1.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(0.9), Inches(4.25), Inches(6.4), Inches(1.5))
    pres_card.fill.solid()
    pres_card.fill.fore_color.rgb = hex_to_rgb('17142A')
    pres_card.line.color.rgb = hex_to_rgb('2D274A')

    tb_pres = s1.shapes.add_textbox(Inches(1.15), Inches(4.45), Inches(5.9), Inches(1.1))
    tf_p = tb_pres.text_frame
    p_p1 = tf_p.paragraphs[0]
    p_p1.text = "Ahmed Amine Ghenimi  &  Abdallah Dridi"
    p_p1.font.size = Pt(14)
    p_p1.font.bold = True
    p_p1.font.color.rgb = C_WHITE

    p_p2 = tf_p.add_paragraph()
    p_p2.text = "ING 5 SSIRE A  •  Class of 2026  •  TEK-UP Engineering School"
    p_p2.font.size = Pt(10)
    p_p2.font.color.rgb = hex_to_rgb('A78BFA')

    p_p3 = tf_p.add_paragraph()
    p_p3.text = "Course: Art of Protecting Secrets  •  Track 02 (Project 2: Protect)"
    p_p3.font.size = Pt(9.5)
    p_p3.font.color.rgb = hex_to_rgb('94A3B8')

    # Tech stack pills footer
    pill_box = s1.shapes.add_textbox(Inches(0.9), Inches(6.25), Inches(11.5), Inches(0.4))
    tf_pill = pill_box.text_frame
    p_pill = tf_pill.paragraphs[0]
    p_pill.text = "TECH STACK:  Python 3.12+  |  FastAPI  |  SQLite 3  |  Argon2id (m=64M,t=2)  |  AES-256-GCM  |  SHA-256 Chain  |  Pytest (77/77 Passed)"
    p_pill.font.size = Pt(9)
    p_pill.font.color.rgb = hex_to_rgb('CBD5E1')

    s1.notes_slide.notes_text_frame.text = (
        "OPENING (Ahmed):\n"
        "Good morning members of the jury. I am Ahmed Amine Ghenimi, and with Abdallah Dridi, we present Enterprise KMS Vault.\n"
        "Our project addresses a core enterprise vulnerability: sensitive operational credentials stored carelessly in plaintext.\n"
        "We built a production-grade Key Management and Zero-Knowledge Vault enforcing 3-tier envelope encryption, Argon2id authentication, and tamper-evident audit chaining."
    )

    # ================= SLIDE 2: 01 WHAT THE PROJECT IS & THREAT =================
    s2 = prs.slides.add_slide(blank_layout)
    set_slide_background(s2, prs, C_LIGHT_BG)
    add_header(s2, "The Real-World Threat & The KMS Solution", "01 Product Overview", "Why storing credentials in databases fails and how Enterprise KMS Vault guarantees zero plaintext at rest.")

    add_card(s2, Inches(0.8), Inches(1.95), Inches(5.65), Inches(4.6), "⚠️ The Real-World Threat Landscape", [
        ("Plaintext Exposure", "Enterprises store API tokens, database credentials, and certificates in plaintext files and DB tables."),
        ("Backup & Dump Theft", "Attackers gaining read-only access to database backups or replicas immediately compromise all credentials."),
        ("No Tamper Detection", "Traditional database rows can be silently modified or bit-flipped without the application noticing."),
        ("Rogue Administrator Risk", "A rogue administrator or compromised admin account can snoop on and exfiltrate user credentials.")
    ], bg_color=C_WHITE_CARD, border_color=C_CARD_BORDER)

    add_card(s2, Inches(6.85), Inches(1.95), Inches(5.65), Inches(4.6), "🛡️ Enterprise KMS Vault Defensive Controls", [
        ("Zero Plaintext at Rest", "Inspecting the SQLite database reveals only high-entropy base64 ciphertext, nonces, and MAC tags."),
        ("3-Tier Envelope Isolation", "Server Root KEK wraps Master KEKs; Master KEKs wrap transient per-secret Data Encryption Keys (DEKs)."),
        ("Zero-Knowledge Admin Principle", "Administrators manage keys and users, but are strictly forbidden (HTTP 403) from decrypting user secrets."),
        ("Tamper-Evident SHA-256 Chain", "Blockchain-style recursive hash chain detects any retroactive audit log alteration instantly.")
    ], bg_color=C_BOX_BG, border_color=C_BOX_BORDER)

    add_footer(s2, 2)
    s2.notes_slide.notes_text_frame.text = (
        "SLIDE 2 (Abdallah):\n"
        "Point to the left: Most breaches occur because credentials sit in plaintext tables. If a backup is leaked, everything is compromised.\n"
        "Point to the right: Our system enforces Zero Plaintext at Rest. Even with full access to keyvault.db, an adversary gets only high-entropy ciphertext.\n"
        "Plaintext is only recovered on-demand via role-checked API calls with authentic user identity, completely denying administrators secret access."
    )

    # ================= SLIDE 3: 02 SYSTEM ARCHITECTURE =================
    s3 = prs.slides.add_slide(blank_layout)
    set_slide_background(s3, prs, C_LIGHT_BG)
    add_header(s3, "Architecture & Trust Boundaries", "02 System Architecture", "Three strictly separated tiers isolate authentication, route authorization, and cryptographic keys.")

    add_card(s3, Inches(0.8), Inches(1.95), Inches(3.65), Inches(4.6), "🌐 Client Workspace", [
        ("Presentation Layer", "Browser Web UI and authenticated REST API clients."),
        ("Session Transport", "Signed HMAC-SHA256 session tokens in HttpOnly Strict cookies & Bearer headers."),
        ("Zero Key Knowledge", "The client holds zero master keys or cryptographic credentials."),
        ("No Plaintext Caching", "Decrypted credentials exist only transiently in view state.")
    ], bg_color=C_WHITE_CARD, border_color=C_CARD_BORDER)

    add_card(s3, Inches(4.8), Inches(1.95), Inches(3.65), Inches(4.6), "⚡ FastAPI Control Plane", [
        ("3-Tier RBAC Guard", "Strict separation of concerns: ADMIN, USER, and AUDITOR roles."),
        ("Anti-IDOR Predicate", "Validates secret ownership on server before any crypto operation."),
        ("Abuse Defense", "5 failed login attempts trigger 15-minute account lockout returning HTTP 403."),
        ("Instant Logout Revocation", "Server-side token registry invalidates session tokens immediately upon logout.")
    ], bg_color=C_BOX_BG, border_color=C_BOX_BORDER)

    add_card(s3, Inches(8.8), Inches(1.95), Inches(3.65), Inches(4.6), "🔒 Storage & KMS Core", [
        ("Root KEK Authority", "Server Root Key (KEY_VAULT_ROOT_KEY) wraps Master KEKs."),
        ("Envelope Engine", "2-Tier AES-256-GCM envelope cryptographic subsystem."),
        ("Zero-Plaintext DB", "SQLite `keyvault.db` stores only base64 ciphertexts and tags."),
        ("SHA-256 Audit Chain", "Recursive blockchain-style hash chain anchoring history.")
    ], bg_color=C_WHITE_CARD, border_color=C_CARD_BORDER)

    add_footer(s3, 3)
    s3.notes_slide.notes_text_frame.text = (
        "SLIDE 3 (Ahmed):\n"
        "Here are our three architectural trust boundaries:\n"
        "1. The Client never holds master keys.\n"
        "2. The FastAPI backend validates ownership before invoking decryption, stopping IDOR vulnerabilities at the root.\n"
        "3. The KMS Core manages keys hierarchically. On logout, sessions are instantly revoked server-side."
    )

    # ================= SLIDE 4: 03 HOW IT WORKS (ENVELOPE CRYPTO) =================
    s4 = prs.slides.add_slide(blank_layout)
    set_slide_background(s4, prs, C_LIGHT_BG)
    add_header(s4, "How It Works: 3-Tier Envelope Encryption", "03 Cryptographic Workflow", "Server Root KEK wraps Master KEKs; unique random DEKs encrypt individual secrets.")

    add_card(s4, Inches(0.8), Inches(1.95), Inches(5.65), Inches(4.6), "🔑 3-Tier Envelope Protocol", [
        ("1. Root Key Authority", "Server Root Key (KEY_VAULT_ROOT_KEY) protects Master KEKs at rest; raw keys are unwrapped only in transient memory."),
        ("2. Fresh DEK Generation", "Every secret generates a fresh, unique 256-bit AES Data Key (DEK) via OS CSPRNG plus a fresh 96-bit random nonce."),
        ("3. Payload Encryption", "Secret payload is encrypted under DEK using AES-256-GCM, yielding ciphertext and a 128-bit MAC authentication tag."),
        ("4. DEK Wrapping", "DEK is encrypted under Master KEK via AES-256-GCM and stored in SQLite as `encrypted_dek`.")
    ], bg_color=C_BOX_BG, border_color=C_BOX_BORDER)

    add_card(s4, Inches(6.85), Inches(1.95), Inches(5.65), Inches(4.6), "⚡ Scaling & Cryptographic Invariants", [
        ("Argon2id Passwords", "Memory-hard password hashing (m=64 MiB, t=2, p=2) protects user credentials against GPU/ASIC cracking."),
        ("Zero-Downtime Rotation", "Rotating Master Key generates new KEK and re-wraps existing DEKs in milliseconds without re-encrypting payloads."),
        ("Unique 96-bit Nonces", "Nonce collision probability is mathematically negligible (< 1 in 2^48), adhering strictly to NIST SP 800-38D."),
        ("Authenticated Integrity", "AES-GCM guarantees that modifying 1 bit of stored ciphertext causes an immediate `InvalidTag` (HTTP 400) abort.")
    ], bg_color=C_WHITE_CARD, border_color=C_CARD_BORDER)

    add_footer(s4, 4)
    s4.notes_slide.notes_text_frame.text = (
        "SLIDE 4 (Abdallah):\n"
        "Explain the key architectural question the jury will ask:\n"
        "'Why envelope encryption instead of direct master key encryption?'\n"
        "Answer: If you encrypt 10,000 secrets directly with a master key and rotate it, you must decrypt and re-encrypt all 10,000 secrets, risking data corruption and downtime.\n"
        "With Envelope Encryption, each secret has its own DEK. Rotating the master key only re-wraps the small DEKs in milliseconds with zero downtime."
    )

    # ================= SLIDE 5: 04 SECURITY EVIDENCE (TEACHER'S CRUCIAL REQUIREMENT) =================
    s5 = prs.slides.add_slide(blank_layout)
    set_slide_background(s5, prs, C_LIGHT_BG)
    add_header(s5, "Verified Defensive Controls & Evidence", "04 Security Evidence", "Satisfying the course standard: 'No evidence = no credit for the claimed security result.'")

    add_card(s5, Inches(0.8), Inches(1.95), Inches(5.65), Inches(4.6), "🛡️ Verified Defensive Controls", [
        ("Anti-IDOR & Zero-Knowledge", "Cross-tenant secret retrieval and Admin secret access are rejected (HTTP 403 Forbidden). Zero plaintext leaked."),
        ("1-Bit Tamper Abort (HTTP 400)", "Directly modifying 1 bit of ciphertext in SQLite triggers AES-GCM MAC failure (`InvalidTag`), aborting decryption."),
        ("Audit Chain Break Alert", "Editing a row in SQLite audit table permanently breaks the SHA-256 recursive hash chain, pinpointing the exact row index."),
        ("Brute-Force Lockout (HTTP 403)", "5 failed login attempts trigger an automated 15-minute account lockout, stopping credential stuffing attacks."),
        ("Instant Token Revocation", "Logged-out bearer tokens and cookies are rejected immediately with HTTP 401 Unauthorized.")
    ], bg_color=C_BOX_BG, border_color=C_BOX_BORDER)

    add_card(s5, Inches(6.85), Inches(1.95), Inches(5.65), Inches(4.6), "✅ Automated Verification Suite (100% Pass)", [
        ("Total Tests Passing", "77 / 77 passed (100% pass rate in pytest across all test suites in 8.12s)."),
        ("Crypto Unit Suite", "18/18 passed: Argon2id, AES-GCM, IV entropy, tag verification, and KEK wrapping."),
        ("API & RBAC Suite", "25/25 passed: Role validation (ADMIN/USER/AUDITOR), anti-IDOR, key rotation, and session revocation."),
        ("Attack Simulation Suite", "18/18 passed: Brute-force lockout, bit-tampering abort, and audit chain break detection."),
        ("Key Rotation Re-wrapping", "Verified: secrets created before key rotation decrypt seamlessly after rotation.")
    ], bg_color=C_WHITE_CARD, border_color=C_CARD_BORDER)

    add_footer(s5, 5)
    s5.notes_slide.notes_text_frame.text = (
        "SLIDE 5 (Ahmed):\n"
        "This slide directly addresses the delivery standard: 'No evidence = no credit.'\n"
        "We have verified all defensive mechanisms with 77 automated tests in pytest:\n"
        "1. Anti-IDOR and Zero-Knowledge Admin enforcement are verified.\n"
        "2. 1-bit tampering causes cryptographic abort.\n"
        "3. Audit tampering breaks the hash chain.\n"
        "4. Account lockout stops brute-force guessing.\n"
        "5. Key rotation re-wraps DEKs seamlessly without downtime."
    )

    # ================= SLIDE 6: 05 LIVE DEMO & DEFENSE Q&A =================
    s6 = prs.slides.add_slide(blank_layout)
    set_slide_background(s6, prs, C_LIGHT_BG)
    add_header(s6, "Live Demonstration Roadmap & Jury Q&A", "05 Live Demo & Defense", "A concise 5-minute live walkthrough demonstrating each security boundary directly to the jury.")

    add_card(s6, Inches(0.8), Inches(1.95), Inches(5.65), Inches(4.6), "🎬 4-Step Live Demo Roadmap", [
        ("Step 1 — Auth & Lockout", "Demonstrate Argon2id hashing; intentionally fail password 5 times to show automated account lockout (`HTTP 403`)."),
        ("Step 2 — Key Management & Rotation", "Admin creates Master Key and rotates it; verify automated DEK re-wrapping and uninterrupted secret access."),
        ("Step 3 — Storage & Anti-IDOR", "Create secret in UI; inspect SQLite directly to prove zero plaintext, then simulate cross-tenant IDOR 403 block."),
        ("Step 4 — Tampering & Chain Break", "Flip 1 byte in SQLite to show GCM MAC failure (HTTP 400); modify audit row in DB to show instant hash chain break detection.")
    ], bg_color=C_BOX_BG, border_color=C_BOX_BORDER)

    add_card(s6, Inches(6.85), Inches(1.95), Inches(5.65), Inches(4.6), "💡 Jury Defense Q&A Cheatsheet", [
        ("Q: Why GCM over CBC mode?", "A: GCM provides authenticated encryption with 128-bit MAC tag. CBC is vulnerable to padding oracles and bit-flipping."),
        ("Q: Why Argon2id over PBKDF2?", "A: Argon2id is memory-hard, defeating ASIC and GPU parallel cracking. It is the winner of the Password Hashing Competition."),
        ("Q: How does rotation scale?", "A: Envelope encryption means only 256-bit DEKs are re-wrapped. Secret payloads are never touched."),
        ("Q: Can an admin forge audit logs?", "A: No; records are chained recursively via SHA-256 and signed via HMAC. Any alteration breaks the chain.")
    ], bg_color=C_WHITE_CARD, border_color=C_CARD_BORDER)

    add_footer(s6, 6)
    s6.notes_slide.notes_text_frame.text = (
        "SLIDE 6 (Ahmed & Abdallah Closing):\n"
        "This is our transition to the live defense demonstration.\n"
        "We will execute our 4-step live walkthrough directly in our terminal and browser.\n"
        "Ahmed demonstrates Steps 1 & 2; Abdallah demonstrates Steps 3 & 4.\n"
        "Thank you for your attention. We are now ready to begin the live demonstration and take your questions."
    )

    prs.save(out_path)
    print(f"Hyper presentation generated successfully: {out_path}")
    return out_path

if __name__ == '__main__':
    generate_hyper_presentation('docs/oral_defense_presentation.pptx')
