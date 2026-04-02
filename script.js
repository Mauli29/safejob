/* =====================================================
   SafeJob AI — script.js
   Handles: navbar, FAQ, analyzer fetch + display
   ===================================================== */

'use strict';

const BACKEND_URL = 'http://127.0.0.1:5000';

/* ─────────────────────────────────────────────────────
   NAVBAR — mobile hamburger toggle
───────────────────────────────────────────────────── */
const hamburger  = document.getElementById('hamburger');
const mobileMenu = document.getElementById('mobileMenu');

if (hamburger && mobileMenu) {
  hamburger.addEventListener('click', (e) => {
    e.stopPropagation();
    mobileMenu.classList.toggle('open');
  });
  document.addEventListener('click', (e) => {
    if (!mobileMenu.contains(e.target) && !hamburger.contains(e.target)) {
      mobileMenu.classList.remove('open');
    }
  });
}

/* ─────────────────────────────────────────────────────
   FAQ ACCORDION (about.html)
───────────────────────────────────────────────────── */
function toggleFaq(btn) {
  const item   = btn.closest('.faq-item');
  const isOpen = item.classList.contains('open');
  document.querySelectorAll('.faq-item.open').forEach(i => i.classList.remove('open'));
  if (!isOpen) item.classList.add('open');
}

/* ─────────────────────────────────────────────────────
   ANALYZER PAGE — only runs on analyze.html
───────────────────────────────────────────────────── */
const analyzeBtn = document.getElementById('analyzeBtn');
if (analyzeBtn) initAnalyzePage();

function initAnalyzePage() {

  /* DOM refs */
  const jobTextEl      = document.getElementById('jobText');
  const charCountEl    = document.getElementById('charCount');
  const exampleBtn     = document.getElementById('exampleBtn');
  const clearBtn       = document.getElementById('clearBtn');
  const analyzeBtn     = document.getElementById('analyzeBtn');
  const resultsCard    = document.getElementById('resultsCard');
  const loadingState   = document.getElementById('loadingState');
  const resultContent  = document.getElementById('resultContent');
  const ringProgress   = document.getElementById('ringProgress');
  const scoreCenter    = document.getElementById('scoreCenter');
  const scoreNum       = document.getElementById('scoreNum');
  const riskBadge      = document.getElementById('riskBadgeLarge');
  const classText      = document.getElementById('classificationText');
  const riskBarFill    = document.getElementById('riskBarFill');
  const warnSection    = document.getElementById('warningSection');
  const warnIcon       = document.getElementById('warningIcon');
  const warnTitle      = document.getElementById('warningTitle');
  const warnMsg        = document.getElementById('warningMessage');
  const kwGrid         = document.getElementById('keywordsGrid');
  const kwCount        = document.getElementById('keywordCount');
  const highlightEl    = document.getElementById('highlightedText');
  const toggleHighBtn  = document.getElementById('toggleHighlight');
  const safetyTipsEl   = document.getElementById('safetyTips');
  const newScanBtn     = document.getElementById('newScanBtn');
  const copyBtn        = document.getElementById('copyResultBtn');
  const downloadPdfBtn = document.getElementById('downloadPdfBtn');

  const CIRCUMFERENCE = 2 * Math.PI * 50; // ≈ 314.16 (r=50)
  const MAX_CHARS     = 5000;

  /* ── Sample fake job offer (example button) ────── */
  const EXAMPLE_TEXT =
`🚨 URGENT HIRING! Work From Home — Easy Money Guaranteed!

We are looking for attractive females aged 18–30 for immediate joining.
No experience required! No qualifications needed — anyone can do this!

Position  : Data Entry / Form Filling
Salary    : ₹30,000–₹50,000/month (100% Guaranteed Income)
Location  : Work from home

HOW TO APPLY:
1. Pay ₹500 registration fee to receive your work kit (refundable!)
2. Send your recent photos along with your application
3. Complete easy tasks from home and get paid daily

Urgent — limited seats available. Act now, offer expires today!
WhatsApp only: +91-XXXXXXXXXX  |  No calls please.

Seats filling fast! Last chance! 100% guaranteed job!`;

  /* ── Character counter ─────────────────────────── */
  jobTextEl.addEventListener('input', updateCharCount);
  function updateCharCount() {
    const len = jobTextEl.value.length;
    charCountEl.textContent = `${len} / ${MAX_CHARS} characters`;
    charCountEl.classList.toggle('warn', len > MAX_CHARS * 0.85);
  }

  /* ── Example button ────────────────────────────── */
  exampleBtn.addEventListener('click', () => {
    jobTextEl.value = EXAMPLE_TEXT;
    updateCharCount();
    jobTextEl.focus();
  });

  /* ── Clear button ──────────────────────────────── */
  clearBtn.addEventListener('click', () => {
    jobTextEl.value = '';
    updateCharCount();
    resultsCard.style.display = 'none';
    jobTextEl.focus();
  });

  /* ── Analyze — button click & Ctrl+Enter ───────── */
  analyzeBtn.addEventListener('click', runAnalysis);
  jobTextEl.addEventListener('keydown', (e) => {
    if (e.ctrlKey && e.key === 'Enter') runAnalysis();
  });

  /* ── New Scan ──────────────────────────────────── */
  newScanBtn.addEventListener('click', () => {
    jobTextEl.value = '';
    updateCharCount();
    resultsCard.style.display = 'none';
    window.scrollTo({ top: 0, behavior: 'smooth' });
    jobTextEl.focus();
  });

  /* ── Copy Report ───────────────────────────────── */
  copyBtn.addEventListener('click', () => copyReport());

  /* ── Download PDF ───────────────────────────────── */
  if (downloadPdfBtn) {
    downloadPdfBtn.addEventListener('click', () => downloadPdf());
  }

  /* ══════════════════════════════════════════════════
     MAIN ANALYSIS FUNCTION
  ══════════════════════════════════════════════════ */
  async function runAnalysis() {
    const text = jobTextEl.value.trim();

    if (!text) {
      flashError('Please paste a job offer, email, or message to analyze.');
      return;
    }
    if (text.length < 10) {
      flashError('Please provide at least 10 characters to get a meaningful result.');
      return;
    }

    /* Show results card in loading state */
    resultsCard.style.display = 'block';
    showState('loading');
    resultsCard.scrollIntoView({ behavior: 'smooth', block: 'nearest' });

    analyzeBtn.disabled = true;
    analyzeBtn.querySelector('.btn-label').textContent = 'Analyzing…';

    const stepInterval = startLoadingSteps();

    try {
      const response = await fetch(`${BACKEND_URL}/analyze`, {
        method:  'POST',
        headers: { 'Content-Type': 'application/json' },
        body:    JSON.stringify({ text }),
      });

      clearInterval(stepInterval);

      if (!response.ok) {
        const errBody = await response.json().catch(() => ({}));
        throw new Error(errBody.error || `Server responded with status ${response.status}`);
      }

      const data = await response.json();
      showState('result');
      displayResults(data, text);

    } catch (err) {
      clearInterval(stepInterval);
      showState('result');

      const isNetworkError = err instanceof TypeError && err.message.toLowerCase().includes('fetch');
      displayError(
        isNetworkError
          ? 'Cannot reach the backend.\n\nMake sure the Flask server is running:\n  cd "backend" && python app.py'
          : (err.message || 'An unexpected error occurred.')
      );
    } finally {
      analyzeBtn.disabled = false;
      analyzeBtn.querySelector('.btn-label').textContent = 'Analyze Job Offer';
    }
  }

  /* ══════════════════════════════════════════════════
     DISPLAY RESULTS
  ══════════════════════════════════════════════════ */
  function displayResults(data, originalText) {
    const { risk_score, risk_level, classification, flagged_keywords = [] } = data;
    const rl = risk_level || 'low';

    /* ① Score ring animation */
    ringProgress.setAttribute('class', `ring-progress ring-${rl}`);
    setTimeout(() => {
      ringProgress.style.strokeDashoffset = CIRCUMFERENCE - (risk_score / 100) * CIRCUMFERENCE;
    }, 50);

    /* ② Score counter (0 → score) */
    scoreCenter.className = `score-center ${rl}`;
    animateValue(scoreNum, 0, risk_score, 1000);

    /* ③ Risk badge */
    riskBadge.textContent = `${rl.toUpperCase()} RISK`;
    riskBadge.className   = `risk-badge-large ${rl}`;

    /* ④ Classification text */
    const classMap = {
      genuine: '✓ Likely Genuine Job Offer',
      fake:    rl === 'medium' ? '⚡ Suspicious — Proceed with Caution' : '✕ Likely Fraudulent Offer',
    };
    classText.textContent = classMap[classification] || classification;

    /* ⑤ Risk bar */
    riskBarFill.className = `risk-bar-fill ${rl}`;
    setTimeout(() => { riskBarFill.style.width = `${risk_score}%`; }, 50);

    /* ⑥ Warning box */
    warnSection.className = `warning-section ${rl}`;
    const icons  = { low: '✅', medium: '⚠️', high: '🚨' };
    const titles = { low: 'Looks Safe',        medium: 'Caution Advised',  high: 'High Risk Alert' };
    const msgs   = {
      low:    `This offer scores ${risk_score}/100 — no major scam indicators detected. Always verify the company independently before sharing documents.`,
      medium: `This offer scores ${risk_score}/100 and contains ${flagged_keywords.length} suspicious pattern(s). Research the company thoroughly before proceeding. Never pay fees upfront.`,
      high:   `⚠️ DANGER — This offer scores ${risk_score}/100 and matches ${flagged_keywords.length} known scam patterns. Do NOT respond, share information, or make payments. Report to cybercrime.gov.in or call 1930.`,
    };
    warnIcon.textContent  = icons[rl];
    warnTitle.textContent = titles[rl];
    warnMsg.textContent   = msgs[rl];

    /* ⑦ Keyword tags */
    kwGrid.innerHTML  = '';
    kwCount.textContent = `${flagged_keywords.length} found`;

    if (flagged_keywords.length > 0) {
      flagged_keywords.forEach((kw, i) => {
        const tag = document.createElement('span');
        tag.className  = 'kw-tag';
        tag.style.animationDelay = `${i * 0.055}s`;
        tag.innerHTML  = `<span class="kw-tag-icon">⚑</span>${escapeHtml(kw)}`;
        kwGrid.appendChild(tag);
      });
    } else {
      kwGrid.innerHTML = '<span class="no-keywords-msg">✓ No suspicious patterns detected</span>';
    }

    /* ⑧ Highlighted text */
    highlightEl.innerHTML = flagged_keywords.length > 0
      ? highlightKeywords(originalText, flagged_keywords)
      : escapeHtml(originalText);

    /* ⑨ Toggle highlighted text */
    let highlightOpen = false;
    highlightEl.style.display = 'none';
    toggleHighBtn.textContent = 'Show ↓';

    /* Replace to remove stale event listeners */
    const newToggle = toggleHighBtn.cloneNode(true);
    toggleHighBtn.parentNode.replaceChild(newToggle, toggleHighBtn);
    newToggle.addEventListener('click', () => {
      highlightOpen = !highlightOpen;
      highlightEl.style.display = highlightOpen ? 'block' : 'none';
      newToggle.textContent = highlightOpen ? 'Hide ↑' : 'Show ↓';
    });

    /* ⑩ Safety tips */
    safetyTipsEl.innerHTML = '';
    getSafetyTips(rl, flagged_keywords).forEach(tip => {
      const li = document.createElement('li');
      li.textContent = tip;
      safetyTipsEl.appendChild(li);
    });

    /* Store data for copy-report */
    copyBtn._reportData = data;
  }

  /* ── Error display ─────────────────────────────── */
  function displayError(message) {
    warnSection.className  = 'warning-section high';
    warnIcon.textContent   = '⚠️';
    warnTitle.textContent  = 'Error';
    warnMsg.textContent    = message;

    scoreNum.textContent   = '—';
    scoreCenter.className  = 'score-center';
    riskBadge.textContent  = 'ERROR';
    riskBadge.className    = 'risk-badge-large high';
    classText.textContent  = 'Analysis failed';
    riskBarFill.style.width = '0%';
    kwGrid.innerHTML       = '';
    safetyTipsEl.innerHTML = '';
    kwCount.textContent    = '—';
  }

  /* ── Flash red border on empty submit ──────────── */
  function flashError(msg) {
    jobTextEl.style.borderColor = 'var(--high-color)';
    jobTextEl.style.boxShadow   = '0 0 0 3px rgba(239,68,68,0.15)';
    setTimeout(() => {
      jobTextEl.style.borderColor = '';
      jobTextEl.style.boxShadow   = '';
    }, 2500);
    /* Shake animation */
    jobTextEl.animate(
      [
        { transform: 'translateX(0)' },
        { transform: 'translateX(-6px)' },
        { transform: 'translateX(6px)' },
        { transform: 'translateX(-4px)' },
        { transform: 'translateX(4px)' },
        { transform: 'translateX(0)' },
      ],
      { duration: 380, easing: 'ease-in-out' }
    );
    // Fallback tooltip
    jobTextEl.title = msg;
    setTimeout(() => { jobTextEl.title = ''; }, 3000);
  }

  /* ── Loading state helper ──────────────────────── */
  function showState(mode) {
    loadingState.style.display  = mode === 'loading' ? 'flex'  : 'none';
    resultContent.style.display = mode === 'result'  ? 'block' : 'none';
  }

  /* ── Animated loading steps ────────────────────── */
  function startLoadingSteps() {
    const ids = ['step1', 'step2', 'step3', 'step4'];
    ids.forEach(id => {
      const el = document.getElementById(id);
      if (el) el.className = 'loading-step';
    });
    let idx = 0;
    activate(idx++);
    return setInterval(() => {
      if (idx <= ids.length) {
        if (idx > 1) done(idx - 2);
        if (idx < ids.length) activate(idx);
        idx++;
      }
    }, 480);

    function activate(i) {
      const el = document.getElementById(ids[i]);
      if (el) el.classList.add('active');
    }
    function done(i) {
      const el = document.getElementById(ids[i]);
      if (el) { el.classList.remove('active'); el.classList.add('done'); }
    }
  }

  /* ── Copy report to clipboard ──────────────────── */
  async function copyReport() {
    const data = copyBtn._reportData;
    if (!data) return;

    const lines = [
      '╔══════════════════════════════════════╗',
      '║     SafeJob AI — Risk Report          ║',
      '╚══════════════════════════════════════╝',
      '',
      `Risk Score     : ${data.risk_score} / 100`,
      `Risk Level     : ${(data.risk_level || '').toUpperCase()}`,
      `Classification : ${(data.classification || '').toUpperCase()}`,
      '',
      `Suspicious Patterns (${(data.flagged_keywords || []).length}):`,
      ...(data.flagged_keywords || []).map(k => `  ⚑ ${k}`),
      '',
      `Generated : ${new Date().toLocaleString()}`,
      'SafeJob AI — Protecting women from job scams',
    ];

    const text = lines.join('\n');
    try {
      await navigator.clipboard.writeText(text);
    } catch {
      /* Fallback for older browsers */
      const ta = Object.assign(document.createElement('textarea'), {
        value: text, style: 'position:fixed;opacity:0;',
      });
      document.body.appendChild(ta);
      ta.select();
      document.execCommand('copy');
      document.body.removeChild(ta);
    }

    const orig = copyBtn.textContent;
    copyBtn.textContent = '✓ Copied!';
    setTimeout(() => { copyBtn.textContent = orig; }, 2000);
  }

  /* ── Download PDF to Device ────────────────────── */
  async function downloadPdf() {
    if (!downloadPdfBtn) return;
    const orig = downloadPdfBtn.textContent;
    downloadPdfBtn.innerHTML = '⏳ Generating...';
    downloadPdfBtn.disabled = true;

    // Temporarily hide the action buttons so they don't appear in the PDF report
    const actions = document.querySelector('.result-actions');
    const oldDisplay = actions ? actions.style.display : '';
    if (actions) actions.style.display = 'none';

    try {
      const element = document.getElementById('resultContent'); 
      const opt = {
        margin:       [0.5, 0.5, 0.5, 0.5],
        filename:     'SafeJob-AI-Report.pdf',
        image:        { type: 'jpeg', quality: 0.98 },
        html2canvas:  { scale: 2, useCORS: true, windowWidth: 800, backgroundColor: '#0e0f2a' },
        jsPDF:        { unit: 'in', format: 'a4', orientation: 'portrait' }
      };
      
      // Wait a short moment to ensure UI updates
      await new Promise(r => setTimeout(r, 100));
      
      // Generate and save PDF using html2pdf.js imported in index.html
      await html2pdf().set(opt).from(element).save();
      
    } catch (err) {
      console.error('Failed to generate PDF:', err);
      alert('Failed to generate PDF. Please try again.');
    } finally {
      if (actions) actions.style.display = oldDisplay;
      downloadPdfBtn.textContent = orig;
      downloadPdfBtn.disabled = false;
    }
  }

} /* end initAnalyzePage */

/* ─────────────────────────────────────────────────────
   UTILITY FUNCTIONS
───────────────────────────────────────────────────── */

/** Animate element textContent from `start` to `end` over `duration` ms */
function animateValue(el, start, end, duration) {
  const t0 = performance.now();
  function step(now) {
    const p = Math.min((now - t0) / duration, 1);
    const e = 1 - Math.pow(1 - p, 3); // ease-out cubic
    el.textContent = Math.round(start + (end - start) * e);
    if (p < 1) requestAnimationFrame(step);
  }
  requestAnimationFrame(step);
}

/** Safely escape HTML special characters */
function escapeHtml(str) {
  const d = document.createElement('div');
  d.textContent = str;
  return d.innerHTML;
}

/** Return HTML with matched keywords wrapped in <mark class="kw-highlight"> */
function highlightKeywords(text, keywords) {
  let html = escapeHtml(text);
  /* Sort longest first to prevent partial overlaps */
  const sorted = [...keywords].sort((a, b) => b.length - a.length);
  sorted.forEach(kw => {
    const safe = kw.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    html = html.replace(
      new RegExp(`(${safe})`, 'gi'),
      '<mark class="kw-highlight">$1</mark>'
    );
  });
  return html.replace(/\n/g, '<br>');
}

/** Return safety tip array based on risk level */
function getSafetyTips(level, keywords) {
  const hasFee   = keywords.some(k => /fee|payment|deposit|pay first/.test(k));
  const hasPhoto = keywords.some(k => /photo/.test(k));

  const base = {
    low: [
      'Verify the company independently — search its name on LinkedIn or MCA India.',
      'Never share Aadhaar, PAN, or bank details before receiving an official offer letter.',
      "Research the recruiter's LinkedIn profile before replying.",
      'Be cautious of unsolicited job offers, even if they appear professional.',
    ],
    medium: [
      'Never pay any registration or training fee — legitimate employers never charge candidates.',
      'Search the company name + "scam" or "fraud" on Google before proceeding.',
      'Call the company using a number from its official website — not the one in the message.',
      'Ask for a formal offer letter on company letterhead before sharing any documents.',
      'Do not click any links in the message without verifying the domain.',
    ],
    high: [
      'DO NOT respond to this offer under any circumstances.',
      'DO NOT share personal information, photos, or documents.',
      'DO NOT make any payments — money sent to scammers is rarely recovered.',
      'Report immediately at cybercrime.gov.in or call the Cyber Helpline: 1930.',
      'Block the sender on all platforms (WhatsApp, email, Telegram).',
      'Share this warning with other women in your network to protect them.',
    ],
  };

  const tips = [...base[level] || base.low];
  if (hasFee   && level !== 'high') tips.unshift('⚠️ A job that asks you to pay a fee before starting is almost certainly a scam.');
  if (hasPhoto && level !== 'high') tips.unshift('⚠️ Never send personal photos to a recruiter you have not verified in person.');
  return tips;
}
