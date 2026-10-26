(function () {
  const BRANDS = [
    { name: 'paypal', domains: ['paypal.com'] },
    { name: 'apple', domains: ['apple.com', 'icloud.com'] },
    { name: 'microsoft', domains: ['microsoft.com', 'outlook.com', 'live.com'] },
    { name: 'amazon', domains: ['amazon.com'] },
    { name: 'bank of america', domains: ['bankofamerica.com'] },
    { name: 'chase', domains: ['chase.com'] },
    { name: 'wells fargo', domains: ['wellsfargo.com'] },
    { name: 'netflix', domains: ['netflix.com'] },
    { name: 'irs', domains: ['irs.gov'] },
    { name: 'docusign', domains: ['docusign.com'] },
    { name: 'google', domains: ['google.com', 'gmail.com'] }
  ];

  const SEVERITY_COLOR = {
    high: { bg: '#F3B0A5', text: '#8A2E20', dot: '#C6432E' },
    medium: { bg: '#F1CE93', text: '#8A5A15', dot: '#C9821E' },
    low: { bg: '#EEE29B', text: '#6B5A24', dot: '#B8A21F' }
  };
  const SEVERITY_RANK = { high: 3, medium: 2, low: 1 };

  const SAMPLES = [
    {
      id: 'critical', title: 'Account Suspended Alert', badge: 'Critical',
      blurb: 'Fake PayPal domain, urgent threats, credential request',
      raw:
`From: PayPal Security <security@paypa1-support.com>
Subject: URGENT: Your account has been suspended

Dear Customer,

We detected unusual activity on your account. Your account has been suspended and will be permanently closed within 24 hours unless you verify your identity immediately.

Click here to verify your account now: http://paypa1-secure-login.tk/verify

Please confirm your password and one-time code to restore access. Failure to respond immediately will result in permanent suspension.

Thank you,
PayPal Security Team`
    },
    {
      id: 'medium', title: 'Overdue Invoice', badge: 'Medium',
      blurb: 'Unfamiliar vendor domain, risky attachment, wire request',
      raw:
`From: Billing Department <billing@vendor-invoices.net>
Subject: Invoice overdue - action needed

Hello,

Please see the attached invoice_statement.exe for your records. Your payment is overdue and we kindly ask that you complete a wire transfer to our updated bank account number as soon as possible to avoid late fees.

Regards,
Billing Team`
    },
    {
      id: 'low', title: 'Order Receipt', badge: 'Low',
      blurb: 'Consistent sender domain, no urgency, no requests',
      raw:
`From: Acme Store <receipts@acmestore.com>
Subject: Your receipt from Acme Store

Hi Jordan,

Thanks for your order! Here's a summary of your purchase:

1x Ceramic Mug - $18.00
Shipping - $4.00
Total - $22.00

Your order will arrive in 3-5 business days. You can track it anytime from your account on acmestore.com.

Thanks for shopping with us,
Acme Store`
    }
  ];

  function escapeHtml(s) {
    return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  }

  function parseEmail(raw) {
    const lines = raw.replace(/^\uFEFF/, '').replace(/\r\n?/g, '\n').split('\n');
    let bodyStart = 0;
    let hasHeaders = false;
    let currentHeader = '';
    const headers = {};
    const standardHeaders = new Set([
      'from', 'to', 'cc', 'bcc', 'subject', 'date', 'sender', 'reply-to',
      'return-path', 'message-id', 'mime-version', 'content-type',
      'content-transfer-encoding', 'received', 'delivered-to',
      'authentication-results', 'arc-authentication-results', 'arc-seal',
      'arc-message-signature', 'dkim-signature', 'content-disposition',
      'x-original-authentication-results'
    ]);
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const m = line.match(/^([A-Za-z][A-Za-z0-9-]*):[ \t]*(.*)$/);
      if (m) {
        const headerName = m[1].toLowerCase();
        if (!hasHeaders && !standardHeaders.has(headerName) && !headerName.startsWith('x-')) break;
        currentHeader = headerName;
        headers[currentHeader] = headers[currentHeader]
          ? `${headers[currentHeader]}\n${m[2].trim()}`
          : m[2].trim();
        hasHeaders = true;
        bodyStart = i + 1;
      } else if (/^[ \t]+/.test(line) && currentHeader) {
        headers[currentHeader] += ` ${line.trim()}`;
        bodyStart = i + 1;
      } else if (!line.trim() && hasHeaders) {
        bodyStart = i + 1;
        break;
      } else if (hasHeaders) {
        bodyStart = i;
        break;
      } else {
        break;
      }
    }
    const body = hasHeaders ? lines.slice(bodyStart).join('\n').trim() : lines.join('\n').trim();
    const isHtml = /text\/html/i.test(headers['content-type'] || '') || /<(?:!doctype|html|head|body|table|div|p|a)\b/i.test(body);
    let displayBody = body;
    if (isHtml) {
      const parsedHtml = new DOMParser().parseFromString(body, 'text/html');
      parsedHtml.querySelectorAll('script, style, head, noscript').forEach(node => node.remove());
      parsedHtml.body.querySelectorAll('a[href]').forEach(anchor => {
        const href = anchor.getAttribute('href');
        if (href && !anchor.textContent.includes(href)) anchor.append(document.createTextNode(` (link: ${href})`));
      });
      displayBody = parsedHtml.body.innerHTML
        .replace(/<br\s*\/?>/gi, '\n')
        .replace(/<\/(?:p|div|li|tr|h[1-6]|blockquote|table)>/gi, '\n')
        .replace(/<[^>]*>/g, '');
      displayBody = new DOMParser().parseFromString(displayBody, 'text/html').body.textContent
        .replace(/[ \t]+\n/g, '\n').replace(/\n{3,}/g, '\n\n').trim();
    }
    const isMultipart = /multipart\//i.test(headers['content-type'] || '');
    const hasEncodedBody = /\b(?:base64|quoted-printable)\b/i.test(headers['content-transfer-encoding'] || '');
    return {
      headers,
      body,
      displayBody,
      isHtml,
      limitations: [
        ...(isMultipart ? ['This is a multipart email. Attachments and encoded MIME parts are not unpacked.'] : []),
        ...(isHtml ? ['HTML was converted to visible text; scripts, styles, and layout were not evaluated.'] : []),
        ...(hasEncodedBody ? ['The message contains encoded content that this browser-only scan does not decode.'] : [])
      ]
    };
  }

  function emailAddresses(value) {
    return [...value.matchAll(/[a-z0-9.!#$%&'*+/=?^_`{|}~-]+@(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}/gi)]
      .map(match => ({ address: match[0].toLowerCase(), domain: match[0].split('@').pop().toLowerCase() }));
  }

  function domainMatches(domain, allowedDomains) {
    return allowedDomains.some(allowed => domain === allowed || domain.endsWith(`.${allowed}`));
  }

  function brandInDomain(domain) {
    return BRANDS.find(brand => {
      if (domainMatches(domain, brand.domains)) return false;
      const name = brand.name.replace(/[^a-z0-9]/g, '');
      return domain.split('.').some(label => {
        const normalized = label.replace(/[0153]/g, char => ({ '0': 'o', '1': 'l', '5': 's', '3': 'e' }[char]));
        return normalized.includes(name);
      });
    });
  }

  function buildFindings(headers, body, displayBody, isHtml) {
    const findings = [];
    const highlightRanges = [];
    const addFinding = (id, title, severity, confidence, evidence, detail, points) => {
      findings.push({ id, title, severity, confidence, evidence, detail, points });
    };
    const fromRaw = headers.from || '';
    const fromAddresses = emailAddresses(fromRaw);
    const fromDomain = fromAddresses[0] ? fromAddresses[0].domain : '';
    const fromDisplay = fromRaw.replace(/<[^>]*>/g, '').replace(/["']/g, '').trim();
    const claimedBrand = BRANDS.find(brand => {
      const name = brand.name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&').replace(/\\ /g, '\\s+');
      return new RegExp(`(^|[^a-z0-9])${name}([^a-z0-9]|$)`, 'i').test(fromDisplay);
    });

    if (!fromAddresses.length) {
      addFinding('sender-missing', 'Sender address is not available', 'low', 'Limited', 'No valid email address was found in the From header.', 'Sender identity cannot be assessed from the provided text.', 0);
    } else if (fromAddresses.length > 1) {
      addFinding('multiple-senders', 'Multiple sender addresses in From header', 'high', 'High confidence', fromRaw, 'A message with multiple From addresses is unusual and can make the apparent sender ambiguous.', 35);
    }
    if (claimedBrand && fromDomain && !domainMatches(fromDomain, claimedBrand.domains)) {
      addFinding('sender-brand-mismatch', `Sender display name claims ${claimedBrand.name}`, 'high', 'High confidence', `${fromDisplay} <${fromAddresses[0].address}>`, `The address domain ${fromDomain} is not in this local check's supported ${claimedBrand.name} domain list. This mismatch is suspicious but not definitive; verify independently.`, 30);
    } else if (fromDomain) {
      const lookalikeBrand = brandInDomain(fromDomain);
      if (lookalikeBrand) {
        addFinding('sender-domain-lookalike', 'Sender domain contains a known brand name', 'medium', 'Some evidence', fromDomain, `The sender domain contains "${lookalikeBrand.name}" but is not a supported domain for that brand. Confirm the sender independently; a brand mention alone does not prove impersonation.`, 20);
      }
    }

    const replyAddresses = emailAddresses(headers['reply-to'] || '');
    if (replyAddresses.length && fromDomain && replyAddresses.some(address => address.domain !== fromDomain)) {
      addFinding('reply-to-mismatch', 'Reply-To domain differs from sender', 'medium', 'Some evidence', `From: ${fromDomain}; Reply-To: ${replyAddresses.map(address => address.domain).join(', ')}`, 'Replies may go to a different organization. Forwarding can be legitimate, so verify unexpected changes using a trusted contact method.', 18);
    }
    const returnPath = emailAddresses(headers['return-path'] || '');
    if (returnPath.length && fromDomain && returnPath.every(address => address.domain !== fromDomain)) {
      addFinding('return-path-mismatch', 'Return-Path differs from sender domain', 'low', 'Needs review', `From: ${fromDomain}; Return-Path: ${returnPath.map(address => address.domain).join(', ')}`, 'Mailing services and forwarding often use separate bounce domains; this difference alone does not establish spoofing.', 8);
    }

    const authHeader = [
      headers['authentication-results'],
      headers['arc-authentication-results'],
      headers['x-original-authentication-results']
    ].filter(Boolean).join('\n');
    const failedAuth = [...authHeader.matchAll(/\b(dmarc|spf|dkim)\s*=\s*(fail|softfail|permerror|temperror)\b/gi)];
    if (failedAuth.length) {
      const uniqueFailures = [...new Set(failedAuth.map(match => `${match[1].toUpperCase()} ${match[2].toLowerCase()}`))];
      const hasDmarcFailure = failedAuth.some(match => match[1].toLowerCase() === 'dmarc' && match[2].toLowerCase() === 'fail');
      addFinding('authentication-failed', 'Authentication failure reported in supplied headers', hasDmarcFailure ? 'high' : 'medium', 'Some evidence', uniqueFailures.join('; '), 'The pasted Authentication-Results header reports a failure. This tool cannot verify who added that header or validate the original mail-server trace.', hasDmarcFailure ? 30 : 20);
    }

    const htmlAnchors = [...body.matchAll(/<a\b[^>]*\bhref\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))[^>]*>([\s\S]*?)<\/a\s*>/gi)];
    const links = [];
    const addLink = (rawUrl, evidence, start, end, canHighlight) => {
      let url;
      try {
        url = new URL(rawUrl);
      } catch (error) {
        return;
      }
      if (!['http:', 'https:'].includes(url.protocol)) return;
      const host = url.hostname.toLowerCase().replace(/\.$/, '');
      const safeHost = host.startsWith('www.') ? host.slice(4) : host;
      if (links.some(link => link.host === safeHost && link.url === url.href)) return;
      links.push({ url: url.href, host: safeHost, evidence, start, end, canHighlight });
    };
    const urlRegex = /https?:\/\/[^\s<>"')]+/gi;
    let urlMatch;
    while ((urlMatch = urlRegex.exec(body))) {
      const rawUrl = urlMatch[0].replace(/[.,!?;:}\]]+$/, '');
      addLink(rawUrl, rawUrl, urlMatch.index, urlMatch.index + rawUrl.length, !isHtml);
    }
    for (const anchor of htmlAnchors) {
      const rawUrl = (anchor[1] || anchor[2] || anchor[3] || '').replace(/&amp;/gi, '&').trim();
      const start = anchor.index + anchor[0].indexOf(rawUrl);
      addLink(rawUrl, `${anchor[4].replace(/<[^>]*>/g, '').trim() || '(no link text)'} → ${rawUrl}`, start, start + rawUrl.length, false);
    }

    const shorteners = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd'];
    const riskyLinks = [];
    for (const link of links) {
      const url = new URL(link.url);
      const host = link.host;
      const brand = brandInDomain(host);
      const dangerousFileLink = /\.(?:exe|scr|js|vbs|bat|cmd|jar|zip|7z|rar|hta|msi|dll|ps1|lnk|iso|img|docm|xlsm|pptm)$/i.test(url.pathname);
      const isIp = /^\d{1,3}(?:\.\d{1,3}){3}$/.test(host) || /^\[?[0-9a-f:]+\]?$/i.test(host) && host.includes(':');
      const isShortener = shorteners.some(domain => host === domain || host.endsWith(`.${domain}`));
      const isPunycode = host.split('.').some(label => label.startsWith('xn--'));
      const isUnusualTld = /\.(?:tk|top|xyz|click|buzz|online)$/.test(host);
      const mismatchAnchor = htmlAnchors.some(anchor => {
        const anchorUrl = (anchor[1] || anchor[2] || anchor[3] || '').replace(/&amp;/gi, '&').trim();
        if (anchorUrl !== link.url && anchorUrl !== url.href) return false;
        const visibleDomain = (anchor[4].replace(/<[^>]*>/g, '').match(/(?:https?:\/\/)?(?:www\.)?([a-z0-9.-]+\.[a-z]{2,})/i) || [])[1];
        return visibleDomain && visibleDomain.toLowerCase() !== host && !host.endsWith(`.${visibleDomain.toLowerCase()}`);
      });
      let reason = '';
      let severity = 'medium';
      let points = 14;
      if (url.username || url.password) {
        reason = 'URL contains credentials before its destination';
        severity = 'high';
        points = 30;
      } else if (isIp) {
        reason = 'Link destination is a raw IP address';
        severity = 'high';
        points = 28;
      } else if (brand) {
        reason = `Link hostname may impersonate ${brand.name}`;
        severity = 'high';
        points = 30;
      } else if (mismatchAnchor) {
        reason = 'Displayed link text does not match its destination';
        severity = 'high';
        points = 28;
      } else if (dangerousFileLink) {
        reason = 'Link points directly to a potentially dangerous file type';
        severity = 'medium';
        points = 18;
      } else if (isShortener || isPunycode || isUnusualTld) {
        reason = isShortener ? 'Shortened URL hides its final destination' : isPunycode ? 'Hostname uses encoded international characters' : 'Hostname uses an unusual top-level domain';
        severity = 'medium';
        points = 16;
      } else if (url.protocol === 'http:') {
        reason = 'Link uses unencrypted HTTP';
        severity = 'low';
        points = 6;
      }
      if (reason) {
        riskyLinks.push({ ...link, reason, severity, points });
        if (link.canHighlight) highlightRanges.push({ start: link.start, end: link.end, severity, label: reason });
      }
    }
    if (riskyLinks.length) {
      const strongestLink = riskyLinks.reduce((strongest, link) => link.points > strongest.points ? link : strongest);
      addFinding(
        'links',
        `${riskyLinks.length} link${riskyLinks.length === 1 ? '' : 's'} need review`,
        strongestLink.severity,
        riskyLinks.some(link => link.severity === 'high') ? 'High confidence' : 'Some evidence',
        [...new Set(riskyLinks.map(link => `${link.reason}: ${link.evidence}`))].join('\n'),
        'Do not open the link to check it. Verify the destination independently through the organization’s official website or app.',
        Math.min(40, strongestLink.points + Math.min(10, (riskyLinks.length - 1) * 4))
      );
    }

    const sensitiveTerms = 'password|passcode|one[- ]time code|verification code|otp|pin|social security number|ssn|credit card|cvv|bank account|routing number';
    const sensitiveActions = 'send|share|provide|enter|submit|reply with|confirm|verify|reveal|give us|update|type in|ask for|request';
    const requestPattern = new RegExp(
      `\\b(?:${sensitiveActions})\\b[^.!?\\n]{0,50}\\b(?:${sensitiveTerms})\\b|\\b(?:${sensitiveTerms})\\b[^.!?\\n]{0,50}\\b(?:${sensitiveActions})\\b`,
      'gi'
    );
    const requestMatches = [...displayBody.matchAll(requestPattern)].filter(match => {
      const sentenceStart = Math.max(
        displayBody.lastIndexOf('.', match.index - 1),
        displayBody.lastIndexOf('!', match.index - 1),
        displayBody.lastIndexOf('?', match.index - 1),
        displayBody.lastIndexOf('\n', match.index - 1)
      ) + 1;
      const prefix = displayBody.slice(sentenceStart, match.index);
      return !/\b(?:never|don't|do not|must not|should not|avoid)\b[^.!?\n]*$/i.test(prefix);
    });
    if (requestMatches.length) {
      const uniqueRequests = [...new Set(requestMatches.map(match => match[0].trim()))].slice(0, 3);
      for (const match of requestMatches) {
        if (match.index !== undefined) highlightRanges.push({ start: match.index, end: match.index + match[0].length, severity: 'high', label: 'Request for sensitive information' });
      }
      addFinding('sensitive-request', 'Requests credentials or financial information', 'high', 'High confidence', uniqueRequests.join('; '), 'Treat an email request for passwords, verification codes, or full payment credentials as unsafe. Contact the organization using a known channel.', 28);
    }

    const paymentChange = /\b(?:new|updated|changed|different)\s+(?:bank|payment|wire|direct deposit)\s+(?:account|details|instructions)\b|\b(?:wire|bank)\s+transfer\b.{0,70}\b(?:new|updated|different|urgent|today)\b/gi;
    const paymentMatches = [...displayBody.matchAll(paymentChange)];
    if (paymentMatches.length) {
      addFinding('payment-change', 'Requests a payment or bank-detail change', 'high', 'Some evidence', [...new Set(paymentMatches.map(match => match[0].trim()))].slice(0, 2).join('; '), 'Unexpected payment-instruction changes are a common business-email-compromise pattern. Confirm the change with a known contact using a separate channel.', 24);
      for (const match of paymentMatches) highlightRanges.push({ start: match.index, end: match.index + match[0].length, severity: 'high', label: 'Payment instruction change' });
    }

    const urgentRegex = /\b(?:act now|immediately|within \d+\s*(?:hours?|minutes?)|final notice|account (?:has been |will be )?(?:suspended|locked|closed)|failure to (?:respond|comply)|will be permanently closed|verify your account now)\b/gi;
    const urgencyMatches = [...`${headers.subject || ''}\n${displayBody}`.matchAll(urgentRegex)];
    if (urgencyMatches.length) {
      const phrases = [...new Set(urgencyMatches.map(match => match[0].toLowerCase()))];
      addFinding('urgency', 'Uses a deadline or threat to pressure action', 'medium', 'Some evidence', phrases.join('; '), 'Pressure language is a warning sign, not proof of fraud. Be especially cautious when it is paired with a link, credential request, or payment change.', 12);
      for (const match of urgencyMatches) {
        const bodyStart = (headers.subject || '').length + 1;
        if (match.index >= bodyStart) {
          const start = match.index - bodyStart;
          highlightRanges.push({ start, end: start + match[0].length, severity: 'medium', label: 'Urgent or threatening language' });
        }
      }
    }

    const attachmentPattern = /\b[\w .()-]+\.(?:exe|scr|js|vbs|bat|cmd|jar|zip|7z|rar|html|hta|msi|dll|ps1|lnk|iso|img|docm|xlsm|pptm)\b/gi;
    const mentionedAttachments = [...displayBody.matchAll(attachmentPattern)]
      .filter(match => !links.some(link => link.canHighlight && match.index >= link.start && match.index < link.end))
      .map(match => match[0].trim());
    const headerAttachments = [...(headers['content-disposition'] || '').matchAll(/filename\*?=(?:UTF-8''|")?([^";\n]+)/gi)]
      .map(match => match[1].replace(/"$/, '').trim());
    const attachmentNames = [...mentionedAttachments, ...headerAttachments];
    if (attachmentNames.length) {
      const uniqueAttachments = [...new Set(attachmentNames)].slice(0, 3);
      const isAttached = headerAttachments.length > 0;
      addFinding('attachment', isAttached ? 'Attachment header names a risky file type' : 'Email text mentions a potentially risky file type', 'medium', isAttached ? 'High confidence' : 'Some evidence', uniqueAttachments.join('; '), isAttached ? 'The supplied Content-Disposition header identifies a script, executable, archive, shortcut, or macro-enabled file. The file contents were not inspected.' : 'The text mentions a script, executable, archive, shortcut, or macro-enabled file. This may only be a reference; the email body alone cannot confirm an attachment.', isAttached ? 20 : 10);
      for (const match of displayBody.matchAll(attachmentPattern)) {
        if (links.some(link => link.canHighlight && match.index >= link.start && match.index < link.end)) continue;
        highlightRanges.push({ start: match.index, end: match.index + match[0].length, severity: 'medium', label: 'Potentially dangerous attachment type' });
      }
    }

    const score = Math.min(100, findings.reduce((total, finding) => total + finding.points, 0));
    return {
      findings: findings.sort((a, b) => b.points - a.points),
      score,
      highlightRanges,
      fromDomain,
      senderMismatch: findings.some(finding => ['sender-brand-mismatch', 'sender-domain-lookalike'].includes(finding.id))
    };
  }

  function buildSegmentsHtml(body, ranges) {
    if (!ranges.length) return escapeHtml(body);
    const sorted = ranges.slice().sort((a, b) => a.start - b.start);
    const merged = [];
    for (const r of sorted) {
      const last = merged[merged.length - 1];
      if (last && r.start <= last.end) {
        if (SEVERITY_RANK[r.severity] > SEVERITY_RANK[last.severity]) last.severity = r.severity;
        last.end = Math.max(last.end, r.end);
        last.labels.add(r.label);
      } else {
        merged.push({ start: r.start, end: r.end, severity: r.severity, labels: new Set([r.label]) });
      }
    }
    let html = '', cursor = 0;
    for (const m of merged) {
      if (m.start > cursor) html += escapeHtml(body.slice(cursor, m.start));
      const colors = SEVERITY_COLOR[m.severity];
      const title = escapeHtml([...m.labels].join(', '));
      html += `<span class="hl" style="background:${colors.bg};color:${colors.text}" title="${title}">${escapeHtml(body.slice(m.start, m.end))}</span>`;
      cursor = m.end;
    }
    if (cursor < body.length) html += escapeHtml(body.slice(cursor));
    return html;
  }

  // --- DOM wiring ---
  const rawInputEl = document.getElementById('rawInput');
  const tabsEl = document.getElementById('tabs');
  const panels = {
    paste: document.getElementById('panel-paste'),
    upload: document.getElementById('panel-upload'),
    samples: document.getElementById('panel-samples')
  };
  const chipsEl = document.getElementById('chips');
  const fromChip = document.getElementById('fromChip');
  const subjectChip = document.getElementById('subjectChip');
  const resultsEl = document.getElementById('results');
  const scoreNumberEl = document.getElementById('scoreNumber');
  const bucketLabelEl = document.getElementById('bucketLabel');
  const meterFillEl = document.getElementById('meterFill');
  const bucketDescEl = document.getElementById('bucketDesc');
  const assessmentNoteEl = document.getElementById('assessmentNote');
  const coverageNoteEl = document.getElementById('coverageNote');
  const findingsEl = document.getElementById('findings');
  const recommendationsEl = document.getElementById('recommendations');
  const annotatedBodyEl = document.getElementById('annotatedBody');
  const sampleGridEl = document.getElementById('sampleGrid');
  const dropzoneLabelEl = document.getElementById('dropzoneLabel');
  const dropzoneEl = document.getElementById('dropzone');
  const fileInputEl = document.getElementById('fileInput');
  const analyzeButtonEl = document.getElementById('analyzeButton');
  const resetButtonEl = document.getElementById('resetButton');
  const statusEl = document.getElementById('status');
  const scoreMeterEl = document.getElementById('scoreMeter');
  const maxInputBytes = 2 * 1024 * 1024;
  let fileReadToken = 0;

  tabsEl.addEventListener('click', (e) => {
    const btn = e.target.closest('[role="tab"]');
    if (!btn) return;
    setActiveTab(btn.dataset.tab);
  });

  tabsEl.addEventListener('keydown', (e) => {
    const tabs = [...tabsEl.querySelectorAll('[role="tab"]')];
    const currentIndex = tabs.indexOf(e.target);
    if (currentIndex < 0) return;
    let nextIndex = currentIndex;
    if (e.key === 'ArrowRight') nextIndex = (currentIndex + 1) % tabs.length;
    else if (e.key === 'ArrowLeft') nextIndex = (currentIndex - 1 + tabs.length) % tabs.length;
    else if (e.key === 'Home') nextIndex = 0;
    else if (e.key === 'End') nextIndex = tabs.length - 1;
    else return;
    e.preventDefault();
    setActiveTab(tabs[nextIndex].dataset.tab, true);
  });

  function setActiveTab(tab, focus) {
    [...tabsEl.querySelectorAll('[role="tab"]')].forEach(button => {
      const selected = button.dataset.tab === tab;
      button.classList.toggle('active', selected);
      button.setAttribute('aria-selected', String(selected));
      button.tabIndex = selected ? 0 : -1;
      panels[button.dataset.tab].hidden = !selected;
      if (selected && focus) button.focus();
    });
  }

  function clearResults() {
    chipsEl.hidden = true;
    fromChip.textContent = '';
    fromChip.className = 'chip';
    subjectChip.textContent = '';
    subjectChip.hidden = true;
    resultsEl.hidden = true;
  }

  rawInputEl.addEventListener('input', () => {
    fileReadToken++;
    clearResults();
    statusEl.textContent = rawInputEl.value.trim()
      ? 'Email changed. Select Analyze Email to update the results.'
      : 'Analysis runs locally in your browser. Results are heuristic and may miss phishing emails or flag legitimate messages.';
  });
  analyzeButtonEl.addEventListener('click', render);
  resetButtonEl.addEventListener('click', () => {
    fileReadToken++;
    rawInputEl.value = '';
    fileInputEl.value = '';
    dropzoneLabelEl.textContent = 'Click or drop a .eml/.txt file';
    clearResults();
    setActiveTab('paste');
    statusEl.textContent = 'Email cleared. Paste or upload an email to begin.';
    rawInputEl.focus();
  });

  function loadFile(file) {
    if (!file) return;
    const token = ++fileReadToken;
    if (!/\.(?:eml|txt)$/i.test(file.name)) {
      statusEl.textContent = 'Choose an .eml or .txt file.';
      fileInputEl.value = '';
      return;
    }
    if (file.size > maxInputBytes) {
      statusEl.textContent = 'That file is larger than the 2 MB limit. Choose a smaller email file.';
      fileInputEl.value = '';
      return;
    }
    const reader = new FileReader();
    statusEl.textContent = `Reading ${file.name}...`;
    reader.onload = () => {
      if (token !== fileReadToken) return;
      if (typeof reader.result !== 'string') {
        fileInputEl.value = '';
        statusEl.textContent = 'The selected file could not be read as text.';
        return;
      }
      fileInputEl.value = '';
      rawInputEl.value = reader.result;
      dropzoneLabelEl.textContent = `Loaded: ${file.name}`;
      setActiveTab('paste');
      render();
    };
    reader.onerror = () => {
      if (token !== fileReadToken) return;
      fileInputEl.value = '';
      statusEl.textContent = 'The selected file could not be read. Try another .eml or .txt file.';
    };
    reader.onabort = () => {
      if (token !== fileReadToken) return;
      fileInputEl.value = '';
      statusEl.textContent = 'File reading was cancelled.';
    };
    reader.readAsText(file);
  }

  fileInputEl.addEventListener('change', (e) => {
    loadFile(e.target.files && e.target.files[0]);
  });

  dropzoneEl.addEventListener('keydown', (e) => {
    if (e.target === fileInputEl) return;
    if (e.key === 'Enter' || e.key === ' ') {
      e.preventDefault();
      fileInputEl.click();
    }
  });
  ['dragenter', 'dragover'].forEach(eventName => {
    dropzoneEl.addEventListener(eventName, (e) => {
      e.preventDefault();
      dropzoneEl.classList.add('dragging');
    });
  });
  ['dragleave', 'drop'].forEach(eventName => {
    dropzoneEl.addEventListener(eventName, (e) => {
      e.preventDefault();
      dropzoneEl.classList.remove('dragging');
    });
  });
  dropzoneEl.addEventListener('drop', (e) => {
    const file = e.dataTransfer && e.dataTransfer.files[0];
    if (file) loadFile(file);
  });

  SAMPLES.forEach(sample => {
    const bc = sample.badge === 'Critical' ? SEVERITY_COLOR.high : sample.badge === 'Medium' ? SEVERITY_COLOR.medium : { bg: '#D9E8D5', text: '#3D7A3A' };
    const card = document.createElement('button');
    card.className = 'sample-card';
    card.innerHTML = `
      <div class="sample-card-top">
        <div class="sample-card-title">${escapeHtml(sample.title)}</div>
        <div class="sample-badge" style="background:${bc.bg};color:${bc.text}">${sample.badge}</div>
      </div>
      <div class="sample-card-blurb">${escapeHtml(sample.blurb)}</div>
    `;
    card.addEventListener('click', () => {
      fileReadToken++;
      rawInputEl.value = sample.raw;
      fileInputEl.value = '';
      dropzoneLabelEl.textContent = 'Click or drop a .eml/.txt file';
      setActiveTab('paste');
      render();
    });
    sampleGridEl.appendChild(card);
  });

  function render() {
    const raw = rawInputEl.value;
    if (!raw.trim()) {
      clearResults();
      statusEl.textContent = 'Paste an email, upload a file, or choose a sample before analyzing.';
      rawInputEl.focus();
      return;
    }
    if (new Blob([raw]).size > maxInputBytes) {
      clearResults();
      statusEl.textContent = 'Email text is larger than the 2 MB limit. Remove some content and try again.';
      return;
    }

    const parsed = parseEmail(raw);
    const analysis = buildFindings(parsed.headers, parsed.body, parsed.displayBody, parsed.isHtml);

    // header chips
    const fromHeader = parsed.headers.from || '';
    const subjectHeader = parsed.headers.subject || '';
    chipsEl.hidden = !fromHeader && !subjectHeader;
    if (fromHeader) {
      fromChip.textContent = `From: ${fromHeader}`;
      fromChip.className = 'chip' + (analysis.senderMismatch ? ' chip-mismatch' : '');
    }
    fromChip.hidden = !fromHeader;
    subjectChip.hidden = !subjectHeader;
    if (subjectHeader) subjectChip.textContent = `Subject: ${subjectHeader}`;

    resultsEl.hidden = false;

    // score + bucket
    const score = analysis.score;
    let bucket;
    if (score === 0) bucket = { label: 'No indicators matched', color: '#3D7A3A', desc: 'The scan did not find any of its defined warning signals. This is not proof that the email is legitimate.' };
    else if (score < 20) bucket = { label: 'Low observed risk', color: '#3D7A3A', desc: 'Few or weak warning signals were found. Verify unexpected requests before acting.' };
    else if (score < 40) bucket = { label: 'Moderate observed risk', color: '#C9821E', desc: 'A meaningful warning signal was found. Check the evidence and confirm the sender independently.' };
    else if (score < 70) bucket = { label: 'High observed risk', color: '#D9622B', desc: 'Multiple or substantial warning signals were found. Do not use email links or payment instructions until independently verified.' };
    else bucket = { label: 'Critical observed risk', color: '#C6432E', desc: 'Several strong warning signals were found. Do not reply, open links, provide information, or follow payment instructions.' };

    scoreNumberEl.textContent = score;
    scoreNumberEl.style.color = bucket.color;
    bucketLabelEl.textContent = bucket.label;
    bucketLabelEl.style.color = bucket.color;
    bucketDescEl.textContent = bucket.desc;
    meterFillEl.style.width = score + '%';
    meterFillEl.style.background = bucket.color;
    scoreMeterEl.setAttribute('aria-valuenow', String(score));
    assessmentNoteEl.textContent = 'Triage score based on distinct observed signals; it is not a probability of fraud. A low score does not establish that an email is safe.';
    const hasAuthenticationResults = Boolean(
      parsed.headers['authentication-results'] ||
      parsed.headers['arc-authentication-results'] ||
      parsed.headers['x-original-authentication-results']
    );
    coverageNoteEl.textContent = [
      `From header: ${parsed.headers.from ? 'present' : 'not present'}.`,
      `Authentication results: ${hasAuthenticationResults ? 'present but not independently verified' : 'not present'}.`,
      ...parsed.limitations,
      'No live DNS, URL-reputation, domain-registration, or attachment-execution checks are performed.'
    ].join(' ');

    // findings
    findingsEl.innerHTML = '';
    if (!analysis.findings.length) {
      const empty = document.createElement('div');
      empty.className = 'no-findings';
      empty.setAttribute('role', 'listitem');
      empty.textContent = 'No rule matched the supplied text. This does not mean the email is safe.';
      findingsEl.appendChild(empty);
    }
    analysis.findings.forEach(f => {
      const row = document.createElement('div');
      row.className = 'finding';
      row.setAttribute('role', 'listitem');
      const dot = document.createElement('div');
      dot.className = 'finding-dot';
      dot.style.background = SEVERITY_COLOR[f.severity].dot;
      const content = document.createElement('div');
      content.className = 'finding-content';
      const titleRow = document.createElement('div');
      titleRow.className = 'finding-title-row';
      const title = document.createElement('div');
      title.className = 'finding-label met';
      title.textContent = f.title;
      const badges = document.createElement('div');
      badges.className = 'finding-badges';
      const severity = document.createElement('span');
      severity.className = `severity severity-${f.severity}`;
      severity.textContent = `${f.severity[0].toUpperCase()}${f.severity.slice(1)} signal`;
      const confidence = document.createElement('span');
      confidence.className = `confidence confidence-${f.confidence.toLowerCase().replace(/\s+/g, '-')}`;
      confidence.textContent = f.confidence;
      const points = document.createElement('span');
      points.className = 'signal-points';
      points.textContent = f.points ? `+${f.points} points` : 'Info only';
      badges.append(severity, confidence, points);
      titleRow.append(title, badges);
      const evidence = document.createElement('div');
      evidence.className = 'finding-evidence';
      evidence.textContent = f.evidence;
      const detail = document.createElement('div');
      detail.className = 'finding-explanation';
      detail.textContent = f.detail;
      content.append(titleRow, evidence, detail);
      row.append(dot, content);
      findingsEl.appendChild(row);
    });

    // recommendations
    const recMap = {
      'sender-missing': 'Inspect the original message headers and verify the sender through a contact method you already trust.',
      'multiple-senders': 'Do not trust the display name alone. Verify the message through the organization’s official website or app.',
      'sender-brand-mismatch': 'Do not reply or use links in the message. Contact the named organization using its official website or app.',
      'sender-domain-lookalike': 'Check the sender domain character by character and contact the organization through its official website or app.',
      'reply-to-mismatch': 'Do not reply with sensitive information. Confirm the reply address using a trusted contact method.',
      'return-path-mismatch': 'A different Return-Path can be legitimate, but verify unexpected messages and payment requests independently.',
      'authentication-failed': 'Treat the supplied authentication failure as a warning. Check the original message in a trusted mail system; pasted headers can be forged.',
      links: 'Do not open the link. Navigate to the organization’s official website or app yourself instead.',
      'sensitive-request': 'Never send passwords or verification codes by email. Contact the organization using a known, independent channel.',
      'payment-change': 'Verify changed bank or payment instructions with a known contact using a separate channel before transferring money.',
      urgency: 'Pause and verify the deadline or threat independently instead of following instructions in the email.',
      attachment: 'Do not open unexpected attachments. Confirm with the sender through a trusted channel and scan files with your security software.'
    };
    let recs = analysis.findings.map(f => recMap[f.id]).filter(Boolean);
    if (!recs.length) recs = ['No defined warning signal matched. This scan cannot verify sender identity or prove the email is safe; independently verify unexpected requests.'];
    recommendationsEl.innerHTML = recs.map(r => `<div class="recommendation" role="listitem"><span class="check" aria-hidden="true">✓</span><span>${escapeHtml(r)}</span></div>`).join('');

    // annotated body
    annotatedBodyEl.innerHTML = buildSegmentsHtml(parsed.displayBody || '(No readable message body found.)', parsed.isHtml ? [] : analysis.highlightRanges);
    const scoredFindings = analysis.findings.filter(finding => finding.points > 0).length;
    const contextNotes = analysis.findings.length - scoredFindings;
    statusEl.textContent = `Analysis complete. ${scoredFindings} scored warning${scoredFindings === 1 ? '' : 's'} and ${contextNotes} context note${contextNotes === 1 ? '' : 's'}. ${bucket.label}; triage score ${score} out of 100.`;
  }
})();
