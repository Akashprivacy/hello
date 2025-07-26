
import express, { Request, Response } from 'express';
import puppeteer, { type Cookie, type Page, type Frame, Browser, HTTPResponse } from 'puppeteer';
import cors from 'cors';
import dotenv from 'dotenv';
import { GoogleGenAI, Type } from '@google/genai';
import { CookieCategory, type CookieInfo, type ScanResultData, type TrackerInfo, ComplianceStatus, type DpaAnalysisResult, type DpaPerspective, type VulnerabilityScanResult, type VulnerabilityCategory } from './types.js';

dotenv.config();

const app = express();
const port = 3001;

app.use(cors());
app.use(express.json({ limit: '5mb' })); // Increase limit for DPA text

if (!process.env.API_KEY) {
  console.error("FATAL ERROR: API_KEY environment variable is not set.");
  (process as any).exit(1);
}

const ai = new GoogleGenAI({ apiKey: process.env.API_KEY });
const model = "gemini-2.5-flash";

const knownTrackerDomains = [
    'google-analytics.com', 'googletagmanager.com', 'analytics.google.com', 'doubleclick.net', 'googleadservices.com', 'googlesyndication.com', 'connect.facebook.net', 'facebook.com/tr', 'c.clarity.ms', 'clarity.ms', 'hotjar.com', 'hotjar.io', 'hjid.hotjar.com', 'hubspot.com', 'hs-analytics.net', 'track.hubspot.com', 'linkedin.com/px', 'ads.linkedin.com', 'twitter.com/i/ads', 'ads-twitter.com', 'bing.com/ads', 'semrush.com', 'optimizely.com', 'vwo.com', 'crazyegg.com', 'taboola.com', 'outbrain.com', 'criteo.com', 'addthis.com', 'sharethis.com', 'tiqcdn.com', // Tealium
];

const getHumanReadableExpiry = (puppeteerCookie: Cookie): string => {
    if (puppeteerCookie.session || puppeteerCookie.expires === -1) return "Session";
    const expiryDate = new Date(puppeteerCookie.expires * 1000);
    const now = new Date();
    const diffSeconds = (expiryDate.getTime() - now.getTime()) / 1000;
    if (diffSeconds < 0) return "Expired";
    if (diffSeconds < 3600) return `${Math.round(diffSeconds / 60)} minutes`;
    if (diffSeconds < 86400) return `${Math.round(diffSeconds / 3600)} hours`;
    if (diffSeconds < 86400 * 30) return `${Math.round(diffSeconds / 86400)} days`;
    if (diffSeconds < 86400 * 365) return `${Math.round(diffSeconds / (86400 * 30))} months`;
    const years = parseFloat((diffSeconds / (86400 * 365)).toFixed(1));
    return `${years} year${years > 1 ? 's' : ''}`;
};

async function findAndClickButton(frame: Frame, keywords: string[]): Promise<boolean> {
  for (const text of keywords) {
    try {
      const clicked = await frame.evaluate((t) => {
        const selectors = 'button, a, [role="button"], input[type="submit"], input[type="button"]';
        const elements = Array.from(document.querySelectorAll(selectors));
        const target = elements.find(el => {
            const elText = (el.textContent || el.getAttribute('aria-label') || (el as HTMLInputElement).value || '').trim().toLowerCase();
            return elText.includes(t)
        });
        if (target) {
          (target as HTMLElement).click();
          return true;
        }
        return false;
      }, text);
      if (clicked) {
        console.log(`[CONSENT] Clicked button containing: "${text}"`);
        await new Promise(r => setTimeout(r, 1500)); // Wait for actions post-click
        return true;
      }
    } catch (error) {
       if (error instanceof Error && !frame.isDetached()) {
         console.warn(`[CONSENT] Warning on frame ${frame.url()}: ${error.message}`);
       }
    }
  }
  return false;
}

async function handleConsent(page: Page, action: 'accept' | 'reject'): Promise<boolean> {
  console.log(`[CONSENT] Attempting to ${action} consent...`);
  const acceptKeywords = ["accept all", "allow all", "agree to all", "accept cookies", "agree", "accept", "allow", "i agree", "ok", "got it", "continue"];
  const rejectKeywords = ["reject all", "deny all", "decline all", "reject cookies", "disagree", "reject", "deny", "decline", "necessary only"];
  
  const keywords = action === 'accept' ? acceptKeywords : rejectKeywords;

  if (await findAndClickButton(page.mainFrame(), keywords)) return true;
  for (const frame of page.frames()) {
    if (!frame.isDetached() && frame !== page.mainFrame() && await findAndClickButton(frame, keywords)) return true;
  }
  
  console.log(`[CONSENT] No actionable button found for "${action}".`);
  return false;
}

const collectPageData = async (page: Page): Promise<{ cookies: Cookie[], trackers: Set<string> }> => {
    const trackers = new Set<string>();
    const requestListener = (request: any) => {
        const reqUrl = request.url();
        const trackerDomain = knownTrackerDomains.find(domain => reqUrl.includes(domain));
        if (trackerDomain) trackers.add(`${trackerDomain}|${reqUrl}`);
    };
    page.on('request', requestListener);
    
    await page.reload({ waitUntil: 'networkidle2' });
    
    const cookies = await page.cookies();
    
    page.off('request', requestListener); // Clean up listener
    return { cookies, trackers };
}

interface ApiScanRequestBody { url: string; }

app.post('/api/scan', async (req: Request<{}, ScanResultData | { error: string }, ApiScanRequestBody>, res: Response<ScanResultData | { error: string }>) => {
  const { url } = req.body;
  if (!url) return res.status(400).json({ error: 'URL is required' });

  console.log(`[SERVER] Received scan request for: ${url}`);
  let browser: Browser | null = null;
  try {
    browser = await puppeteer.launch({ headless: true, args: ['--no-sandbox', '--disable-setuid-sandbox', '--start-maximized'] });
    const context = await browser.createBrowserContext();
    const page = await context.newPage();
    await page.setUserAgent('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36');
    await page.setViewport({ width: 1920, height: 1080 });

    console.log('[SCAN] Capturing pre-consent state...');
    await page.goto(url, { waitUntil: 'networkidle2', timeout: 45000 });
    const screenshotBase64 = await page.screenshot({ encoding: 'base64', type: 'jpeg', quality: 70 });
    const { cookies: preConsentCookies, trackers: preConsentTrackers } = await collectPageData(page);
    console.log(`[SCAN] Pre-consent: ${preConsentCookies.length} cookies, ${preConsentTrackers.size} trackers.`);
    
    console.log('[SCAN] Capturing post-rejection state...');
    await handleConsent(page, 'reject');
    const { cookies: postRejectCookies, trackers: postRejectTrackers } = await collectPageData(page);
    console.log(`[SCAN] Post-rejection: ${postRejectCookies.length} cookies, ${postRejectTrackers.size} trackers.`);
    
    console.log('[SCAN] Capturing post-acceptance state...');
    await page.reload({ waitUntil: 'networkidle2' });
    await handleConsent(page, 'accept');
    const { cookies: postAcceptCookies, trackers: postAcceptTrackers } = await collectPageData(page);
    console.log(`[SCAN] Post-acceptance: ${postAcceptCookies.length} cookies, ${postAcceptTrackers.size} trackers.`);

    const allCookieMap = new Map<string, any>();
    const allTrackerMap = new Map<string, any>();

    const processItems = (map: Map<string, any>, items: any[], state: string, isCookie: boolean) => {
      items.forEach((item: any) => {
        const key = isCookie ? `${item.name}|${item.domain}|${item.path}` : `${item.split('|')[0]}|${item.split('|')[1]}`;
        if (!map.has(key)) map.set(key, { states: new Set() });
        map.get(key).states.add(state);
        map.get(key).data = item;
      });
    };
    
    processItems(allCookieMap, preConsentCookies, 'pre-consent', true);
    processItems(allCookieMap, postRejectCookies, 'post-rejection', true);
    processItems(allCookieMap, postAcceptCookies, 'post-acceptance', true);
    processItems(allTrackerMap, Array.from(preConsentTrackers), 'pre-consent', false);
    processItems(allTrackerMap, Array.from(postRejectTrackers), 'post-rejection', false);
    processItems(allTrackerMap, Array.from(postAcceptTrackers), 'post-acceptance', false);

    const allItemsToAnalyze = [
        ...Array.from(allCookieMap.values()).map(value => ({ type: 'cookie', data: value })),
        ...Array.from(allTrackerMap.values()).map(value => ({ type: 'tracker', data: value }))
    ];

    if (allItemsToAnalyze.length === 0) {
        return res.json({
            cookies: [], trackers: [], screenshotBase64,
            compliance: {
                gdpr: { riskLevel: 'Low', assessment: 'No cookies or trackers were detected.'},
                ccpa: { riskLevel: 'Low', assessment: 'No cookies or trackers were detected.'},
            }
        });
    }

    // --- BATCHING LOGIC ---
    const BATCH_SIZE = 15; // Further reduced batch size for maximum stability
    const batches = [];
    for (let i = 0; i < allItemsToAnalyze.length; i += BATCH_SIZE) {
        batches.push(allItemsToAnalyze.slice(i, i + BATCH_SIZE));
    }
    console.log(`[AI] Splitting analysis into ${batches.length} batch(es) of size ~${BATCH_SIZE}.`);

    const analyzeBatch = async (batch: any[], batchNum: number, maxRetries = 2): Promise<any[]> => {
      const itemsForBatchAnalysis = batch.map(item => {
        if (item.type === 'cookie') {
            const { name, domain, path } = item.data.data;
            return { type: 'cookie', key: `${name}|${domain}|${path}`, name, provider: domain, states: Array.from(item.data.states) };
        }
        const [provider] = item.data.data.split('|');
        return { type: 'tracker', key: item.data.data, provider, states: Array.from(item.data.states) };
      });
  
      const batchPrompt = `You are a privacy expert categorizing web technologies. Given this batch of cookies and trackers and the states they were observed in ('pre-consent', 'post-rejection', 'post-acceptance'), provide a JSON array. For each item:
- key: The original key.
- category: Categorize into 'Necessary', 'Functional', 'Analytics', 'Marketing', or 'Unknown'. Be strict: only essential-for-operation items are 'Necessary'.
- purpose: (For cookies only) A very brief, one-sentence description of the cookie's likely function. Limit to 15 words. If not a cookie, return an empty string.
- complianceStatus: Determine based on its 'states' and 'category':
    - If category is 'Necessary': 'Compliant'.
    - If state includes 'pre-consent' AND category is NOT 'Necessary': 'Pre-Consent Violation'.
    - If state includes 'post-rejection' AND category is NOT 'Necessary': 'Post-Rejection Violation'.
    - Otherwise: 'Compliant'.
Input Data:
${JSON.stringify(itemsForBatchAnalysis, null, 2)}
Return ONLY the valid JSON array of results.`;
      
      const batchResponseSchema = {
        type: Type.ARRAY,
        items: {
            type: Type.OBJECT,
            properties: {
                key: { type: Type.STRING },
                category: { type: Type.STRING },
                purpose: { type: Type.STRING },
                complianceStatus: { type: Type.STRING }
            },
            required: ["key", "category", "purpose", "complianceStatus"]
        }
      };
      
      for (let attempt = 0; attempt <= maxRetries; attempt++) {
        try {
            console.log(`[AI] Analyzing batch ${batchNum + 1}/${batches.length} (Attempt ${attempt + 1})...`);
            const result = await ai.models.generateContent({
                model, contents: batchPrompt,
                config: {
                    responseMimeType: "application/json",
                    responseSchema: batchResponseSchema,
                },
            });
            const resultText = result.text;
            if (!resultText) {
                throw new Error(`Gemini API returned an empty response for analysis batch #${batchNum + 1}.`);
            }
            return JSON.parse(resultText);
        } catch(error) {
            console.warn(`[AI] Attempt ${attempt + 1}/${maxRetries + 1} failed for batch ${batchNum + 1}.`, error instanceof Error ? error.message : error);
            if (attempt === maxRetries) {
                console.error(`[AI] Batch ${batchNum + 1} failed after ${maxRetries + 1} attempts.`);
                throw error;
            }
            await new Promise(res => setTimeout(res, 1500 * (attempt + 1))); // Exponential backoff
        }
      }
      throw new Error(`Exhausted all retries for batch ${batchNum + 1}`);
    };

    const batchPromises = batches.map((batch, index) => analyzeBatch(batch, index));
    const allBatchAnalyses = await Promise.all(batchPromises);
    const aggregatedAnalysis = allBatchAnalyses.flat();
    console.log('[AI] All batches analyzed successfully.');

    // --- FINAL COMPLIANCE ASSESSMENT ---
    const violationSummary = {
        preConsentViolations: aggregatedAnalysis.filter(a => a.complianceStatus === 'Pre-Consent Violation').length,
        postRejectionViolations: aggregatedAnalysis.filter(a => a.complianceStatus === 'Post-Rejection Violation').length,
        totalMarketing: aggregatedAnalysis.filter(a => a.category === CookieCategory.MARKETING).length,
        totalAnalytics: aggregatedAnalysis.filter(a => a.category === CookieCategory.ANALYTICS).length,
        totalItems: allItemsToAnalyze.length,
    };
    
    const compliancePrompt = `You are a privacy expert providing a risk assessment. Based on this summary from a website scan, provide a JSON object with "gdpr" and "ccpa" keys.
Summary:
${JSON.stringify(violationSummary, null, 2)}
For both GDPR and CCPA, provide:
- riskLevel: 'Low', 'Medium', or 'High'. Any violation ('preConsentViolations' or 'postRejectionViolations' > 0) immediately makes the risk 'High'. A large number of marketing/analytics trackers suggests at least 'Medium' risk.
- assessment: A brief, professional summary explaining the risk level. Specifically mention the number of violations as the primary reason for a 'High' risk assessment.
Return ONLY the valid JSON object.`;
    
    const complianceSchema = {
      type: Type.OBJECT, properties: {
          gdpr: { type: Type.OBJECT, properties: { riskLevel: { type: Type.STRING }, assessment: { type: Type.STRING } }, required: ['riskLevel', 'assessment']},
          ccpa: { type: Type.OBJECT, properties: { riskLevel: { type: Type.STRING }, assessment: { type: Type.STRING } }, required: ['riskLevel', 'assessment']},
      }, required: ['gdpr', 'ccpa']
    };
    
    console.log('[AI] Requesting final compliance assessment...');
    const complianceResult = await ai.models.generateContent({
        model, contents: compliancePrompt,
        config: { responseMimeType: "application/json", responseSchema: complianceSchema },
    });
    
    const complianceText = complianceResult.text;
    if (!complianceText) {
      throw new Error('Gemini API returned an empty response for the final compliance assessment.');
    }
    const complianceAnalysis = JSON.parse(complianceText);
    
    // --- MERGE AND ENRICH DATA ---
    const analysisMap = new Map(aggregatedAnalysis.map((item: any) => [item.key, item]));
    const scannedUrlHostname = new URL(url).hostname;
    
    const finalEnrichedCookies: CookieInfo[] = Array.from(allCookieMap.values()).map(c => {
        const key = `${c.data.name}|${c.data.domain}|${c.data.path}`;
        const analyzed = analysisMap.get(key);
        const domain = c.data.domain.startsWith('.') ? c.data.domain : `.${c.data.domain}`;
        const rootDomain = `.${scannedUrlHostname.replace(/^www\./, '')}`;
        return {
            key, name: c.data.name, provider: c.data.domain, expiry: getHumanReadableExpiry(c.data),
            party: domain.endsWith(rootDomain) ? 'First' : 'Third',
            isHttpOnly: c.data.httpOnly, isSecure: c.data.secure,
            complianceStatus: analyzed?.complianceStatus || 'Unknown',
            category: analyzed?.category || CookieCategory.UNKNOWN,
            purpose: analyzed?.purpose || 'No purpose determined.',
        };
    });

    const finalEnrichedTrackers: TrackerInfo[] = Array.from(allTrackerMap.values()).map(t => {
        const [provider, trackerUrl] = t.data.split('|');
        const key = t.data;
        const analyzed = analysisMap.get(key);
        return {
            key, url: trackerUrl, provider,
            category: analyzed?.category || CookieCategory.UNKNOWN,
            complianceStatus: analyzed?.complianceStatus || 'Unknown',
        };
    });

    res.json({ cookies: finalEnrichedCookies, trackers: finalEnrichedTrackers, compliance: complianceAnalysis, screenshotBase64 });

  } catch (error) {
    const message = error instanceof Error ? error.message : "An unknown error occurred.";
    console.error('[SERVER] Scan failed:', message);
    if (error instanceof Error && error.message.includes("JSON")) {
       res.status(500).json({ error: `An AI analysis step failed due to invalid data format. This can happen with complex sites. Please try again. Details: ${message}` });
    } else {
       res.status(500).json({ error: `Failed to scan ${url}. ${message}` });
    }
  } finally {
    if (browser) await browser.close();
  }
});

app.post('/api/scan-vulnerabilities', async (req: Request<{}, VulnerabilityScanResult | { error: string }, ApiScanRequestBody>, res: Response<VulnerabilityScanResult | { error: string }>) => {
    const { url } = req.body;
    if (!url) return res.status(400).json({ error: 'URL is required' });

    console.log(`[SERVER] Received vulnerability scan request for: ${url}`);
    let browser: Browser | null = null;
    try {
        browser = await puppeteer.launch({ headless: true, args: ['--no-sandbox', '--disable-setuid-sandbox'] });
        const page = await browser.newPage();
        
        const response = await page.goto(url, { waitUntil: 'networkidle0', timeout: 45000 });
        if (!response) throw new Error('Could not get a response from the URL.');

        const headers = response.headers();
        const cookies = await page.cookies();
        
        const pageData = await page.evaluate(() => {
          const comments: string[] = [];
          const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_COMMENT, null);
          let node;
          while(node = walker.nextNode()) {
            if (node.nodeValue) comments.push(node.nodeValue.trim());
          }

          const externalScripts = Array.from(document.querySelectorAll('script[src]'))
                 .map(s => s.getAttribute('src'))
                 .filter((src): src is string => !!src && (src.startsWith('http') || src.startsWith('//')));
                 
          const metaTags = Array.from(document.querySelectorAll('meta')).map(m => ({ name: m.name, content: m.content }));

          const insecureLinks = Array.from(document.querySelectorAll('a[target="_blank"]:not([rel~="noopener"]):not([rel~="noreferrer"])'))
            .map(a => (a as HTMLAnchorElement).href);

          return { comments, externalScripts, metaTags, insecureLinks };
        });

        const vulnerabilityPrompt = `
          You are a Lead Penetration Tester with extensive experience in web application security, threat modeling, and OWASP standards. You are conducting a black-box assessment of "${url}".
          Your analysis must be meticulous, accurate, and actionable. Your response MUST be a single, valid JSON object conforming to the schema. Do not add markdown.

          **Collected Intelligence:**
          *   **HTTP Headers:** ${JSON.stringify(headers, null, 2)}
          *   **Cookies:** ${JSON.stringify(cookies.map(c => ({ name: c.name, secure: c.secure, httpOnly: c.httpOnly, sameSite: c.sameSite })), null, 2)}
          *   **Meta Tags:** ${JSON.stringify(pageData.metaTags, null, 2)}
          *   **External Scripts:** ${JSON.stringify(pageData.externalScripts, null, 2)}
          *   **HTML Comments:** ${JSON.stringify(pageData.comments, null, 2)}
          *   **Insecure Links (Tabnabbing):** ${JSON.stringify(pageData.insecureLinks, null, 2)}
          
          **Analysis & Reporting Mandate:**
          1.  **Overall Risk Score & Summary:**
              *   **score:** Assign a CVSS-like score from 0.0 to 10.0. Critical findings (e.g., missing CSP on a complex site) should push the score above 8.0. A well-configured site should be below 3.0.
              *   **level:** Assign a risk level ('Critical', 'High', 'Medium', 'Low', 'Informational') based on the highest-risk finding.
              *   **summary:** A C-level summary of the site's security posture.
          2.  **Findings Array:** For each identified vulnerability, create a detailed finding object.
              *   **name:** Standard vulnerability name (e.g., "Missing Content-Security-Policy Header").
              *   **riskLevel:** Classify the risk of this specific finding.
              *   **category:** Categorize using one of: 'Security Headers', 'Cookie Configuration', 'Information Exposure', 'Insecure Transport', 'Software Fingerprinting', 'Frontend Security', 'Best Practices', 'Unknown'.
              *   **description:** Explain the vulnerability and its context for this site.
              *   **impact:** Detail the potential consequences of exploitation (e.g., data theft, session hijacking, phishing).
              *   **evidence:** Quote the specific data point from the collected intelligence that proves this vulnerability exists.
              *   **remediation:** Provide clear, actionable steps to fix it. Include code snippets or configuration examples where possible.
              *   **references:** Provide an array of objects with 'title' and 'url' linking to OWASP, Mozilla Developer Network (MDN), or other authoritative sources.
          
          **Focus Areas:**
          *   **Headers:** Scrutinize for missing or weak \`Content-Security-Policy\`, \`Strict-Transport-Security\`, \`X-Content-Type-Options\`, \`X-Frame-Options\`, \`Permissions-Policy\`, \`Referrer-Policy\`.
          *   **Information Leakage:** Check for revealing headers (\`Server\`, \`X-Powered-By\`), verbose comments, or meta tags (\`generator\`).
          *   **Cookie Security:** Audit every cookie for missing \`Secure\`, \`HttpOnly\`, and strict \`SameSite\` attributes.
          *   **Frontend Security:** Report on Tabnabbing risks from insecure links. Acknowledge risks from numerous third-party scripts.
          Base your analysis ONLY on the data provided. If no issues are found, return an empty 'findings' array and a 'Low' risk score.
        `;

        const vulnerabilityResponseSchema = {
          type: Type.OBJECT,
          properties: {
              overallRisk: { type: Type.OBJECT, properties: {
                  level: { type: Type.STRING },
                  score: { type: Type.NUMBER },
                  summary: { type: Type.STRING }
              }, required: ["level", "score", "summary"]},
              findings: { type: Type.ARRAY, items: {
                  type: Type.OBJECT, properties: {
                      name: { type: Type.STRING },
                      riskLevel: { type: Type.STRING },
                      category: { type: Type.STRING },
                      description: { type: Type.STRING },
                      impact: { type: Type.STRING },
                      evidence: { type: Type.STRING },
                      remediation: { type: Type.STRING },
                      references: { type: Type.ARRAY, items: {
                          type: Type.OBJECT, properties: {
                              title: { type: Type.STRING },
                              url: { type: Type.STRING }
                          }, required: ["title", "url"]
                      }}
                  }, required: ["name", "riskLevel", "category", "description", "impact", "evidence", "remediation", "references"]
              }}
          },
          required: ["overallRisk", "findings"]
        };

        const result = await ai.models.generateContent({
            model,
            contents: vulnerabilityPrompt,
            config: {
                responseMimeType: "application/json",
                responseSchema: vulnerabilityResponseSchema,
            },
        });

        const resultText = result.text;
        if (!resultText) throw new Error('Gemini API returned an empty response for vulnerability analysis.');
        
        const analysisResult = JSON.parse(resultText) as VulnerabilityScanResult;
        res.json(analysisResult);

    } catch (error) {
        const message = error instanceof Error ? error.message : "An unknown error occurred.";
        console.error('[SERVER] Vulnerability scan failed:', message);
        res.status(500).json({ error: `Failed to scan ${url}. ${message}` });
    } finally {
        if (browser) await browser.close();
    }
});


interface DpaReviewRequestBody { dpaText: string; perspective: DpaPerspective; }

app.post('/api/review-dpa', async (req: Request<{}, DpaAnalysisResult | { error: string }, DpaReviewRequestBody>, res: Response<DpaAnalysisResult | { error: string }>) => {
    const { dpaText, perspective } = req.body;
    if (!dpaText || !perspective) {
        return res.status(400).json({ error: 'DPA text and perspective are required' });
    }

    console.log(`[SERVER] Received DPA review request from perspective: ${perspective}`);

    try {
        const perspectiveText = perspective === 'controller' ? 'Data Controller' : 'Data Processor';
        const dpaPrompt = `
          You are a world-class data privacy lawyer with deep expertise in GDPR, CCPA, and international data transfer law. Your task is to review the following Data Processing Agreement (DPA).
          Analyze the text from the perspective of a **${perspectiveText}**.
          Your response MUST be a single, valid JSON object.
          For each major clause area, provide a neutral summary, a risk analysis from the specified perspective, and a concrete recommendation.

          The major clause areas to analyze are:
          - "Subject Matter and Scope of Processing"
          - "Data Subject Rights"
          - "Processor's Obligations (Confidentiality & Security)"
          - "Sub-processing"
          - "Liability and Indemnity"
          - "Audit Rights"
          - "Data Breach Notification"
          - "Termination and Data Return/Deletion"
          
          If a clause is missing or poorly defined, state that in the risk analysis. For each clause, also provide a "riskLevel" of 'Low', 'Medium', or 'High'.

          Here is the DPA text:
          ---
          ${dpaText}
          ---
        `;

        const dpaResponseSchema = {
            type: Type.OBJECT,
            properties: {
                overallRisk: { type: Type.OBJECT, properties: {
                    level: { type: Type.STRING, description: "Overall risk level, can be 'Low', 'Medium', or 'High'." },
                    summary: { type: Type.STRING, description: "A brief summary explaining the overall risk level based on the analysis."}
                }, required: ["level", "summary"]},
                analysis: { type: Type.ARRAY, items: {
                    type: Type.OBJECT, properties: {
                        clause: { type: Type.STRING, description: "The name of the DPA clause being analyzed." },
                        summary: { type: Type.STRING, description: "A neutral summary of what the clause contains." },
                        risk: { type: Type.STRING, description: "A detailed analysis of the risks for the specified perspective." },
                        riskLevel: { type: Type.STRING, description: "Risk level for this specific clause: 'Low', 'Medium', or 'High'."},
                        recommendation: { type: Type.STRING, description: "A concrete, actionable recommendation for negotiation or clarification." }
                    }, required: ["clause", "summary", "risk", "riskLevel", "recommendation"]
                }}
            },
            required: ["overallRisk", "analysis"]
        };

        const result = await ai.models.generateContent({
            model,
            contents: dpaPrompt,
            config: {
                responseMimeType: "application/json",
                responseSchema: dpaResponseSchema,
            },
        });

        const resultText = result.text;
        if (!resultText) throw new Error('Gemini API returned an empty response for DPA analysis.');

        const analysisResult = JSON.parse(resultText) as DpaAnalysisResult;
        res.json(analysisResult);

    } catch (error) {
        const message = error instanceof Error ? error.message : "An unknown error occurred.";
        console.error('[SERVER] DPA review failed:', message);
        res.status(500).json({ error: `Failed to review DPA. ${message}` });
    }
});

app.listen(port, () => {
  console.log(`[SERVER] Cookie Care listening on http://localhost:${port}`);
});
