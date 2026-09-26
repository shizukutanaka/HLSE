/* hlse_advisory.c — the public verdict-interpretation layer: score→action
 * ladders, blind-spot/exoneration hedges, attack-class labels, pattern ids,
 * confidence, attacker-objective, safe-destination, homoglyph/ASCII-diff
 * reports, verify/triage/cascade advisories, canonical-brand confirm.
 * Extracted verbatim from hlse_core.c (split increment 7). The CLI
 * printers consume these; nothing here reads flag globals or prints. */
#include <string.h>
#include <stddef.h>
#include <stdint.h>
#include <ctype.h>
#include "hlse_core.h"
#include "hlse_text.h"
#include "hlse_util.h"

const char *
hlse_action_for_score(int score) {
    if (score >= 80) return "ISOLATE";
    if (score >= 60) return "BLOCK";
    if (score >= 40) return "ALERT";
    if (score >= 15) return "LOG";
    return "SAFE";
}

/* Map a score to a monotonic severity integer (0–4) aligned with CVSS-style
 * numeric severity levels.  Consumers can write `severity >= 3` instead of
 * `action == "BLOCK" || action == "ISOLATE"`, making rules stable against any
 * future insertion of a new named tier:
 *   0 = SAFE    (0..14)
 *   1 = LOG    (15..39)
 *   2 = ALERT  (40..59)
 *   3 = BLOCK  (60..79)
 *   4 = ISOLATE(80+)    */
int
hlse_severity_for_score(int score) {
    if (score >= 80) return 4;
    if (score >= 60) return 3;
    if (score >= 40) return 2;
    if (score >= 15) return 1;
    return 0;
}

/* Recommended next action for an actionable verdict (score >= 60).
 *
 * A detector answers "is this dangerous?"; the user's real question is "what
 * do I do now?". For the highest-stakes, time-critical checks we return a
 * concrete remediation directive, turning a verdict into a response. `kind`
 * is the subcommand label ("clipboard", "secret", "email", "url", "file").
 * Returns NULL when there is no specific guidance (caller prints nothing).  */
const char *
hlse_remediation_for(const char *kind, int score) {
    if (score < 60 || !kind) return NULL;
    if (strcmp(kind, "clipboard") == 0)
        return "Do NOT send funds. Clipboard-hijacker malware may be active: "
               "re-copy the address, verify every character against the source, "
               "and run a malware scan before transacting.";
    if (strcmp(kind, "secret") == 0)
        return "Treat this credential as compromised: revoke/rotate it now and "
               "purge it from git history (git filter-repo / BFG) — commits are "
               "already cloned.";
    if (strcmp(kind, "email") == 0)
        return "Do not click links, open attachments, or reply. Verify the "
               "sender through a separately-known channel before acting.";
    if (strcmp(kind, "url") == 0)
        return "Do not enter credentials or payment details. Navigate to the "
               "brand's site by typing its known address, not via this link.";
    if (strcmp(kind, "file") == 0)
        return "Do not open or execute this file. Inspect it in a sandbox or "
               "delete it; the real type does not match its name.";
    return NULL;
}

/* Blind-spot disclosure for a CLEAN verdict (score 0). A clean result means
 * "no syntactic deception markers found" — NOT "safe". Stating what HLSE
 * cannot see prevents the most dangerous outcome: a false OK the user trusts
 * and acts on. Returned for the phishing-judgment checks where structural
 * cleanliness is weakest evidence of safety; NULL otherwise.              */
const char *
hlse_blindspot_for(const char *kind) {
    if (!kind) return NULL;
    if (strcmp(kind, "url") == 0)
        return "structural check only — a pixel-perfect clone on a clean or "
               "newly-compromised domain still phishes; confirm the brand "
               "independently before entering credentials or payment.";
    if (strcmp(kind, "text") == 0)
        return "keyword/structure based — a novel or carefully-worded scam "
               "with no known phrasing can read clean; trust your judgment on "
               "unexpected requests for money or credentials. Prompt-injection "
               "coverage is structural only: hidden carriers (Unicode Tags, "
               "long zero-width runs), canonical override phrases and LLM "
               "control tokens are detected, but a novel injection written "
               "in ordinary prose is a semantic problem this does not "
               "solve — do not treat a clean result as clearance to feed "
               "untrusted content to an agent.";
    if (strcmp(kind, "email") == 0)
        return "header forensics only — authentication PASS (SPF/DKIM/DMARC) is "
               "not a safety guarantee: a brand name in the display field, an "
               "attacker-owned look-alike/cousin domain, or a breached but "
               "legitimate account all pass authentication by design. Read the "
               "actual From-address domain character-by-character and verify "
               "unexpected requests out-of-band.";
    if (strcmp(kind, "clipboard") == 0)
        return "swap check only — this compares the two addresses you provided; "
               "it cannot confirm the address belongs to the intended recipient. "
               "Crypto transfers are irreversible: verify the full address "
               "against the recipient's own published source before sending.";
    if (strcmp(kind, "paste") == 0)
        return "injection-pattern check only — this flags hidden or obfuscated "
               "command injection, not whether a command is safe to run. Never "
               "run a command you did not seek out or do not understand, even "
               "when it looks clean.";
    if (strcmp(kind, "url_canonical") == 0)
        return "positive authentication covers the domain name — it cannot "
               "verify the page's content, a same-site redirect, or that the "
               "service actually sent you here; close unexpected pop-ups and "
               "confirm the specific page's request is what you expect from "
               "this service before entering credentials or authorising payment.";
    if (strcmp(kind, "secret") == 0)
        return "pattern-based detection — novel credential formats, encoded "
               "secrets, or credentials split across lines that don't match "
               "known patterns will be missed; manually review high-entropy "
               "strings and any line containing 'password', 'key', or 'token'.";
    if (strcmp(kind, "network") == 0)
        return "local-view only — DNS-over-HTTPS, process-level routing, "
               "encrypted tunnels, and outbound traffic over allowed ports are "
               "invisible to this check; a compromised process may appear clean.";
    if (strcmp(kind, "package") == 0)
        return "typosquat detection only — a compromised legitimate package, "
               "a dependency confusion attack, or malicious post-install scripts "
               "inside a correctly-named package are not detected; review the "
               "package's repository, recent commits, and published checksums "
               "before installing in a production or privileged environment.";
    /* Distinct from "package": the name matched no known package AND is not a
     * near-miss of one, so this is the "cannot verify" case. Naming it
     * separately matters because the residual risk is different in kind —
     * slopsquatting. Edit-distance detection structurally cannot see a
     * fully-invented name: the large-scale study of LLM package
     * hallucinations (Spracklen et al., USENIX Security 2025 — 576k samples,
     * 16 models) measured ~19.7% of LLM-recommended packages as
     * non-existent, and found only ~13% of those were off-by-one typos while
     * roughly half were highly dissimilar to any real package. Those are
     * invisible to a distance<=2 check by construction, and HLSE is offline
     * by design so it cannot confirm existence. Say so plainly. */
    if (strcmp(kind, "package_unverified") == 0)
        return "this name matches no package HLSE knows and is not a near-miss "
               "of one — so nothing was detected, but nothing was confirmed "
               "either: HLSE is offline by design and cannot check whether the "
               "package exists. Typo-distance detection also cannot catch a "
               "wholly invented name (slopsquatting): in the USENIX Security "
               "2025 analysis of LLM-generated code, ~1 in 5 recommended "
               "packages did not exist, and about half of those were not "
               "near-misses of any real package. If this name came from an AI "
               "assistant or an unfamiliar snippet, confirm it on the registry "
               "and check its age, owner, and download history before "
               "installing — attackers pre-register plausible hallucinated "
               "names.";
    if (strcmp(kind, "file") == 0)
        return "magic-byte and filename analysis only — obfuscated payloads, "
               "encrypted content, or malicious macros inside office formats "
               "are not detected; run untrusted files through a multi-engine "
               "scanner before opening.";
    if (strcmp(kind, "audit") == 0)
        return "point-in-time configuration snapshot — kernel-level exploits, "
               "container escapes, LD_PRELOAD injection, and custom LSM bypasses "
               "are outside the scope of this check; re-run after any system or "
               "configuration change.";
    if (strcmp(kind, "protect") == 0)
        return "indicator-based scan only — memory-only ransomware, staged "
               "pre-encryption activity, encrypted C2 traffic, and ransomware "
               "that operates before writing ransom notes will not be detected; "
               "an OK here does not rule out active compromise.";
    if (strcmp(kind, "esp") == 0)
        return "string-pattern scan of the EFI System Partition only — a "
               "bootkit that uses fileless persistence, firmware-level implants, "
               "or Secure-Boot bypass techniques not matching known patterns will "
               "not be detected; an OK here does not guarantee bootloader "
               "integrity.";
    if (strcmp(kind, "scan") == 0)
        return "pattern-based secret detection only — obfuscated credentials, "
               "secrets in binary or compiled artefacts, environment variables "
               "passed at runtime, and vault-managed secrets retrieved at startup "
               "are invisible to this scan; treat as complementary to a secrets "
               "manager, not a replacement.";
    return NULL;
}

/* Exoneration: the benign explanation that would clear a HEURISTIC threat.
 * Mirror of hlse_blindspot_for — that hedges a clean OK, this hedges a
 * low-confidence threat. Scoped to the LOG/ALERT band (15..59) where false
 * positives live; at BLOCK/ISOLATE (>=60) the signals (homoglyph, @-trick,
 * clipboard swap) are high-confidence and a benign read would mislead. Gives
 * the user the *falsifying test* so they neither panic nor blindly comply. */
const char *
hlse_exoneration_for(const char *kind, int score) {
    if (!kind || score < 15 || score >= 60) return NULL;
    if (strcmp(kind, "url") == 0)
        return "heuristic — legitimate small businesses and security vendors "
               "also use hyphens and words like 'secure'/'login'. Decisive "
               "test: were you expecting this link, and does the registrable "
               "domain (just before the first single '/') belong to the real "
               "brand?";
    if (strcmp(kind, "text") == 0)
        return "heuristic — urgent or financial wording appears in genuine "
               "messages too. Decisive test: were you expecting this, and does "
               "it push you to act through an unusual channel or in a hurry?";
    if (strcmp(kind, "email") == 0)
        return "heuristic — forwarders, mailing lists, and some legitimate "
               "senders trip these checks. Decisive test: confirm the request "
               "with the sender through a separately-known channel.";
    if (strcmp(kind, "protect") == 0)
        return "heuristic \xe2\x80\x94 legitimate software (compression tools, "
               "encrypted containers, software installers) can produce "
               "high-entropy content and file patterns that resemble ransomware. "
               "Decisive test: verify the file has a publisher signature whose "
               "hash matches the vendor's published release notes.";
    if (strcmp(kind, "esp") == 0)
        return "heuristic \xe2\x80\x94 hardware-vendor firmware updates and "
               "OS-managed bootloaders also modify the EFI System Partition. "
               "Decisive test: cross-check the modified file against your last "
               "known-good ESP snapshot and the vendor's firmware changelog "
               "before taking any disruptive action.";
    if (strcmp(kind, "package") == 0)
        return "heuristic \xe2\x80\x94 a name this close to a popular library can be "
               "a legitimate fork, organisation-scoped package, or namespace "
               "variant. Decisive test: search the official registry for the "
               "exact name, verify the maintainer's username matches the "
               "original project, and check the publish date and download count.";
    if (strcmp(kind, "network") == 0)
        return "heuristic \xe2\x80\x94 update servers, telemetry daemons, and "
               "monitoring agents routinely make external connections on unusual "
               "ports. Decisive test: identify the owning process "
               "('lsof -i' or 'ss -tp') and verify it against the software's "
               "documented network requirements.";
    if (strcmp(kind, "paste") == 0)
        return "heuristic \xe2\x80\x94 legitimate install scripts and CI snippets "
               "also use curl, sudo, and base64. Decisive test: paste into a "
               "plain text editor first and read every line \xe2\x80\x94 a hidden "
               "newline or trailing command that only appears there is the "
               "decisive sign of a paste-and-run trap.";
    if (strcmp(kind, "file") == 0)
        return "heuristic \xe2\x80\x94 some legitimate tools intentionally bundle "
               "content in unconventional containers (self-extracting installers, "
               "polyglot test fixtures, archive-based package formats). Decisive "
               "test: check the file's actual origin (was it downloaded from an "
               "official site, or did it arrive unsolicited?) and scan it with a "
               "multi-engine tool (e.g. VirusTotal) before opening.";
    if (strcmp(kind, "secret") == 0)
        return "heuristic \xe2\x80\x94 test-mode keys (sk_test_/pk_test_), "
               "placeholder examples in documentation, and low-entropy sample "
               "values can match a credential pattern without being a real, "
               "live secret. Decisive test: does the value work against the "
               "provider's live API right now, and does it appear in version "
               "control history rather than a docs/example file?";
    return NULL;
}

const char *
hlse_version(void) {
    return HLSE_VERSION;
}

/* Pattern-aware exoneration: the benign explanation and falsifying test keyed
 * to the specific attack pattern that fired, not a generic URL heuristic.
 *
 * Socratic question (Perspective 24): "hlse_exoneration_for('url', score)
 * returns 'heuristic — legitimate small businesses also use hyphens and words
 * like secure/login' for EVERY LOG/ALERT URL — including URL shorteners
 * (bit.ly), DGA-style domains, free-hosting pages, and typosquats. A shortener
 * LOG user reads 'hyphens and login words' and is completely confused — their
 * URL has no hyphens. The falsifying test ('does the registrable domain belong
 * to the brand?') is unanswerable for a shortener because the registrable
 * domain IS the shortener (bit.ly). The exoneration isn't just generic; for
 * shorteners it's actively wrong. Shouldn't the benign explanation match the
 * actual signal?"
 *
 * Returns a static string matched to the pattern in the verdict, or falls
 * back to the generic hlse_exoneration_for("url", score) when no specific
 * pattern is recognisable. Returns NULL when score is outside [15, 59].
 * Thread-safe: no allocation.                                               */
const char *
hlse_url_exoneration(const Verdict *v) {
    const char *pat;
    if (!v || v->score < 15 || v->score >= 60) return NULL;
    pat = hlse_classify_url_attack(v);
    if (!pat) return hlse_exoneration_for("url", v->score);

    if (strstr(pat, "obfuscated") || strstr(pat, "shortener"))
        return "URL shorteners are standard tools for social-media links, print "
               "materials, and marketing campaigns. Decisive test: expand the link "
               "first (append '+' for bit.ly/tinyurl previews) to see the real "
               "destination before you open it";
    if (strstr(pat, "free-hosting"))
        return "developers and small teams legitimately host projects on GitHub "
               "Pages, Netlify, and similar platforms. Decisive test: search the "
               "exact domain — if it's a real project the owner is easy to find; "
               "if it's impersonating a brand, ownership will be anonymous";
    if (strstr(pat, "subdomain spoofing"))
        return "legitimate small businesses and security vendors also use hyphens "
               "and words like 'secure'/'verify' in subdomains. Decisive test: "
               "read the domain right-to-left — the registrable part just before "
               "the first '/' must belong to the real brand, not appear before it";
    if (strstr(pat, "typosquat") || strstr(pat, "lookalike"))
        return "human typing errors that coincidentally resemble brand names are "
               "common. Decisive test: was this URL typed manually or sent by "
               "someone? If sent, did the sender independently confirm it through "
               "a channel you trust?";
    if (strstr(pat, "DGA") || strstr(pat, "high-entropy"))
        return "newly-registered or randomly-named domains are also used by "
               "legitimate services, CDNs, and internal tools. Decisive test: "
               "search the domain in a search engine — a legitimate service will "
               "have a traceable history; a phishing domain will not";
    if (strstr(pat, "high-risk TLD"))
        return "high-risk TLDs (.xyz, .tk, .top) are also used by legitimate "
               "start-ups and projects. Decisive test: find the brand via a "
               "bookmark or search engine and confirm you reach the same domain";
    if (strstr(pat, "credential trick") || strstr(pat, "@-trick"))
        return "the '@' in a URL is a standard HTTP Basic Auth separator; some "
               "internal tools use it legitimately. Decisive test: paste the URL "
               "into a URL decoder — what comes after '@' is where you actually land";
    /* Fallback for any unrecognised pattern */
    return hlse_exoneration_for("url", v->score);
}

/* Pattern-aware exoneration for a text verdict — the benign explanation and
 * falsifying test keyed to the specific social-engineering pattern, not the
 * generic "urgent wording appears in genuine messages" catch-all.
 *
 * Socratic question (Perspective 30): "hlse_exoneration_for('text', score)
 * returns 'heuristic — urgent or financial wording appears in genuine messages
 * too' for every LOG/ALERT text verdict — including QR-code phishing (which
 * has nothing to do with urgent wording), callback scams (which target phone
 * numbers, not urgency language), and investment lures (which look like
 * financial advice). The falsifying test ('were you expecting this, does it
 * push you to act in a hurry?') is unanswerable for a QR code — QR codes are
 * legitimately used everywhere. Shouldn't the benign explanation and decisive
 * test match the actual signal pattern, exactly as hlse_url_exoneration does
 * for URLs?"
 *
 * Returns a static string matched to the pattern in the verdict, or falls
 * back to hlse_exoneration_for("text", score) when no specific pattern is
 * recognisable. Returns NULL when score is outside [15, 59]. Thread-safe;
 * no allocation.                                                              */
const char *
hlse_text_exoneration(const TextVerdict *v) {
    const char *pat;
    if (!v || v->score < 15 || v->score >= 60) return NULL;
    pat = hlse_classify_text_attack(v);
    if (!pat) return hlse_exoneration_for("text", v->score);

    if (strstr(pat, "device-code") || strstr(pat, "OAuth"))
        return "Microsoft and other services do send genuine verification codes "
               "you requested yourself. Decisive test: did YOU initiate a sign-in "
               "or device-pairing flow in the last 60 seconds? If not, the code "
               "is the attacker's session and entering it grants them your tokens";
    if (strstr(pat, "fake-job") || strstr(pat, "task scam"))
        return "legitimate recruiters do reach out with real openings. Decisive "
               "test: does the 'job' require you to pay anything, deposit your "
               "own funds, or buy equipment to start? A real job pays you "
               "\xe2\x80\x94 money only ever flows TO you, never from you";
    if (strstr(pat, "MFA-fatigue") || strstr(pat, "push-bombing"))
        return "legitimate sign-ins do trigger MFA prompts. Decisive test: did "
               "YOU just try to log in? If an 'approve' request or push arrives "
               "that you did not start, deny it \xe2\x80\x94 it means someone else "
               "already has your password";
    if (strstr(pat, "sextortion") || strstr(pat, "webcam blackmail"))
        return "these threats feel personal but are almost always mass-mailed "
               "bluffs. Decisive test: can they show actual footage, or only "
               "claim it? A breached password quoted from a data leak is not "
               "proof of webcam access \xe2\x80\x94 do not pay, do not reply";
    if (strstr(pat, "payment-diversion"))
        return "employees and vendors do legitimately change banks. Decisive "
               "test: call the person or company on a number you ALREADY have on "
               "file (never the contact in this message) and confirm the change "
               "before updating any payee or direct-deposit record";
    if (strstr(pat, "QR") || strstr(pat, "quishing"))
        return "QR codes appear legitimately in event tickets, restaurant menus, "
               "and physical adverts. Decisive test: scan with a QR decoder that "
               "shows the URL before opening it, then verify the domain belongs "
               "to the expected organisation; on a physical QR, check it is not a "
               "sticker placed over the original";
    if (strstr(pat, "grandparent") || strstr(pat, "emergency impersonation"))
        return "family members do have genuine emergencies. Decisive test: a "
               "familiar voice is no longer proof \xe2\x80\x94 AI clones a voice "
               "from a few seconds of audio; hang up and call them back on their "
               "own known number, and ask a pre-agreed safe word that an AI "
               "clone cannot know";
    if (strstr(pat, "refund") || strstr(pat, "subscription-renewal"))
        return "real subscriptions do auto-renew and send receipts. Decisive "
               "test: open your bank/card statement or the provider's official "
               "app directly (never the number or link here) and check whether "
               "the charge is real \xe2\x80\x94 a 'call to cancel' invoice for a "
               "service you don't use is the tell";
    if (strstr(pat, "callback") || strstr(pat, "TOAD") || strstr(pat, "vishing"))
        return "organisations do send callback numbers for account verification. "
               "Decisive test: find the number independently on the organisation's "
               "official website and call that — not the number provided here";
    if (strstr(pat, "ClickFix") || strstr(pat, "script-injection"))
        return "developers and sysadmins do share commands in messages. Decisive "
               "test: legitimate software updates and fixes are delivered through "
               "official package managers or websites — a message that asks you to "
               "paste or run a command you were not expecting is the defining sign "
               "of a script-injection lure";
    if (strstr(pat, "investment") || strstr(pat, "pig-butchering"))
        return "investment outreach from regulated firms is legitimate. Decisive "
               "test: verify the firm's authorisation on the FCA/SEC/ASIC register "
               "before sending any funds or personal information";
    if (strstr(pat, "lottery") || strstr(pat, "advance-fee"))
        return "prize notifications appear in genuine marketing campaigns. Decisive "
               "test: search the organisation's official website — genuine prizes "
               "do not require winners to pay upfront fees";
    if (strstr(pat, "prize"))
        return "prize and reward messages appear in legitimate loyalty programmes. "
               "Decisive test: log in to your account at the organisation's official "
               "domain (not via any link here) and check whether the reward appears";
    if (strstr(pat, "urgency credential") || strstr(pat, "credential / payment"))
        return "account security alerts are sent legitimately by services you use. "
               "Decisive test: navigate to the site directly (not via any link in "
               "this message) and check whether the alert appears in your account "
               "dashboard";
    if (strstr(pat, "authority impersonation"))
        return "authority figures send urgent communications legitimately. Decisive "
               "test: verify by calling the supposed sender on a number you already "
               "have — not any contact provided in this message";
    if (strstr(pat, "urgency"))
        return "time-sensitive messages are common in legitimate business. Decisive "
               "test: verify the request through a separately-known channel — "
               "urgency combined with a request to act through an unusual channel "
               "is the strongest warning sign";
    if (strstr(pat, "BEC") || strstr(pat, "CEO") ||
        strstr(pat, "wire-transfer") || strstr(pat, "wire transfer"))
        return "internal payment requests do arrive by email. Decisive test: call "
               "the supposed sender on a number you already have — wire-transfer "
               "requests without a prior phone call are a strong warning sign";
    if (strstr(pat, "tech-support"))
        return "tech-support teams do send proactive alerts about account issues. "
               "Decisive test: call the company's main switchboard (on their "
               "official website), not any number provided in this message";
    if (strstr(pat, "fake security alert") || strstr(pat, "account suspension"))
        return "account suspension and security notices are sent legitimately by "
               "service providers. Decisive test: log in to the service directly "
               "(via bookmark or search engine, not any link here) and check "
               "whether your account actually shows a problem";
    /* Fallback for any unrecognised text pattern */
    return hlse_exoneration_for("text", v->score);
}

/* Synthesize a named attack pattern from the set of signals that fired.
 *
 * Socratic question (Perspective 17): "Single-brand detection assumes one
 * attacker wearing one mask. But what if the URL simultaneously contains two
 * known brand names — 'paypal.apple-secure.com', 'netflix-amazon-billing.net'?
 * Presenting as two brands at once exploits both user bases and is harder to
 * dismiss, because each fragment looks 'almost right' in isolation. Shouldn't
 * a fundamentally different attack label surface this compound deception?"
 *
 * Returns a short human-readable attack-class label (e.g. "typosquat
 * credential-harvest page"), or NULL when the signals don't map to a
 * recognisable pattern. The label is intentionally terse — it belongs on
 * a single summary line, not a paragraph.
 *
 * Precondition: called only when score > 0 (no signals → no pattern).   */
const char *
hlse_classify_url_attack(const Verdict *v) {
    /* Scan reason strings for the signal classes we care about. */
    int has_homoglyph     = 0;  /* confusable-char, II→ll, rn/vv, Cyrillic */
    int has_idn           = 0;  /* Punycode / IDN homograph                */
    int has_typosquat     = 0;  /* edit-distance 1 or 2 from a brand       */
    int has_brand         = 0;  /* any brand-impersonation reason           */
    int has_path          = 0;  /* phishing-typical path pattern            */
    int has_tld           = 0;  /* high-risk TLD                            */
    int has_subdomain     = 0;  /* subdomain spoofing                       */
    int has_free_host     = 0;  /* brand in netlify/github.io/etc.          */
    int has_shortener     = 0;  /* URL shortener                            */
    int has_at_trick      = 0;  /* @ in authority                           */
    int has_ip            = 0;  /* IP-address host with brand in path       */
    int has_hyphen_brand  = 0;  /* brand-hyphen-securityword pattern        */
    int has_dga           = 0;  /* DGA / high-entropy random domain         */
    int n_brands          = 0;  /* count of distinct impersonated brands    */
    int i;

    if (!v || v->n_reasons == 0) return NULL;

    for (i = 0; i < v->n_reasons; i++) {
        const char *r = v->reasons[i];
        if (strstr(r, "homoglyph") || strstr(r, "Homoglyph") ||
            strstr(r, "Mixed-script"))               has_homoglyph = 1;
        if (strstr(r, "IDN") || strstr(r, "Punycode")) has_idn     = 1;
        if (strstr(r, "Typosquat") || strstr(r, "typosquat") ||
            strstr(r, "Digraph homoglyph"))           has_typosquat = 1;
        if (strstr(r, "Brand") || strstr(r, "brand") ||
            strstr(r, "Legitimate '"))                 has_brand   = 1;
        if (strstr(r, "path pattern") || strstr(r, "Phishing path"))
                                                       has_path     = 1;
        if (strstr(r, "TLD"))                          has_tld      = 1;
        if (strstr(r, "Subdomain spoofing") ||
            strstr(r, "subdomain"))                  { has_subdomain= 1; has_brand = 1; }
        if (strstr(r, "Free-hosting") ||
            strstr(r, "free page builder"))          { has_free_host= 1; has_brand = 1; }
        if (strstr(r, "shortener") || strstr(r, "Shortened"))
                                                       has_shortener= 1;
        if (strstr(r, "credential trick") ||
            strstr(r, "@ in authority"))               has_at_trick = 1;
        if (strstr(r, "IP-based URL") || strstr(r, "IP-address host"))
                                                       has_ip       = 1;
        if (strstr(r, "hyphenated with security") ||
            strstr(r, "Brand impersonation"))          has_hyphen_brand = 1;
        if (strstr(r, "DGA") || strstr(r, "high-entropy") ||
            strstr(r, "random-looking"))               has_dga      = 1;
        if (strstr(r, "Legitimate '"))                 n_brands++;
    }

    /* Priority-ordered classification: most specific / highest-confidence
     * patterns first so the label describes the dominant attack vector.  */
    if (has_idn)
        return "Unicode/IDN homograph impersonation";
    /* Perspective 17: two or more distinct brand canonical reasons means the
     * attacker is simultaneously impersonating multiple brands — a compound
     * co-spoof that is more sophisticated than any single-brand pattern. */
    if (n_brands >= 2)
        return "multi-brand co-spoof (compound impersonation)";
    if (has_homoglyph && has_brand)
        return "visual impersonation via lookalike characters";
    if (has_at_trick)
        return "authority-trick credential phishing";
    if (has_ip && has_brand)
        return "IP-hosted brand impersonation";
    if (has_free_host)
        return "free-hosting phishing infrastructure";
    if (has_subdomain && has_brand && has_path)
        return "subdomain-spoof credential-harvest page";
    if (has_subdomain && has_brand)
        return "subdomain spoofing";
    if (has_typosquat && has_path)
        return "typosquat credential-harvest page";
    if (has_typosquat)
        return "typosquat domain";
    if (has_hyphen_brand && has_path)
        return "brand-hyphen credential-harvest page";
    if (has_hyphen_brand)
        return "brand hyphenation phishing";
    if (has_brand && has_path && has_tld)
        return "classic credential-harvest phishing";
    if (has_brand && has_tld)
        return "brand phishing on high-risk TLD";
    if (has_brand)
        return "brand impersonation";
    if (has_shortener)
        return "obfuscated link (shortener conceals destination)";
    if (has_dga)
        return "DGA / random-domain phishing";
    return NULL;
}

/* Stable machine-readable pattern identifier for a URL Verdict — the URL
 * counterpart of hlse_text_pattern_id (Perspective 78). The prose label from
 * hlse_classify_url_attack may be reworded across versions; these HLSE-URL-*
 * tokens are APPEND-ONLY so SIEM/SOAR rules can route on a stable id instead
 * of substring-matching prose. Returns NULL when score is 0 or no pattern was
 * recognised. Order mirrors the classifier's priority so the most specific
 * id wins. Thread-safe; no allocation. */
const char *
hlse_url_pattern_id(const Verdict *v) {
    const char *pat = hlse_classify_url_attack(v);
    if (!pat) return NULL;
    if (strstr(pat, "IDN homograph"))            return "HLSE-URL-IDN-HOMOGRAPH";
    if (strstr(pat, "multi-brand co-spoof"))     return "HLSE-URL-MULTI-BRAND";
    if (strstr(pat, "lookalike characters"))     return "HLSE-URL-HOMOGLYPH";
    if (strstr(pat, "authority-trick"))          return "HLSE-URL-AT-CRED-TRICK";
    if (strstr(pat, "IP-hosted"))                return "HLSE-URL-IP-BRAND";
    if (strstr(pat, "free-hosting"))             return "HLSE-URL-FREEHOST";
    if (strstr(pat, "subdomain-spoof credential-harvest"))
                                                 return "HLSE-URL-SUBDOMAIN-HARVEST";
    if (strstr(pat, "subdomain spoofing"))       return "HLSE-URL-SUBDOMAIN";
    if (strstr(pat, "typosquat credential-harvest"))
                                                 return "HLSE-URL-TYPOSQUAT-HARVEST";
    if (strstr(pat, "typosquat domain"))         return "HLSE-URL-TYPOSQUAT";
    if (strstr(pat, "brand-hyphen credential-harvest"))
                                                 return "HLSE-URL-HYPHEN-HARVEST";
    if (strstr(pat, "brand hyphenation"))        return "HLSE-URL-HYPHEN-BRAND";
    if (strstr(pat, "classic credential-harvest"))
                                                 return "HLSE-URL-CRED-HARVEST";
    if (strstr(pat, "high-risk TLD"))            return "HLSE-URL-BRAND-RISKY-TLD";
    if (strstr(pat, "brand impersonation"))      return "HLSE-URL-BRAND";
    if (strstr(pat, "shortener"))                return "HLSE-URL-SHORTENER";
    if (strstr(pat, "DGA"))                       return "HLSE-URL-DGA";
    return "HLSE-URL-GENERIC";
}

/* Synthesise a named social-engineering attack pattern from the signals in a
 * text verdict — the text counterpart of hlse_classify_url_attack.
 *
 * Socratic question (Perspective 25): "hlse_classify_url_attack gives URL
 * verdicts a ▸ Pattern: label ('typosquat credential-harvest', 'authority-trick
 * credential phishing', etc.). Text verdicts above score 0 show only raw reason
 * strings and a generic exoneration. A BEC wire-transfer fraud and a grandparent
 * emergency scam both say 'Urgency pressure (N hits)' — but they need entirely
 * different responses: one requires immediate CFO verification, the other
 * requires calling the family member directly. Shouldn't text verdicts also name
 * the attack pattern so the response is directed to the right playbook?"
 *
 * Scans the reasons[] for amplifier labels and individual signal names to
 * identify the dominant tactic. Priority order mirrors threat severity.
 * Returns a short label or NULL when no signals fired. Thread-safe; no alloc. */
const char *
hlse_classify_text_attack(const TextVerdict *v) {
    int i;
    int urgency = 0, bait = 0, prize = 0, ransom = 0, authority = 0;
    int secrecy = 0, investment = 0, qr = 0, callback = 0;
    int emergency = 0, clickfix = 0;
    int fake_alert = 0, direct_fin = 0;
    int amp_bec = 0, amp_tss = 0, amp_ceo = 0, amp_laf = 0;
    int devicecode = 0, bankchange = 0, mfapush = 0, jobscam = 0, sextortion = 0;
    int refundscam = 0;

    if (!v || v->n_reasons == 0) return NULL;

    for (i = 0; i < v->n_reasons; i++) {
        const char *r = v->reasons[i];
        if (strstr(r, "Urgency pressure"))           urgency    = 1;
        if (strstr(r, "Financial/credential"))        bait       = 1;
        if (strstr(r, "Prize/reward"))                prize      = 1;
        if (strstr(r, "Ransom") || strstr(r, "ransom")) ransom   = 1;
        if (strstr(r, "Authority impersonation"))     authority  = 1;
        if (strstr(r, "Secrecy/grooming"))            secrecy    = 1;
        if (strstr(r, "Investment scam"))             investment = 1;
        if (strstr(r, "QR code phishing"))            qr         = 1;
        if (strstr(r, "Callback") || strstr(r, "TOAD") ||
            strstr(r, "smishing"))                    callback   = 1;
        if (strstr(r, "Emergency") || strstr(r, "grandparent")) emergency = 1;
        if (strstr(r, "ClickFix") || strstr(r, "Shell-pipe")) clickfix  = 1;
        if (strstr(r, "Fake security alert"))         fake_alert = 1;
        if (strstr(r, "Direct financial action"))     direct_fin = 1;
        /* Amplifier pattern labels */
        if (strstr(r, "BEC") || strstr(r, "wire transfer"))  amp_bec = 1;
        if (strstr(r, "tech-support") || strstr(r, "gift card")) amp_tss = 1;
        if (strstr(r, "CEO-fraud"))                           amp_ceo = 1;
        if (strstr(r, "lottery") || strstr(r, "advance-fee")) amp_laf = 1;
        /* OAuth device-code phishing (P64): the 2026 attack class where the
         * victim is sent to a LEGITIMATE Microsoft URL (microsoft.com/
         * devicelogin) and asked to enter an attacker-supplied code. The raw
         * reason text includes the literal phrase that fired, so we can match
         * "verification code" / "device code" / "two-factor code" surfacing
         * from the auth-bait list. Detection is unchanged; this only refines
         * the pattern label so the user knows the unique mechanism. */
        if (strstr(r, "verification code") ||
            strstr(r, "device code") ||
            strstr(r, "two-factor code") ||
            strstr(r, "one-time code") ||
            strstr(r, "otp code"))                    devicecode = 1;
        /* Payment/payroll-diversion BEC (P73): the attacker impersonates an
         * employee (to HR/payroll) or a vendor (to AP/finance) and requests a
         * BANK-ACCOUNT / direct-deposit CHANGE, diverting future payments to
         * their account. This is the fastest-growing BEC variant (FBI), but it
         * is NOT a wire-transfer and NOT credential harvest — so it needs its
         * own label and advisory. The banking-change phrases surface in the
         * matched-phrase "e.g. '...'" of the reason text, same as gift-card. */
        if (strstr(r, "bank account has changed") ||
            strstr(r, "banking details") ||
            strstr(r, "payment details have changed") ||
            strstr(r, "update our bank") ||
            strstr(r, "update our payment") ||
            strstr(r, "direct deposit") ||
            strstr(r, "new bank account") ||
            strstr(r, "new payment account"))         bankchange = 1;
        /* MFA-fatigue / push-bombing (P74): the attacker already has the
         * password and spams authenticator push prompts (or phones the victim)
         * asking them to "just approve" one. The defining tell is an
         * unsolicited request to approve an auth push. Distinct remedy: deny
         * the prompt and rotate the already-compromised password. Phrases
         * surface in the matched-phrase text of the reasons. */
        if (strstr(r, "approve the notification") ||
            strstr(r, "approve the push") ||
            strstr(r, "approve the sign-in") ||
            strstr(r, "approve the login") ||
            strstr(r, "approve the authentication") ||
            strstr(r, "approve the mfa") ||
            strstr(r, "approve the two-factor") ||
            strstr(r, "approve on your phone") ||
            strstr(r, "just approve") ||
            strstr(r, "approve in") ||
            strstr(r, "approve on your authenticator") ||
            strstr(r, "until you approve"))            mfapush = 1;
        /* Fake-job / task scam (P75): 2026's fastest-growing consumer fraud
         * (FTC: $521M, +1000% spike). The defining tell is a "job" that
         * requires the victim to PAY to start — buy equipment, deposit funds
         * to "unlock" tasks, or install a "work-from-home app" (often a RAT).
         * Distinct remedy: a real job only ever pays money TO you. Phrases
         * surface in the matched-phrase text of the reasons. */
        if (strstr(r, "work from home opportunity") ||
            strstr(r, "no experience required") ||
            strstr(r, "starter kit") ||
            strstr(r, "buy your equipment") ||
            strstr(r, "purchase the equipment") ||
            strstr(r, "equipment will be reimbursed") ||
            strstr(r, "reimbursed on first paycheck") ||
            strstr(r, "mystery shopper") ||
            strstr(r, "brand ambassador") ||
            strstr(r, "money transfer agent") ||
            strstr(r, "reshipping agent") ||
            strstr(r, "shipping agent position") ||
            strstr(r, "per day from home") ||
            strstr(r, "per week from home") ||
            strstr(r, "weekly income from home"))      jobscam = 1;
        /* Sextortion / webcam-extortion (P76): the attacker claims to hold
         * intimate footage (real, bluffed, or AI-deepfaked) and threatens to
         * send it to the victim's contacts unless paid. Distinct from
         * ransomware extortion — there is nothing to "recover"; the threat is
         * usually an empty mass-mailed bluff. Distinct remedy: do not pay, do
         * not reply, preserve and report. Phrases surface in the matched-phrase
         * text of the Ransom/extortion reason. */
        if (strstr(r, "footage of you") ||
            strstr(r, "video of you") ||
            strstr(r, "photos of you") ||
            strstr(r, "recorded you") ||
            strstr(r, "your webcam") ||
            strstr(r, "your camera") ||
            strstr(r, "camera was hacked") ||
            strstr(r, "adult content") ||
            strstr(r, "watching explicit") ||
            strstr(r, "compromising footage") ||
            strstr(r, "compromising material") ||
            strstr(r, "send this to your contacts") ||
            strstr(r, "send this video to your contacts"))  sextortion = 1;
        /* Refund / subscription-renewal scam (P77): a fake auto-renewal invoice
         * (Geek Squad, Norton, McAfee, PayPal) that exists to make the victim
         * CALL to "cancel and get a refund" — then the agent demands remote
         * access or tricks the victim into "returning an over-refund" via gift
         * cards/wire. Distinct from a plain callback scam by the refund pretext.
         * Phrases surface in the matched-phrase text of the reasons. */
        if (strstr(r, "auto-renew") ||
            strstr(r, "membership has renewed") ||
            strstr(r, "subscription has renewed") ||
            strstr(r, "subscription has been renewed") ||
            strstr(r, "annual membership") ||
            strstr(r, "receive a full refund") ||
            strstr(r, "cancel and refund") ||
            strstr(r, "cancel and receive a refund") ||
            strstr(r, "to cancel and receive") ||
            strstr(r, "did not authorize this") ||
            strstr(r, "did not authorize this charge") ||
            strstr(r, "to cancel this charge"))         refundscam = 1;
    }

    /* Fake security alerts and direct financial-action signals are credential/
     * financial bait by nature; fold them into the bait category so they
     * participate in BEC, urgency-credential, and related pattern rules. */
    if (fake_alert || direct_fin) bait = 1;

    /* Specific amplifier patterns take priority over individual signals */
    if (clickfix)
        return "ClickFix script-injection lure (paste-and-run attack)";
    /* Device-code phishing: when auth-code language fires with authority
     * impersonation OR fake security alert, the attack class is OAuth
     * device-code abuse (M365/Azure 2026 #1 vector) rather than a generic
     * fake-alert. The unique mechanism — legitimate URL, attacker-supplied
     * code — needs its own label so the advisory can warn about it. */
    if (devicecode && (authority || fake_alert))
        return "OAuth device-code phishing "
               "(legitimate URL, attacker-supplied verification code)";
    /* MFA-fatigue / push-bombing: an unsolicited 'approve the prompt' request
     * is a distinct attack — the attacker already holds the password — with a
     * distinct remedy (deny and rotate the password), not a credential
     * re-harvest. Priority above the generic fake-alert/credential labels. */
    if (mfapush)
        return "MFA-fatigue / push-bombing (approve-the-prompt attack)";
    /* Payment/payroll-diversion BEC takes priority over the generic
     * wire-transfer and credential-harvest labels: a bank-account-change
     * request is a distinct attack with a distinct remedy (verify the change
     * out-of-band, do not update the payee), not a password reset. */
    if (bankchange)
        return "payment-diversion BEC (bank-account-change / payroll fraud)";
    if (amp_ceo || (authority && secrecy && bait))
        return "BEC / CEO-fraud wire-transfer";
    if (amp_bec || (urgency && bait && authority))
        return "business email compromise (BEC) wire-transfer fraud";
    if (amp_tss || (urgency && bait && strstr(v->reasons[0], "gift")))
        return "tech-support gift-card scam";
    /* Fake-job / task scam takes priority over the generic lottery/advance-fee
     * and investment/pig-butchering labels: a "job" that asks you to pay,
     * deposit, or buy equipment to start is a distinct fraud with a distinct
     * tell — a real job only ever pays money TO you. */
    if (jobscam)
        return "fake-job / task scam (pay-to-start employment fraud)";
    if (amp_laf || (prize && bait))
        return "lottery / advance-fee fraud";
    /* Sextortion takes priority over the generic ransom/extortion label: the
     * threat is to release intimate footage (often a bluff or AI deepfake),
     * not to withhold encrypted files — a distinct attack with a distinct
     * remedy (do not pay, do not reply, preserve and report). */
    if (sextortion)
        return "sextortion / webcam blackmail";
    if (ransom)
        return "ransom / extortion message";
    if (investment)
        return "investment scam / pig-butchering";
    if (emergency)
        return "emergency impersonation scam (grandparent / fake-kidnapping)";
    if (qr)
        return "QR-code phishing (quishing)";
    /* Refund / subscription-renewal scam takes priority over the generic
     * callback/TOAD label: the fake auto-renewal invoice and the "call to get
     * a refund" hook have a distinct remedy (a real refund needs nothing from
     * you; never grant remote access or return an "over-refund"). */
    if (refundscam)
        return "refund / subscription-renewal scam (fake auto-renewal invoice)";
    if (callback)
        return "callback phone scam (TOAD / vishing)";
    if (authority && urgency)
        return "authority impersonation phishing";
    if (urgency && bait)
        return "urgency credential-harvest phishing";
    /* Fake security alert without urgency amplifier — account suspension hook */
    if (fake_alert)
        return "fake security alert / account suspension phishing";
    if (urgency)
        return "urgency social engineering";
    if (bait)
        return "credential / payment lure";
    if (prize)
        return "prize lure / fraud bait";
    return NULL;
}

/* Stable machine-readable identifier for a text attack pattern.
 *
 * Socratic question (Perspective 78): "Every text verdict now carries a human
 * `pattern` label, but that label is prose we keep refining — when P57 changed
 * 'Verify first' to 'Verify independently' a downstream test broke. A SIEM or
 * SOAR rule that wants to route 'OAuth device-code phishing' alerts has no
 * choice but to substring-match the prose, so every wording polish risks
 * silently breaking automation. Shouldn't each pattern also expose a STABLE id
 * (e.g. HLSE-OAUTH-DEVICECODE) that survives wording changes, so machines key
 * on the id and humans read the label?"
 *
 * Maps the label from hlse_classify_text_attack() to a stable token. The ids
 * are an append-only contract: an id, once shipped, never changes meaning even
 * if the human label is reworded. Returns NULL when no pattern fired (so JSON
 * consumers can treat absence as 'no recognised pattern'). Thread-safe; no
 * allocation. */
const char *
hlse_text_pattern_id(const TextVerdict *v) {
    const char *pat = hlse_classify_text_attack(v);
    if (!pat) return NULL;
    /* Order mirrors the classifier's priority so the most specific id wins. */
    if (strstr(pat, "ClickFix"))              return "HLSE-CLICKFIX";
    if (strstr(pat, "device-code") || strstr(pat, "OAuth"))
                                              return "HLSE-OAUTH-DEVICECODE";
    if (strstr(pat, "MFA-fatigue") || strstr(pat, "push-bombing"))
                                              return "HLSE-MFA-FATIGUE";
    if (strstr(pat, "payment-diversion"))     return "HLSE-BEC-PAYMENT-DIVERSION";
    if (strstr(pat, "CEO-fraud"))             return "HLSE-BEC-CEO";
    if (strstr(pat, "business email compromise") ||
        strstr(pat, "BEC"))                   return "HLSE-BEC-WIRE";
    if (strstr(pat, "tech-support"))          return "HLSE-TECH-SUPPORT";
    if (strstr(pat, "fake-job") || strstr(pat, "task scam"))
                                              return "HLSE-JOB-SCAM";
    if (strstr(pat, "lottery") || strstr(pat, "advance-fee"))
                                              return "HLSE-ADVANCE-FEE";
    if (strstr(pat, "sextortion") || strstr(pat, "webcam blackmail"))
                                              return "HLSE-SEXTORTION";
    if (strstr(pat, "ransom") || strstr(pat, "extortion"))
                                              return "HLSE-RANSOM";
    if (strstr(pat, "investment") || strstr(pat, "pig-butchering"))
                                              return "HLSE-INVESTMENT";
    if (strstr(pat, "emergency"))             return "HLSE-EMERGENCY";
    if (strstr(pat, "quishing") || strstr(pat, "QR"))
                                              return "HLSE-QUISHING";
    if (strstr(pat, "refund") || strstr(pat, "subscription-renewal"))
                                              return "HLSE-REFUND-SCAM";
    if (strstr(pat, "callback") || strstr(pat, "TOAD") || strstr(pat, "vishing"))
                                              return "HLSE-CALLBACK-TOAD";
    if (strstr(pat, "authority impersonation"))
                                              return "HLSE-AUTHORITY";
    if (strstr(pat, "urgency credential"))    return "HLSE-URGENCY-CRED";
    if (strstr(pat, "fake security alert") || strstr(pat, "account suspension"))
                                              return "HLSE-FAKE-ALERT";
    if (strstr(pat, "urgency"))               return "HLSE-URGENCY";
    if (strstr(pat, "credential / payment"))  return "HLSE-CRED-LURE";
    if (strstr(pat, "prize"))                 return "HLSE-PRIZE";
    return "HLSE-GENERIC";
}

/*
 * Socratic question (Perspective 21): "Your score says HOW threatening, but two
 * verdicts both scoring 60 can be epistemically worlds apart: one from a single
 * homoglyph detector barely crossing threshold, another from homoglyph + path +
 * TLD + structure all agreeing. The first might be a fragile-heuristic false
 * positive; the second is corroborated by four independent detectors. A SOC
 * analyst triaging a borderline score has no way to tell which they're looking
 * at. Shouldn't the output disclose how many independent signals concur, so a
 * reviewer knows whether to trust a thin score or act on a corroborated one?"
 *
 * Counts DISTINCT detector families — not raw reasons — so that two reasons from
 * the same family (e.g. "Brand homoglyph" + "Multiple confusable chars") count
 * once. The "Legitimate '<brand>'" canonical lines are evidence the engine
 * derived, not independent detections, so they are excluded. Writes a label
 * ("single signal — corroborate before acting", "corroborated by N independent
 * signals", etc.) into `out`; returns the family count (0 when no signal fired).
 * Thread-safe; caller owns the buffer. */
int
hlse_confidence_for(const Verdict *v, char *out, size_t outsz) {
    int fam_homoglyph = 0, fam_typosquat = 0, fam_idn = 0, fam_brand = 0;
    int fam_subdomain = 0, fam_freehost = 0, fam_path = 0, fam_tld = 0;
    int fam_shortener = 0, fam_attrick = 0, fam_ip = 0, fam_dga = 0;
    int fam_structure = 0, fam_depth = 0;
    int n_families;
    int i;

    /* 160-byte minimum: longest label ("high confidence — N independent
     * detector families agree; this is a deliberate, multi-faceted spoof")
     * is ~115 bytes incl. the multi-byte em dash. */
    if (!v || !out || outsz < 160) return 0;
    out[0] = '\0';
    if (v->n_reasons == 0) return 0;

    for (i = 0; i < v->n_reasons; i++) {
        const char *r = v->reasons[i];
        if (strstr(r, "homoglyph") || strstr(r, "Homoglyph") ||
            strstr(r, "Mixed-script") || strstr(r, "confusable") ||
            strstr(r, "Confusable"))                      fam_homoglyph = 1;
        if (strstr(r, "Typosquat") || strstr(r, "typosquat")) fam_typosquat = 1;
        if (strstr(r, "IDN") || strstr(r, "Punycode"))    fam_idn       = 1;
        if (strstr(r, "Brand impersonation") ||
            strstr(r, "Brand+") || strstr(r, "Brand present") ||
            strstr(r, "Brand homoglyph"))                 fam_brand     = 1;
        if (strstr(r, "Subdomain spoofing"))              fam_subdomain = 1;
        if (strstr(r, "Free-hosting") ||
            strstr(r, "free page builder"))               fam_freehost  = 1;
        if (strstr(r, "path pattern") || strstr(r, "Phishing path"))
                                                          fam_path      = 1;
        if (strstr(r, "TLD"))                             fam_tld       = 1;
        if (strstr(r, "shortener") || strstr(r, "Shortened"))
                                                          fam_shortener = 1;
        if (strstr(r, "credential trick") ||
            strstr(r, "@ in authority"))                  fam_attrick   = 1;
        if (strstr(r, "IP-based URL") || strstr(r, "IP-address host"))
                                                          fam_ip        = 1;
        if (strstr(r, "DGA") || strstr(r, "high-entropy") ||
            strstr(r, "random-looking"))                  fam_dga       = 1;
        if (strstr(r, "Phishing-typical domain structure")) fam_structure = 1;
        if (strstr(r, "Deep subdomain nesting"))          fam_depth     = 1;
    }

    /* Homoglyph and typosquat are the same underlying family (lookalike SLD);
     * collapse so we don't double-count a single visual-spoofing technique. */
    if (fam_homoglyph && fam_typosquat) fam_typosquat = 0;
    /* Brand-homoglyph sets both fam_homoglyph and fam_brand; the homoglyph is
     * the detection, the brand match is its consequence — collapse to one when
     * homoglyph is the only brand signal (no independent hyphenation/subdomain). */
    if (fam_homoglyph && fam_brand &&
        !fam_subdomain && !fam_freehost && !fam_structure) fam_brand = 0;

    n_families = fam_homoglyph + fam_typosquat + fam_idn + fam_brand +
                 fam_subdomain + fam_freehost + fam_path + fam_tld +
                 fam_shortener + fam_attrick + fam_ip + fam_dga +
                 fam_structure + fam_depth;

    if (n_families <= 0) return 0;
    if (n_families == 1) {
        snprintf(out, outsz,
                 "single signal \xe2\x80\x94 one detector fired; corroborate "
                 "independently before acting on a borderline score");
        return 1;
    }
    if (n_families == 2) {
        snprintf(out, outsz,
                 "corroborated by %d independent signals \xe2\x80\x94 unlikely "
                 "to be a single-heuristic false positive", n_families);
        return n_families;
    }
    snprintf(out, outsz,
             "high confidence \xe2\x80\x94 %d independent detector families "
             "agree; this is a deliberate, multi-faceted spoof", n_families);
    return n_families;
}

/* Count how many INDEPENDENT signal categories corroborate a text verdict.
 *
 * Socratic question (Perspective 28): "hlse_confidence_for gives URL verdicts
 * an ⚖ Confidence label. Text verdicts have the same epistemic spectrum: a
 * BEC with urgency + financial + authority + secrecy all firing concurrently
 * is as corroborated as a URL with four independent detectors agreeing. A
 * single-urgency LOG text is as fragile as a single-heuristic URL LOG. Without
 * a confidence line, text verdicts look uniformly certain. Why should URL get
 * epistemic disclosure and text be silent?"
 *
 * Counts base signal families (urgency, financial, authority, secrecy, etc.)
 * separately from amplifier reason strings — amplifiers are derived, not
 * independent. Applies the same qualitative labels as hlse_confidence_for:
 * 1 → "single signal", 2 → "corroborated by N independent signals",
 * 3+ → "high confidence — N independent signal categories agree".
 * Caller supplies `out` buffer (160+ bytes); returns the family count.
 * Thread-safe; no allocation.                                              */
int
hlse_text_confidence(const TextVerdict *v, char *out, size_t outsz) {
    int i;
    int sig_urgency = 0, sig_financial = 0, sig_prize = 0, sig_ransom = 0;
    int sig_authority = 0, sig_secrecy = 0, sig_investment = 0;
    int sig_qr = 0, sig_callback = 0, sig_emergency = 0, sig_clickfix = 0;
    int sig_fake_alert = 0, sig_direct_fin = 0;
    int n_sigs;

    if (!v || !out || outsz < 160) return 0;
    out[0] = '\0';
    if (v->n_reasons == 0) return 0;

    for (i = 0; i < v->n_reasons; i++) {
        const char *r = v->reasons[i];
        /* Skip amplifier lines — they are derived, not independent */
        if (strncmp(r, "Amplifier:", 10) == 0) continue;
        if (strstr(r, "Urgency pressure"))           sig_urgency    = 1;
        if (strstr(r, "Financial/credential"))        sig_financial  = 1;
        if (strstr(r, "Prize/reward"))                sig_prize      = 1;
        if (strstr(r, "Ransom") || strstr(r, "ransom")) sig_ransom   = 1;
        if (strstr(r, "Authority impersonation"))     sig_authority  = 1;
        if (strstr(r, "Secrecy/grooming"))            sig_secrecy    = 1;
        if (strstr(r, "Investment scam"))             sig_investment = 1;
        if (strstr(r, "QR code phishing"))            sig_qr         = 1;
        if (strstr(r, "Callback") || strstr(r, "TOAD") ||
            strstr(r, "smishing"))                    sig_callback   = 1;
        if (strstr(r, "Emergency") || strstr(r, "grandparent")) sig_emergency = 1;
        if (strstr(r, "ClickFix") || strstr(r, "Shell-pipe")) sig_clickfix  = 1;
        if (strstr(r, "Fake security alert"))         sig_fake_alert = 1;
        if (strstr(r, "Direct financial action"))     sig_direct_fin = 1;
    }

    n_sigs = sig_urgency + sig_financial + sig_prize + sig_ransom +
             sig_authority + sig_secrecy + sig_investment + sig_qr +
             sig_callback + sig_emergency + sig_clickfix +
             sig_fake_alert + sig_direct_fin;

    if (n_sigs <= 0) return 0;
    if (n_sigs == 1) {
        snprintf(out, outsz,
                 "single signal \xe2\x80\x94 one category fired; corroborate "
                 "independently before acting on a borderline score");
        return 1;
    }
    if (n_sigs == 2) {
        snprintf(out, outsz,
                 "corroborated by %d independent signals \xe2\x80\x94 unlikely "
                 "to be a single-heuristic false positive", n_sigs);
        return n_sigs;
    }
    snprintf(out, outsz,
             "high confidence \xe2\x80\x94 %d independent signal categories "
             "agree; this is a multi-tactic social engineering attempt", n_sigs);
    return n_sigs;
}

/* Extract the safe destination a user actually wanted, from a URL verdict.
 *
 * Socratic question: "You blocked the counterfeit — but the user still has
 * the legitimate need that made them click. Saying only 'no' leaves them to
 * re-search straight back into the same phishing net. You already know the
 * real domain (you used it to detect the fake). Shouldn't you hand it over?"
 *
 * Perspective 8 derives the canonical brand domain and records it as the
 * evidence reason "Legitimate '<brand>': <domain>". This lifts that buried
 * fact into an actionable, navigable destination so detection completes the
 * loop into guidance. Writes "https://<domain>" into `out`; returns 1 when a
 * canonical brand domain is present in the verdict, 0 otherwise. Thread-safe
 * (caller owns the buffer); no allocation. */
int
hlse_safe_destination(const Verdict *v, char *out, size_t outsz) {
    int i;
    /* Need room for at least "https://" + one host char + NUL. */
    if (!v || !out || outsz < 10) return 0;
    for (i = 0; i < v->n_reasons; i++) {
        const char *r     = v->reasons[i];
        const char *brand = strstr(r, "Legitimate '");
        const char *colon;
        if (!brand) continue;
        colon = strstr(brand, "': ");
        if (!colon) continue;
        /* colon+3 points at the canonical domain, which runs to end-of-reason
         * (the reason is built as "Legitimate '<brand>': <domain>"). */
        snprintf(out, outsz, "https://%s", colon + 3);
        return 1;
    }
    return 0;
}

/* Compound safe destination — the logical counterpart to hlse_compound_objective:
 * for multi-brand co-spoof URLs, a single canonical URL leaves the second
 * brand's legitimate site unnamed while the ◉ and ⊕ lines name both.
 *
 * Socratic question (Perspective 22): "hlse_compound_objective already says
 * 'compound theft — paypal (financial) AND apple (identity) both targeted
 * simultaneously'. hlse_cascade_risk says 'two credential classes targeted at
 * once — audit BOTH'. But → Safe destination: https://paypal.com names only
 * PayPal. The user who just escaped a PayPal+Apple co-spoof phishing page reads
 * 'go to paypal.com' and has no navigable address for their Apple account.
 * The compound framing is now logically inconsistent — should both legitimate
 * destinations appear on that line?"
 *
 * For n_brands == 1 writes "https://<domain>" exactly as hlse_safe_destination().
 * For n_brands >= 2 writes "https://<domain1> and https://<domain2>".
 * Caller supplies `out` buffer (256+ bytes recommended for compound case);
 * returns 1 when any canonical domain was found, 0 otherwise. Thread-safe. */
int
hlse_safe_destinations(const Verdict *v, char *out, size_t outsz) {
    int i;
    char url1[128] = "";
    char url2[128] = "";
    int n_found = 0;

    /* Minimum for "https://<longest domain>" (8 + 64 + NUL = 73) */
    if (!v || !out || outsz < 10) return 0;
    out[0] = '\0';

    for (i = 0; i < v->n_reasons && n_found < 2; i++) {
        const char *r     = v->reasons[i];
        const char *brand = strstr(r, "Legitimate '");
        const char *colon;
        if (!brand) continue;
        colon = strstr(brand, "': ");
        if (!colon) continue;
        /* colon+3 is the canonical domain (to end of reason string) */
        if (n_found == 0)
            snprintf(url1, sizeof(url1), "https://%s", colon + 3);
        else
            snprintf(url2, sizeof(url2), "https://%s", colon + 3);
        n_found++;
    }

    if (n_found == 0) return 0;
    if (n_found == 1 || url2[0] == '\0') {
        snprintf(out, outsz, "%s", url1);
        return 1;
    }
    /* n_found >= 2: name both destinations */
    snprintf(out, outsz, "%s and %s", url1, url2);
    return 1;
}

/* True if `brand` is one of the NULL-terminated names in `set`. */
static int
brand_in_set(const char *brand, const char *const *set) {
    int i;
    for (i = 0; set[i]; i++)
        if (strcmp(brand, set[i]) == 0) return 1;
    return 0;
}

/* Map an impersonated brand to the attacker's likely objective and the asset
 * the victim must now treat as compromised. A known brand that matches no
 * category still returns the generic credential-harvest objective, so any
 * identified brand yields guidance. */
static const char *
brand_objective(const char *brand) {
    static const char *const crypto[] = {
        "coinbase","binance","kraken","coincheck","crypto","metamask","ledger",
        "trezor","trustwallet","opensea","uniswap","pancakeswap","blockchain", NULL };
    static const char *const payment[] = {
        "paypal","paypay","venmo","zelle","cashapp","payoneer","stripe","wise",
        "revolut","chase","wellsfargo","bankofamerica","citibank","barclays",
        "hsbc","usbank","capitalone","mufg","smbc","mizuho","truist","robinhood",
        "etrade","fidelity","schwab","intuit","turbotax","quickbooks", NULL };
    static const char *const identity[] = {
        "google","microsoft","apple","outlook","yahoo","office365",
        "microsoft365","microsoftonline", NULL };
    static const char *const work[] = {
        "okta","microsoftteams","teams","salesforce","docusign","slack","zoom", NULL };
    static const char *const vault[] = {
        "1password","lastpass","bitwarden", NULL };
    static const char *const social[] = {
        "facebook","meta","instagram","twitter","tiktok","snapchat","telegram",
        "whatsapp","reddit","discord","line","linkedin","youtube", NULL };
    static const char *const shopping[] = {
        "netflix","hulu","spotify","disney","hbo","twitch","peacock","amazon",
        "ebay","walmart","bestbuy","homedepot","shopify","rakuten", NULL };
    static const char *const gaming[] = {
        "steam","epicgames","roblox", NULL };
    static const char *const logistics[] = {
        "fedex","dhl","dhlexpress","ups","usps", NULL };
    static const char *const avsoft[] = {
        "norton","mcafee","kaspersky","bitdefender","avast","malwarebytes", NULL };
    static const char *const ai[] = {
        "openai","anthropic","chatgpt","gemini", NULL };
    static const char *const telecom[] = {
        "verizon","tmobile","docomo","softbank", NULL };

    if (brand_in_set(brand, crypto))
        return "crypto theft \xe2\x80\x94 seed phrase or wallet drain; transfers are irreversible";
    if (brand_in_set(brand, payment))
        return "financial-account takeover \xe2\x80\x94 your funds and linked bank accounts";
    if (brand_in_set(brand, vault))
        return "password-vault compromise \xe2\x80\x94 the master key to every stored credential";
    if (brand_in_set(brand, identity))
        return "email/identity takeover \xe2\x80\x94 the keystone that can reset every other account";
    if (brand_in_set(brand, work))
        return "corporate credential theft \xe2\x80\x94 lateral movement into your employer's systems";
    if (brand_in_set(brand, social))
        return "social-account hijack \xe2\x80\x94 impersonation and contact-list scams";
    if (brand_in_set(brand, shopping))
        return "subscription/payment-card theft \xe2\x80\x94 stored payment methods on file";
    if (brand_in_set(brand, gaming))
        return "gaming-account theft \xe2\x80\x94 resale of the account and in-game items";
    if (brand_in_set(brand, logistics))
        return "delivery-fee scam \xe2\x80\x94 a small fraudulent payment and card capture";
    if (brand_in_set(brand, avsoft))
        return "fake-AV / tech-support scam \xe2\x80\x94 remote access and bogus 'support' fees";
    if (brand_in_set(brand, ai))
        return "AI-account / API-key theft \xe2\x80\x94 billed usage and access to your data";
    if (brand_in_set(brand, telecom))
        return "telecom-account takeover \xe2\x80\x94 SIM-swap to intercept your 2FA codes";
    return "credential harvesting \xe2\x80\x94 account takeover";
}

/* One-word credential class label, used to build compound-objective summaries.
 * Derived from the same category sets as brand_objective(). */
static const char *
brand_objective_class(const char *brand) {
    const char *obj = brand_objective(brand);
    if (!obj) return "account";
    if (strstr(obj, "financial") || strstr(obj, "banking") || strstr(obj, "funds"))
        return "financial";
    if (strstr(obj, "crypto") || strstr(obj, "seed phrase") || strstr(obj, "wallet"))
        return "crypto";
    if (strstr(obj, "password-vault"))
        return "vault";
    if (strstr(obj, "identity") || strstr(obj, "keystone"))
        return "identity";
    if (strstr(obj, "corporate") || strstr(obj, "employer") || strstr(obj, "enterprise"))
        return "corporate";
    if (strstr(obj, "social") || strstr(obj, "contact-list"))
        return "social";
    if (strstr(obj, "gaming"))
        return "gaming";
    if (strstr(obj, "subscription") || strstr(obj, "streaming") ||
        strstr(obj, "stored payment"))
        return "subscription";
    if (strstr(obj, "SIM-swap") || strstr(obj, "telecom"))
        return "telecom";
    if (strstr(obj, "AI") || strstr(obj, "API-key"))
        return "AI/API";
    if (strstr(obj, "delivery-fee"))
        return "payment";
    if (strstr(obj, "shopping") || strstr(obj, "logistics"))
        return "shopping";
    return "account";
}

/* Name the attacker's likely objective for a URL verdict.
 *
 * Socratic question: "You named HOW the attack works and WHERE the user should
 * go instead — but never WHAT the attacker is after. 'A phishing page' is
 * abstract and easy to shrug off; 'they want your crypto seed phrase, and that
 * theft is irreversible' names the exact asset to treat as compromised right
 * now. Doesn't the stake decide how hard the user should care?"
 *
 * The attack-pattern lens (hlse_classify_url_attack) describes the mechanism;
 * this describes the *motive and the asset at risk*, derived from which brand
 * was impersonated. Returns a static string, or NULL when no brand was
 * identified in the verdict (no brand → no specific objective to name). */
const char *
hlse_attacker_objective(const Verdict *v) {
    int i;
    if (!v) return NULL;
    for (i = 0; i < v->n_reasons; i++) {
        const char *r     = v->reasons[i];
        const char *start = strstr(r, "Legitimate '");
        const char *end;
        char brand[64];
        size_t len;
        if (!start) continue;
        start += 12;                 /* skip past "Legitimate '" */
        end = strchr(start, '\'');
        if (!end) continue;
        len = (size_t)(end - start);
        if (len == 0 || len >= sizeof(brand)) continue;
        memcpy(brand, start, len);
        brand[len] = '\0';
        return brand_objective(brand);
    }
    return NULL;
}

/* Compound objective for multi-brand co-spoof URLs.
 *
 * Socratic question (Perspective 19): "hlse_attacker_objective() names the
 * primary target precisely — but for multi-brand co-spoof URLs (Perspective 17)
 * it returns only the FIRST brand's objective. A user phished for PayPal AND
 * Apple ID simultaneously faces two compromised credential classes, not one.
 * The ◉ Attacker's goal line says 'financial-account takeover', leaving Apple
 * ID's identity-credential risk completely unnamed. The second objective isn't
 * redundant noise — it determines what the user must protect next. Shouldn't
 * the output name BOTH?"
 *
 * For n_brands == 1 writes the same result as hlse_attacker_objective().
 * For n_brands >= 2 writes a compound summary: "compound theft — paypal
 * (financial) AND apple (identity) both targeted simultaneously". Caller
 * supplies the buffer; no allocation. Returns 1 when any brand was found,
 * 0 when no "Legitimate '...'" reason exists in the verdict. Thread-safe. */
int
hlse_compound_objective(const Verdict *v, char *out, size_t outsz) {
    int i;
    char brand1[64] = "";
    char brand2[64] = "";
    const char *obj1   = NULL;
    const char *class1 = NULL, *class2 = NULL;
    int n_found = 0;

    /* 256 bytes minimum: worst-case compound format is ~228 bytes
     * (19-byte prefix + 63-byte brand1 + 12-byte class + separators
     * + 63-byte brand2 + 12-byte class + 48-byte suffix + NUL). */
    if (!v || !out || outsz < 256) return 0;
    out[0] = '\0';

    for (i = 0; i < v->n_reasons && n_found < 2; i++) {
        const char *r     = v->reasons[i];
        const char *start = strstr(r, "Legitimate '");
        const char *end;
        char brand[64];
        size_t len;
        if (!start) continue;
        start += 12;
        end = strchr(start, '\'');
        if (!end) continue;
        len = (size_t)(end - start);
        if (len == 0 || len >= sizeof(brand)) continue;
        memcpy(brand, start, len);
        brand[len] = '\0';
        if (n_found == 0) {
            memcpy(brand1, brand, len + 1);
            obj1   = brand_objective(brand1);
            class1 = brand_objective_class(brand1);
        } else {
            memcpy(brand2, brand, len + 1);
            class2 = brand_objective_class(brand2);
        }
        n_found++;
    }

    if (n_found == 0) return 0;
    if (n_found == 1) {
        /* Single brand: write the full descriptive objective */
        snprintf(out, outsz, "%s",
                 (obj1 && obj1[0]) ? obj1 : "credential harvesting");
        return 1;
    }
    /* Multi-brand: name both credential classes explicitly */
    snprintf(out, outsz,
             "compound theft \xe2\x80\x94 %s (%s) AND %s (%s) both targeted "
             "simultaneously in a single click",
             brand1, class1 ? class1 : "account",
             brand2, class2 ? class2 : "account");
    return 1;
}

/* Characterise an ASCII character for the diff label. */
static const char *
ascii_char_type(char c) {
    if (c >= '0' && c <= '9') return "digit";
    if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')) return "letter";
    if (c == '-') return "hyphen";
    if (c == '_') return "underscore";
    return "char";
}

/* Pinpoint the ASCII lookalike substitution(s) in a typosquat or ASCII
 * homoglyph verdict — the character-level proof that complements
 * hlse_confusable_report() (which only fires for non-ASCII codepoints).
 *
 * Socratic question (Perspective 20): "You report 'paypa1' vs 'paypal' as a
 * homoglyph. But in a proportional-font browser address bar, digit '1' and
 * lowercase 'l' are visually indistinguishable — the user has to mentally
 * align two strings to spot the difference. Your own verify guidance says
 * 'compare the address bar character by character' without saying WHICH
 * character. What if you pointed to position 6: 'digit 1 masking letter l'?
 * That transforms 'edit distance 1' from an abstract metric into proof the
 * user can physically verify in their address bar right now."
 *
 * Parses "Brand homoglyph: 'X' -> 'Y' (brand)" and
 * "Typosquat: 'X' is edit distance N from 'Y'" reason strings to extract the
 * fake string X and genuine string Y, then reports every differing position
 * with its character type (digit/letter/hyphen). Deliberately skips reasons
 * where X contains non-ASCII bytes — those are already covered by
 * hlse_confusable_report() with richer Unicode context.
 *
 * Writes a one-line summary into `out` (caller-owned); returns 1 when an
 * ASCII-level difference was found, 0 otherwise. Thread-safe; no allocation. */
int
hlse_ascii_diff(const Verdict *v, char *out, size_t outsz) {
    int ri;
    /* 192-byte minimum: worst-case format is "'<63-char-host>': chars N,N are
     * <type> '<c>' masking '<c>'" ≈ 2+63+30+30+30 = ~155 bytes + NUL */
    if (!v || !out || outsz < 192) return 0;
    out[0] = '\0';

    for (ri = 0; ri < v->n_reasons; ri++) {
        const char *r = v->reasons[ri];
        const char *fake_s = NULL, *fake_e = NULL;
        const char *real_s = NULL, *real_e = NULL;
        char fake[64], real_str[64];
        size_t fl, rl;
        int k;

        /* "Brand homoglyph: 'X' -> 'Y' (brand)" */
        if (strncmp(r, "Brand homoglyph:", 16) == 0 &&
            strstr(r, " -> '")) {
            fake_s = strchr(r, '\'');
            if (!fake_s) continue;
            fake_s++;
            fake_e = strchr(fake_s, '\'');
            if (!fake_e) continue;
            real_s = strstr(fake_e, "-> '");
            if (!real_s) continue;
            real_s += 4;
            real_e = strchr(real_s, '\'');
            if (!real_e) continue;
        }
        /* "Typosquat: 'X' is edit distance N from 'Y'"
         * "Possible typosquat: 'X' is edit distance N from 'Y'" */
        else if ((strncmp(r, "Typosquat:", 10) == 0 ||
                  strncmp(r, "Possible typosquat:", 19) == 0) &&
                 strstr(r, "from '")) {
            fake_s = strchr(r, '\'');
            if (!fake_s) continue;
            fake_s++;
            fake_e = strchr(fake_s, '\'');
            if (!fake_e) continue;
            real_s = strstr(fake_e, "from '");
            if (!real_s) continue;
            real_s += 6;
            real_e = strchr(real_s, '\'');
            if (!real_e) continue;
        } else {
            continue;
        }

        fl = (size_t)(fake_e - fake_s);
        rl = (size_t)(real_e - real_s);
        if (fl == 0 || fl >= sizeof(fake)) continue;
        if (rl == 0 || rl >= sizeof(real_str)) continue;
        memcpy(fake,     fake_s, fl); fake[fl]    = '\0';
        memcpy(real_str, real_s, rl); real_str[rl] = '\0';

        /* Skip if fake contains non-ASCII — hlse_confusable_report() covers it */
        {
            int has_non_ascii = 0;
            for (k = 0; k < (int)fl; k++)
                if ((unsigned char)fake[k] > 127) { has_non_ascii = 1; break; }
            if (has_non_ascii) continue;
        }

        /* Find all differing positions (substitution case: fl == rl) */
        if (fl == rl) {
            int diff_positions[8];
            int n_diffs = 0;
            for (k = 0; k < (int)fl && n_diffs < 8; k++) {
                if (fake[k] != real_str[k]) diff_positions[n_diffs++] = k;
            }
            if (n_diffs == 0) continue;
            if (n_diffs == 1) {
                int p = diff_positions[0];
                snprintf(out, outsz,
                         "'%s': char %d is %s '%c', masking %s '%c'",
                         fake, p + 1,
                         ascii_char_type(fake[p]), fake[p],
                         ascii_char_type(real_str[p]), real_str[p]);
            } else {
                /* Multiple substitutions: report first two, note count */
                int p0 = diff_positions[0];
                int p1 = diff_positions[1];
                snprintf(out, outsz,
                         "'%s': char %d %s '%c'→'%c', char %d %s '%c'→'%c'%s",
                         fake,
                         p0 + 1, ascii_char_type(fake[p0]), fake[p0], real_str[p0],
                         p1 + 1, ascii_char_type(fake[p1]), fake[p1], real_str[p1],
                         n_diffs > 2 ? " (more)" : "");
            }
            return 1;
        }

        /* Insertion: fake has one extra character */
        if (fl == rl + 1) {
            int j = 0;
            for (k = 0; k < (int)fl; k++) {
                if (j >= (int)rl || fake[k] != real_str[j]) {
                    snprintf(out, outsz,
                             "'%s': extra %s '%c' at char %d",
                             fake, ascii_char_type(fake[k]), fake[k], k + 1);
                    return 1;
                }
                j++;
            }
            continue;
        }

        /* Deletion: real has one extra character */
        if (rl == fl + 1) {
            int j = 0;
            for (k = 0; k < (int)rl; k++) {
                if (j >= (int)fl || real_str[k] != fake[j]) {
                    snprintf(out, outsz,
                             "'%s': missing %s '%c' at char %d",
                             fake, ascii_char_type(real_str[k]), real_str[k], k + 1);
                    return 1;
                }
                j++;
            }
            continue;
        }
    }
    return 0;
}

/* Name the Unicode script block a confusable codepoint belongs to, for the
 * human-readable forensic report. */
static const char *
confusable_script(unsigned long cp) {
    if (cp >= 0x0400 && cp <= 0x04FF) return "Cyrillic";
    if (cp >= 0x0500 && cp <= 0x052F) return "Cyrillic-supplement";
    if (cp >= 0x0370 && cp <= 0x03FF) return "Greek";
    if (cp >= 0x0530 && cp <= 0x058F) return "Armenian";
    if (cp >= 0x2000 && cp <= 0x206F) return "Unicode-punctuation";
    if (cp >= 0xFF00 && cp <= 0xFFEF) return "fullwidth/halfwidth";
    return "non-Latin";
}

/* Pinpoint the first disguised (non-ASCII) character in a URL's host, with its
 * 1-based position, Unicode codepoint, and script — the forensic proof behind
 * a "homoglyph" label.
 *
 * Socratic question: "You said 'mixed-script homoglyph' and then showed the
 * user the very string their eyes already glossed over — 'раypal.com' looks
 * identical to 'paypal.com'. Which exact character is the impostor? Naming it
 * ('position 1 is Cyrillic U+0440, not an ASCII letter') turns an abstract
 * label into undeniable, teachable proof a browser's address bar hides."
 *
 * Only non-ASCII (raw IDN / mixed-script) hosts produce a report — pure-ASCII
 * homoglyphs (0/1/l) are already spelled out in the brand-homoglyph reason, and
 * xn-- punycode hosts are ASCII and covered by the IDN reason. Operates on the
 * host (between "://" and the first "/?#"). Writes a one-line summary into out;
 * returns 1 when a disguised character is found, 0 otherwise. Thread-safe; no
 * allocation. */
int
hlse_confusable_report(const char *url, char *out, size_t outsz) {
    const char *h, *p, *host_end;
    int cp_pos = 0;
    if (!url || !out || outsz == 0) return 0;
    h = strstr(url, "://");
    h = h ? h + 3 : url;
    host_end = h;
    while (*host_end && *host_end != '/' && *host_end != '?' && *host_end != '#')
        host_end++;
    for (p = h; p < host_end; ) {
        unsigned char c = (unsigned char)*p;
        unsigned long cp;
        int n, k, ok = 1;
        if      (c < 0x80)          { n = 1; cp = c; }
        else if ((c & 0xE0) == 0xC0){ n = 2; cp = (unsigned long)(c & 0x1F); }
        else if ((c & 0xF0) == 0xE0){ n = 3; cp = (unsigned long)(c & 0x0F); }
        else if ((c & 0xF8) == 0xF0){ n = 4; cp = (unsigned long)(c & 0x07); }
        else                        { n = 1; cp = c; }
        for (k = 1; k < n; k++) {
            if (p + k >= host_end || ((unsigned char)p[k] & 0xC0) != 0x80) {
                ok = 0;
                break;
            }
            cp = (cp << 6) | (unsigned long)((unsigned char)p[k] & 0x3F);
        }
        cp_pos++;
        if (ok && cp >= 0x80) {
            /* Format into a bounded local buffer first: in the library build
             * GCC cannot see callers to bound `outsz`, so a direct snprintf of
             * the literal trips -Wformat-truncation=2. Stage into a fixed-size
             * buffer (provable bound), then copy with an explicit clamp to
             * outsz — memcpy is outside the format-truncation analysis. */
            char tmp[96];
            size_t L;
            snprintf(tmp, sizeof(tmp),
                     "position %d is %s U+%04lX, not an ASCII letter",
                     cp_pos, confusable_script(cp), cp);
            if (outsz > 0) {
                L = strlen(tmp);
                if (L >= outsz) L = outsz - 1;
                memcpy(out, tmp, L);
                out[L] = '\0';
            }
            return 1;
        }
        p += ok ? n : 1;
    }
    return 0;
}

/* The single best independent check a user can run to confirm an actionable
 * URL verdict — without trusting HLSE.
 *
 * Socratic question (Perspective 95): "You're a heuristic engine with no
 * network, no certificate inspection, no ground truth. A user about to type
 * their password is betting on your word alone. What ONE check can they run
 * right now — one that doesn't require trusting you — to confirm the verdict
 * before they act? And why does ALERT [40-59] leave verify/triage/cascade_risk
 * NULL while BLOCK [60+] fills them in — is the user at 40-59 not ALSO about
 * to make a decision that benefits from an independent check?"
 *
 * This used to gate at score >= 60 only, leaving the ALERT band a
 * pattern+objective with no actionable next step. But ALERT is precisely the
 * band where the verdict is least certain and an independent check is most
 * valuable — a BLOCK verdict is confident enough that "verify" is a courtesy,
 * while an ALERT verdict genuinely needs it to resolve the ambiguity. Gates
 * at score >= 40 (ALERT+) so it now co-occurs with hlse_exoneration_for's
 * 15..59 band in the 40..59 overlap: exoneration gives the benign read,
 * verify gives the independent test — together they let the user decide
 * rather than just watching a score. The check is chosen from the signals
 * that fired so it targets the actual deception. Returns a static string, or
 * NULL when score < 40. */
const char *
hlse_verification_for(const Verdict *v) {
    int i;
    int shortener = 0, at_trick = 0, ip = 0, homoglyph = 0, idn = 0;
    int subdomain = 0, free_host = 0, typo = 0, brand = 0;

    if (!v || v->score < 40) return NULL;

    for (i = 0; i < v->n_reasons; i++) {
        const char *r = v->reasons[i];
        if (strstr(r, "shortener") || strstr(r, "Shortened"))       shortener = 1;
        if (strstr(r, "credential trick") || strstr(r, "@ in authority")) at_trick = 1;
        if (strstr(r, "IP-based URL") || strstr(r, "IP-address host")) ip = 1;
        if (strstr(r, "homoglyph") || strstr(r, "Homoglyph") ||
            strstr(r, "Mixed-script"))                              homoglyph = 1;
        if (strstr(r, "IDN") || strstr(r, "Punycode"))              idn = 1;
        if (strstr(r, "Subdomain spoofing") || strstr(r, "subdomain")) subdomain = 1;
        if (strstr(r, "Free-hosting") || strstr(r, "free page builder")) free_host = 1;
        if (strstr(r, "Typosquat") || strstr(r, "typosquat"))       typo = 1;
        if (strstr(r, "Brand") || strstr(r, "brand") ||
            strstr(r, "Legitimate '"))                              brand = 1;
    }

    if (shortener)
        return "expand the short link before opening it (many shorteners show a "
               "preview if you append '+' to the URL) \xe2\x80\x94 never click one blind";
    if (at_trick)
        return "read the authority right before the first '/': everything after "
               "an '@' is where you actually land, not the brand shown before it";
    if (ip)
        return "legitimate brands do not serve login pages from a bare IP "
               "address \xe2\x80\x94 that alone marks it fake";
    if (idn || homoglyph)
        return "don't read the link \xe2\x80\x94 reach the brand from your own "
               "bookmark or a search engine and compare the address bar "
               "character by character";
    if (subdomain || free_host)
        return "read the domain right-to-left: the registrable name just before "
               "the first single '/' is the real owner, not the brand spelled "
               "earlier in the host";
    if (typo || brand)
        return "ignore the link text; open the brand via a saved bookmark or by "
               "typing its name into a search engine, then compare the domain";
    return "confirm through a channel you already trust (the official app, or a "
           "number printed on your card/statement) \xe2\x80\x94 never one supplied "
           "by this message";
}

/* First-response triage for the post-click user — what to do in the next
 * 60 seconds to minimise damage.
 *
 * Socratic question: "The verdict assumes the user saw HLSE's output BEFORE
 * clicking. But people typically notice something's wrong AFTER submitting
 * credentials. At that moment 'BLOCK' and a list of structural reasons is
 * useless — they need triage: what to do right now. Does HLSE serve the
 * post-click user at all?"
 *
 * This is the temporal complement: verify (before) → triage (after). Derived
 * from the same brand-objective class as hlse_attacker_objective so the
 * action directly matches the asset at risk. Only fires at score >= 60 where
 * the verdict is confident enough to warrant incident-response guidance.
 * Returns a static string, or NULL when score < 60.                         */
const char *
hlse_triage_for(const Verdict *v) {
    const char *obj;
    if (!v || v->score < 60) return NULL;
    obj = hlse_attacker_objective(v);
    if (!obj)
        return "revoke all active sessions NOW (Security settings \xe2\x86\x92 "
               "'sign out everywhere'), THEN change the password \xe2\x80\x94 "
               "modern phishing proxies your real login and steals the session "
               "cookie, so 2FA does not stop it and a password change alone "
               "leaves the attacker's stolen session live; check login history "
               "for sessions you do not recognise";
    if (strstr(obj, "crypto") || strstr(obj, "seed phrase") || strstr(obj, "wallet"))
        return "if you entered a seed phrase or private key, move remaining assets "
               "to a new wallet immediately \xe2\x80\x94 crypto transfers cannot be "
               "reversed or frozen; if instead you APPROVED a transaction or "
               "connected your wallet to the site, revoke the token approval NOW "
               "at revoke.cash or your chain's explorer (Token Approvals) \xe2\x80\x94 "
               "a wallet drainer steals through a live approval, not your seed, "
               "and keeps draining until the approval is revoked";
    if (strstr(obj, "password-vault"))
        return "change your master password now and rotate every credential stored "
               "in the vault \xe2\x80\x94 a compromised vault is a skeleton key to "
               "every account you manage";
    if (strstr(obj, "financial") || strstr(obj, "funds"))
        return "call the number on the back of your card or the banking app "
               "immediately to block it and dispute any pending transactions";
    if (strstr(obj, "identity") || strstr(obj, "keystone"))
        return "change your email password, revoke all active sessions (usually "
               "in Security settings), and audit account-recovery options now "
               "\xe2\x80\x94 this account can reset every other";
    if (strstr(obj, "corporate") || strstr(obj, "employer"))
        return "notify your IT/security team immediately \xe2\x80\x94 enterprise "
               "SSO compromise enables lateral movement into your organisation's "
               "systems and must be contained within minutes";
    if (strstr(obj, "social") || strstr(obj, "contact-list"))
        return "revoke active sessions, change your password, and warn your "
               "contacts right now \xe2\x80\x94 attackers use hijacked accounts to "
               "target your network next";
    if (strstr(obj, "SIM-swap") || strstr(obj, "telecom"))
        return "call your carrier immediately to add a SIM-lock PIN \xe2\x80\x94 "
               "a SIM-swap defeats every SMS-based 2FA code across all accounts";
    if (strstr(obj, "API-key") || strstr(obj, "AI"))
        return "revoke the affected API key in the provider console now "
               "\xe2\x80\x94 a live key incurs billed usage every second until "
               "revoked and may expose your data";
    if (strstr(obj, "gaming"))
        return "change your account password and enable 2FA now \xe2\x80\x94 "
               "gaming accounts are listed for sale within minutes of compromise";
    if (strstr(obj, "subscription") || strstr(obj, "stored payment"))
        return "remove saved payment methods from the account and change your "
               "password; check for unauthorised subscription charges";
    if (strstr(obj, "delivery-fee"))
        return "if you entered card details on the fake delivery page, call the "
               "number on the back of the card immediately to block it";
    return "revoke all active sessions NOW (Security settings \xe2\x86\x92 "
           "'sign out everywhere'), THEN change the password \xe2\x80\x94 "
           "modern phishing proxies your real login and steals the session "
           "cookie, so 2FA does not stop it and a password change alone "
           "leaves the attacker's stolen session live; check login history "
           "for sessions you do not recognise";
}

/* Map an objective-class label to its concise triage imperative for use
 * in compound (multi-brand) triage sentences.
 * Returns a short phrase (<= 140 chars) or the generic fallback. */
static const char *
triage_imperative(const char *cls) {
    if (!cls) return "change the password and check recent login activity";
    if (strcmp(cls, "financial") == 0)
        return "call the number on the back of your card to freeze it and dispute "
               "pending transactions";
    if (strcmp(cls, "crypto") == 0)
        return "move remaining assets to a new wallet immediately \xe2\x80\x94 "
               "crypto transfers are irreversible";
    if (strcmp(cls, "vault") == 0)
        return "change your master password and rotate every stored credential "
               "now \xe2\x80\x94 a compromised vault is a skeleton key to every account";
    if (strcmp(cls, "identity") == 0)
        return "change that email/identity password, revoke all sessions, and "
               "audit recovery options \xe2\x80\x94 it can reset every other account";
    if (strcmp(cls, "corporate") == 0)
        return "notify your IT/security team immediately \xe2\x80\x94 enterprise "
               "SSO compromise enables lateral movement within minutes";
    if (strcmp(cls, "social") == 0)
        return "revoke active sessions, change your password, and warn your "
               "contacts \xe2\x80\x94 attackers target your network next";
    if (strcmp(cls, "telecom") == 0)
        return "call your carrier to add a SIM-lock PIN \xe2\x80\x94 a SIM-swap "
               "defeats every SMS-based 2FA code";
    if (strcmp(cls, "AI/API") == 0)
        return "revoke the affected API key in the provider console now";
    if (strcmp(cls, "gaming") == 0)
        return "change your account password and enable 2FA \xe2\x80\x94 gaming "
               "accounts are listed for sale within minutes";
    if (strcmp(cls, "subscription") == 0 || strcmp(cls, "payment") == 0)
        return "remove saved payment methods and change your password";
    return "change the password and check recent login activity";
}

/* Compound first-response triage for the post-click user — the temporal
 * complement to hlse_cascade_risk, narrowed to the next 60 seconds.
 *
 * Socratic question (Perspective 23): "hlse_triage_for() calls
 * hlse_attacker_objective() which returns the FIRST brand's objective.
 * For a PayPal+Apple co-spoof (financial AND identity), the triage line says
 * 'call the number on the back of your card' — correct for PayPal but silent
 * on Apple ID. That account can reset every other account the victim owns.
 * In a compound attack the victim has TWO concurrent incident-response
 * obligations, not one. If they prioritise the bank call and miss the Apple
 * ID reset window, the attacker still controls the recovery gateway for their
 * entire account ecosystem. Shouldn't the ⚑ line cover both?
 *
 * For n_brands == 1: writes the same result as hlse_triage_for().
 * For n_brands >= 2: writes a numbered two-step sequence:
 *   '(1) <financial triage>; (2) <identity triage>'
 * so both response obligations are visible in one line without truncation.
 * Caller supplies `out` buffer (512+ bytes for compound case);
 * returns 1 when guidance was written, 0 when score < 60 or buffer too small. */
int
hlse_compound_triage(const Verdict *v, char *out, size_t outsz) {
    int i;
    char brand1[64] = "";
    char brand2[64] = "";
    const char *class1 = NULL, *class2 = NULL;
    int n_found = 0;
    const char *single;

    /* 512-byte minimum for compound two-step triage sentence */
    if (!v || !out || outsz < 512 || v->score < 60) return 0;
    out[0] = '\0';

    for (i = 0; i < v->n_reasons && n_found < 2; i++) {
        const char *r     = v->reasons[i];
        const char *start = strstr(r, "Legitimate '");
        const char *end;
        char brand[64];
        size_t len;
        if (!start) continue;
        start += 12;
        end = strchr(start, '\'');
        if (!end) continue;
        len = (size_t)(end - start);
        if (len == 0 || len >= sizeof(brand)) continue;
        memcpy(brand, start, len);
        brand[len] = '\0';
        if (n_found == 0) {
            memcpy(brand1, brand, len + 1);
            class1 = brand_objective_class(brand1);
        } else {
            memcpy(brand2, brand, len + 1);
            class2 = brand_objective_class(brand2);
        }
        n_found++;
    }

    if (n_found == 0) {
        /* No brand found — fall back to hlse_triage_for() */
        single = hlse_triage_for(v);
        if (!single) return 0;
        snprintf(out, outsz, "%s", single);
        return 1;
    }
    if (n_found == 1) {
        single = hlse_triage_for(v);
        if (!single) return 0;
        snprintf(out, outsz, "%s", single);
        return 1;
    }
    /* n_found >= 2: compound two-step triage */
    snprintf(out, outsz,
             "(1) %s; (2) %s",
             triage_imperative(class1), triage_imperative(class2));
    return 1;
}

/* First-response triage for a text verdict — the 60-second action the post-
 * response user must take immediately.
 *
 * Socratic question (Perspective 27): "URL verdicts have ⚑ If already clicked:
 * triage. But BEC, tech-support scam, and grandparent-emergency victims don't
 * click a URL — they REPLY to an email, call a phone number, or act on a voice
 * instruction. By the time they reach HLSE, the harmful action is already done.
 * A BEC victim who just sent a wire needs to know: call the sending bank's
 * fraud line within 72 hours and request SWIFT recall — not read 'BLOCK [100]'.
 * A tech-support victim who gave remote access needs: disconnect from the
 * internet immediately, not a structural verdict. Shouldn't text threats >= 60
 * have the same temporal triage as URL threats?"
 *
 * Keyed to the same attack pattern as hlse_classify_text_attack() so the
 * response matches the specific harm that fired. Returns a static string, or
 * NULL when score < 60 or no recognisable pattern was found. Thread-safe;
 * no allocation.                                                              */
const char *
hlse_text_triage(const TextVerdict *v) {
    const char *pat;
    if (!v || v->score < 60) return NULL;
    pat = hlse_classify_text_attack(v);
    if (!pat) return NULL;

    if (strstr(pat, "fake-job") || strstr(pat, "task scam"))
        return "stop all payments and deposits now; if you already paid or "
               "deposited crypto, contact your bank or exchange immediately; if "
               "you installed any 'work-from-home' or 'security' app they sent, "
               "disconnect from the internet and remove it \xe2\x80\x94 it may be a "
               "remote-access trojan; report to the FTC (reportfraud.ftc.gov) "
               "or your national fraud line";
    if (strstr(pat, "MFA-fatigue") || strstr(pat, "push-bombing"))
        return "deny/dismiss the prompt; do NOT approve it \xe2\x80\x94 then "
               "change your password immediately from a device you trust, "
               "because an unsolicited MFA prompt means your password is already "
               "compromised; if you did approve one, sign out all sessions, "
               "rotate the password, and report it to your IT/security team";
    if (strstr(pat, "payment-diversion"))
        return "do NOT update the bank/payee details; if you already changed "
               "them, revert immediately and alert your payroll/accounts-payable "
               "team and your bank \xe2\x80\x94 check whether a payment run already "
               "went out so it can be recalled while it is still pending; verify "
               "the real employee or vendor on a phone number you already have";
    if (strstr(pat, "device-code") || strstr(pat, "OAuth"))
        return "if you entered the code OR clicked 'Accept' on a consent "
               "screen: FIRST revoke the app's access at "
               "myapplications.microsoft.com (or have an admin remove the "
               "enterprise app), then sign out of all Microsoft 365 sessions "
               "and revoke active tokens in entra.microsoft.com (Security "
               "\xe2\x86\x92 Sign-ins \xe2\x86\x92 revoke), then rotate the "
               "password \xe2\x80\x94 a consented app and a stolen refresh "
               "token both outlive a password reset, so removing the app's "
               "consent is the step most victims miss";
    if (strstr(pat, "ClickFix"))
        return "if you already pasted and ran the command: disconnect from the "
               "network immediately, scan with antivirus, and consider a full "
               "reinstall \xe2\x80\x94 a pasted command runs with your privileges";
    if (strstr(pat, "BEC") || strstr(pat, "CEO") ||
        strstr(pat, "wire-transfer") || strstr(pat, "wire transfer"))
        return "DO NOT send or authorise the transfer \xe2\x80\x94 if already "
               "sent, call your bank's fraud line within 72 hours to attempt a "
               "SWIFT recall; verify the request by calling the supposed sender "
               "on a separately-known number, not the one in this message";
    if (strstr(pat, "tech-support"))
        return "if you called the number: hang up now; if you gave remote "
               "access: disconnect from the internet immediately and UNINSTALL "
               "the remote-access tool they had you install (AnyDesk, "
               "TeamViewer, UltraViewer, etc.) \xe2\x80\x94 it keeps their access "
               "until removed; then change your banking credentials from a "
               "different device and call your IT team or bank directly";
    if (strstr(pat, "grandparent") || strstr(pat, "emergency impersonation"))
        return "call the family member directly on a number you already know "
               "\xe2\x80\x94 if they are genuinely in trouble, they can confirm "
               "it themselves; a voice that sounds exactly like them is NOT "
               "proof \xe2\x80\x94 AI clones a voice from 3 seconds of audio, so "
               "ask a pre-agreed safe word and do not send money or gift cards "
               "until you reach them on your own number";
    if (strstr(pat, "sextortion") || strstr(pat, "webcam blackmail"))
        return "do NOT pay and do NOT reply \xe2\x80\x94 replying confirms a live "
               "target and invites more demands; screenshot the message as "
               "evidence, block the sender, and report to IC3 / your national "
               "cybercrime line (and, if a minor is involved, NCMEC at "
               "CyberTipline.org); if real intimate images of you do exist, "
               "report them to the platform for takedown";
    if (strstr(pat, "ransom") || strstr(pat, "extortion"))
        return "do not pay \xe2\x80\x94 screenshot the message and report to "
               "your local cybercrime unit (FBI IC3, Action Fraud, etc.), then "
               "block the sender; most extortion threats are empty";
    if (strstr(pat, "investment") || strstr(pat, "pig-butchering"))
        return "stop all transfers immediately \xe2\x80\x94 if funds were sent, "
               "contact your bank to attempt a recall; report to your financial "
               "regulator; 'withdrawal fees' to recover losses are always a "
               "second theft";
    if (strstr(pat, "quishing") || strstr(pat, "QR"))
        return "if you already scanned the QR code: check your browser's address "
               "bar for an untrusted domain before entering any credentials; if "
               "you entered credentials, change that account's password now; if "
               "you approved a payment to an unexpected payee, contact your bank "
               "or payment provider immediately to stop or dispute it";
    if (strstr(pat, "refund") || strstr(pat, "subscription-renewal"))
        return "do not call the number; if you already called, never grant "
               "remote access or send back an 'over-refund' \xe2\x80\x94 a genuine "
               "refund needs nothing from you; if you gave remote access, "
               "disconnect and uninstall the tool (it may be a trojan) and "
               "dispute any real charge through your card issuer, not the caller";
    if (strstr(pat, "callback") || strstr(pat, "vishing") || strstr(pat, "TOAD"))
        return "do not call the number in this message \xe2\x80\x94 if you "
               "already called and gave personal information, contact your bank "
               "and change the relevant account credentials immediately";
    if (strstr(pat, "lottery") || strstr(pat, "advance-fee"))
        return "stop sending money \xe2\x80\x94 every 'fee' request is another "
               "theft; report to Action Fraud / FTC and block the contact";
    if (strstr(pat, "urgency credential") || strstr(pat, "urgency social") ||
        strstr(pat, "authority impersonation"))
        return "if you entered credentials: change that account's password "
               "immediately and enable 2FA; if you shared personal information: "
               "monitor credit and banking for unusual activity";
    /* Generic fallback for any other high-confidence text threat */
    return "stop the action if ongoing; change credentials for any account "
           "involved and enable 2FA; report the contact to your IT team or "
           "the relevant platform's abuse reporting";
}

/* Pre-action verification for a text verdict — the single check to perform
 * BEFORE taking any requested action (score >= 40, the ALERT floor).
 *
 * Socratic question (Perspective 31): "URL BLOCK verdicts show BOTH
 * ✓ Verify independently: (what to check before clicking) AND ⚑ If already
 * clicked: (post-click triage). Text BLOCK verdicts show only ⚑ If you acted:
 * whose label implies post-action, even when the most important advice is
 * pre-action — 'DO NOT send the wire transfer'. A BEC victim reading BLOCK [100]
 * needs to know the single decisive check they should do BEFORE authorising
 * anything: call the supposed sender on a separately-known number. A ClickFix
 * victim needs to know: never paste commands from unsolicited messages. Burying
 * this pre-action guidance inside a post-action triage label obscures it. Should
 * text BLOCK verdicts have the same ✓ Verify first: / ⚑ If you acted: split
 * that URL verdicts already have?"
 *
 * Socratic question (Perspective 95): "An ALERT [40-59] text verdict — e.g.
 * a single urgency/callback signal — shows a pattern label but no verify
 * guidance, same gap as the URL side. Widened the floor from 60 to 40 in
 * lockstep with hlse_verification_for so a user reading ALERT text gets the
 * same pre-action check a BLOCK reader gets, before the situation escalates."
 *
 * Keyed to the pattern from hlse_classify_text_attack(). Returns a static
 * string, or NULL when score < 40 or no recognisable pattern. Thread-safe;
 * no allocation.                                                               */
const char *
hlse_text_verify(const TextVerdict *v) {
    const char *pat;
    if (!v || v->score < 40) return NULL;
    pat = hlse_classify_text_attack(v);
    if (!pat) return NULL;
    if (strstr(pat, "fake-job") || strstr(pat, "task scam"))
        return "a real job only ever pays money TO you \xe2\x80\x94 no legitimate "
               "employer asks you to pay to start, deposit your own funds to "
               "'unlock' tasks or earnings, or buy equipment upfront; that "
               "request alone proves the job is fake, so stop before paying "
               "anything";
    if (strstr(pat, "MFA-fatigue") || strstr(pat, "push-bombing"))
        return "never approve an MFA or authenticator prompt you did not start "
               "yourself \xe2\x80\x94 a prompt or 'approve' request that arrives "
               "when you were not logging in means someone ALREADY has your "
               "password; deny it, and never approve to 'make the prompts stop'";
    if (strstr(pat, "payment-diversion"))
        return "confirm any bank-account or direct-deposit change by calling the "
               "employee or vendor on a number you ALREADY have on file \xe2\x80\x94 "
               "never the number, email, or reply-to in the request; a banking-"
               "detail change is the single highest-risk request, so treat it as "
               "fraud until verified through a separate channel";
    if (strstr(pat, "device-code") || strstr(pat, "OAuth"))
        return "never enter a verification code you did not initiate yourself, "
               "and never click 'Accept' on an app-permission/consent screen "
               "you did not start \xe2\x80\x94 even at a legitimate microsoft.com "
               "or google.com URL; the page is real but the code or consent "
               "hands the attacker's app your tokens";
    if (strstr(pat, "ClickFix"))
        return "never paste or run commands from unsolicited messages \xe2\x80\x94 "
               "legitimate software installations never require manual command-line "
               "execution";
    if (strstr(pat, "BEC") || strstr(pat, "CEO") ||
        strstr(pat, "wire-transfer") || strstr(pat, "wire transfer"))
        return "verify by calling the supposed sender on a number you already have "
               "\xe2\x80\x94 not any number or channel in this message; wire-transfer "
               "requests without a prior phone call are a red flag";
    if (strstr(pat, "tech-support"))
        return "a virus-warning popup that shows a phone number is ALWAYS fake "
               "\xe2\x80\x94 real security software never tells you to call; close "
               "the browser (or force-quit it) and never call the number on the "
               "screen; if you need help, call the company's main switchboard "
               "independently before allowing any remote access or payment";
    if (strstr(pat, "sextortion") || strstr(pat, "webcam blackmail"))
        return "the 'I hacked your webcam' claim is almost always a bluff blasted "
               "to millions \xe2\x80\x94 any password they quote was bought from a "
               "data breach, not proof of access; they cannot show you real "
               "footage because none exists, so do not pay and do not reply";
    if (strstr(pat, "ransom") || strstr(pat, "extortion"))
        return "do not pay \xe2\x80\x94 consult a law enforcement or cybersecurity "
               "professional before responding; paying funds further attacks";
    if (strstr(pat, "investment") || strstr(pat, "pig-butchering"))
        return "verify the firm's FCA/SEC/ASIC registration before engaging \xe2\x80\x94 "
               "registration numbers must match the official regulator's public register";
    if (strstr(pat, "grandparent") || strstr(pat, "emergency impersonation"))
        return "do not trust the voice \xe2\x80\x94 AI voice-cloning reproduces a "
               "loved one from a few seconds of audio; hang up and call the "
               "family member back on their own known number, and ask a "
               "pre-agreed safe word before sending any money or meeting any "
               "courier \xe2\x80\x94 take at least 10 minutes to verify independently";
    if (strstr(pat, "refund") || strstr(pat, "subscription-renewal"))
        return "check the charge in your real bank or card statement, or the "
               "provider's official app \xe2\x80\x94 never the number or link in "
               "this message; no genuine company phones you to give money back, "
               "so an unexpected 'refund' offer is itself the scam";
    if (strstr(pat, "callback") || strstr(pat, "TOAD") || strstr(pat, "vishing"))
        return "do not call the number in this message \xe2\x80\x94 find the "
               "organisation's number independently on their official website";
    if (strstr(pat, "lottery") || strstr(pat, "advance-fee"))
        return "do not pay any fee \xe2\x80\x94 legitimate prize schemes never charge "
               "winners upfront; search the organisation's official website to verify";
    if (strstr(pat, "QR") || strstr(pat, "quishing"))
        return "preview the QR destination before scanning \xe2\x80\x94 do not enter "
               "any credentials until you have confirmed the domain belongs to the "
               "expected organisation; on a PHYSICAL QR (parking meter, restaurant "
               "table, payment poster) feel for a sticker placed over the original, "
               "and on any payment QR confirm the payee name shown matches the real "
               "merchant before approving";
    if (strstr(pat, "urgency credential") || strstr(pat, "credential / payment") ||
        strstr(pat, "authority impersonation"))
        return "navigate directly to the service's official website (bookmark or "
               "search engine) \xe2\x80\x94 do not use any link in this message; "
               "verify the alert appears in your actual account dashboard";
    if (strstr(pat, "urgency"))
        return "verify the request through a separately-known channel before acting "
               "\xe2\x80\x94 do not use any contact details provided in this message";
    return NULL;
}

/* Name the attacker's likely objective for a text verdict — the specific asset
 * the recipient must treat as at-risk.
 *
 * Socratic question (Perspective 29): "URL verdicts show ◉ Attacker's goal:
 * keyed to the impersonated brand — 'crypto theft — seed phrase or wallet
 * drain; transfers are irreversible'. Text verdicts name the attack pattern
 * (▸ Pattern:) but not what the attacker is specifically trying to take. A BEC
 * victim reads 'BEC / CEO-fraud wire-transfer' and knows the mechanism, but
 * not that the asset at risk is wire-transfer funds with a 72-hour recall
 * window. A grandparent-scam victim reads 'emergency impersonation scam' but
 * not that the asset is cash — unrecoverable once handed to a courier. Without
 * naming the specific asset, the advisory gives no triage priority signal.
 * Shouldn't text threats >= 60 name the specific asset at risk, parallel to
 * the URL ◉ Attacker's goal: line?"
 *
 * Keyed to the same pattern as hlse_classify_text_attack(). Returns a static
 * string, or NULL when score < 60 or no recognisable pattern. Thread-safe;
 * no allocation.                                                               */
const char *
hlse_text_objective(const TextVerdict *v) {
    const char *pat;
    if (!v || v->score < 60) return NULL;
    pat = hlse_classify_text_attack(v);
    if (!pat) return NULL;
    if (strstr(pat, "fake-job") || strstr(pat, "task scam"))
        return "upfront fees and deposits you will never recover \xe2\x80\x94 the "
               "'job' exists to take your equipment payment or 'task' deposit; "
               "any 'work-from-home app' they tell you to install may be a "
               "remote-access trojan that drains your bank and files";
    if (strstr(pat, "MFA-fatigue") || strstr(pat, "push-bombing"))
        return "account takeover via MFA approval \xe2\x80\x94 the attacker "
               "already has your password and is spamming push prompts; "
               "approving one hands them an authenticated session";
    if (strstr(pat, "payment-diversion"))
        return "redirected payments \xe2\x80\x94 your next payroll deposit or "
               "vendor invoice is rerouted to the attacker's bank account; the "
               "money is gone once the payment run clears";
    if (strstr(pat, "device-code") || strstr(pat, "OAuth"))
        return "Microsoft 365 / Azure OAuth tokens \xe2\x80\x94 grants persistent "
               "access that bypasses MFA and survives password reset; attacker "
               "can read mail, exfiltrate files, and pivot to connected SaaS";
    if (strstr(pat, "ClickFix"))
        return "system access \xe2\x80\x94 pasted command runs with your user "
               "privileges; treat the machine as compromised until proven clean";
    if (strstr(pat, "BEC") || strstr(pat, "CEO") ||
        strstr(pat, "wire-transfer") || strstr(pat, "wire transfer"))
        return "wire-transfer funds \xe2\x80\x94 irreversible once processed; "
               "72-hour SWIFT recall window";
    if (strstr(pat, "tech-support"))
        return "credit card or remote device access \xe2\x80\x94 reversible "
               "within hours if caught immediately";
    if (strstr(pat, "sextortion") || strstr(pat, "webcam blackmail"))
        return "an extortion payment for a threat that is almost always an empty "
               "bluff \xe2\x80\x94 these emails are mass-mailed and the attacker "
               "usually has no footage at all; even AI-deepfaked images do not "
               "make paying work, because payment only marks you as a target";
    if (strstr(pat, "ransom") || strstr(pat, "extortion"))
        return "cryptocurrency payment \xe2\x80\x94 paying does not guarantee "
               "recovery and invites further extortion demands";
    if (strstr(pat, "investment") || strstr(pat, "pig-butchering"))
        return "long-term savings \xe2\x80\x94 typically unrecoverable once "
               "withdrawn to attacker-controlled wallet";
    if (strstr(pat, "grandparent") || strstr(pat, "emergency impersonation"))
        return "cash withdrawal \xe2\x80\x94 typically unrecoverable once handed "
               "to courier";
    if (strstr(pat, "QR") || strstr(pat, "quishing"))
        return "credentials entered after redirect \xe2\x80\x94 QR codes bypass "
               "link-preview safety checks";
    if (strstr(pat, "refund") || strstr(pat, "subscription-renewal"))
        return "money and device access via a fake refund \xe2\x80\x94 the "
               "invoice is bait to make you call; the 'refund' then requires "
               "remote access to your device or tricks you into wiring back an "
               "'over-refund' the scammer never actually sent";
    if (strstr(pat, "callback") || strstr(pat, "TOAD") || strstr(pat, "vishing"))
        return "financial account or device access obtained via voice social "
               "engineering";
    if (strstr(pat, "lottery") || strstr(pat, "advance-fee"))
        return "upfront payment or personal information for a non-existent prize";
    if (strstr(pat, "urgency credential") || strstr(pat, "credential / payment") ||
        strstr(pat, "authority impersonation"))
        return "account credentials \xe2\x80\x94 all sites sharing this password "
               "are at cascade risk";
    if (strstr(pat, "urgency"))
        return "account credentials or an action taken under false time pressure";
    if (strstr(pat, "prize"))
        return "personal information or upfront payment for a fraudulent prize";
    return NULL;
}

/* Cascade risk for a text verdict — the other accounts or assets at risk
 * beyond the primary target.
 *
 * Socratic question (Perspective 32): "URL verdicts have ⊕ Also change:
 * naming every account class in the password-reuse blast radius (email,
 * banking, every service sharing the harvested password). Text BLOCK verdicts
 * identify the primary attack and tell users what to do about it — but say
 * nothing about the downstream accounts that fall if the primary is compromised.
 * A ClickFix victim who disconnects their machine has fixed the primary but may
 * still have all their saved browser passwords exfiltrated. A BEC victim who
 * recalls the wire has stopped the funds but may have the corporate email
 * account compromised, giving the attacker the recovery address for everything
 * else. Shouldn't text BLOCK verdicts also name what else is at risk, parallel
 * to the URL ⊕ Also change: line?"
 *
 * Keyed to the attack pattern from hlse_classify_text_attack(). Returns a
 * static string, or NULL when score < 60 or no recognisable pattern.
 * Thread-safe; no allocation.                                                 */
const char *
hlse_text_cascade(const TextVerdict *v) {
    const char *pat;
    if (!v || v->score < 60) return NULL;
    pat = hlse_classify_text_attack(v);
    if (!pat) return NULL;
    if (strstr(pat, "sextortion") || strstr(pat, "webcam blackmail"))
        return "nothing of yours is technically compromised by the threat itself "
               "\xe2\x80\x94 but if you reused the breached password they quoted, "
               "change it everywhere it appears, and tighten privacy on your "
               "social accounts so the attacker cannot reach your contact list";
    if (strstr(pat, "refund") || strstr(pat, "subscription-renewal"))
        return "if you granted remote access or moved any money, treat the whole "
               "device and every account you opened during the call as "
               "compromised \xe2\x80\x94 scan from a clean device, change those "
               "passwords, and watch your card and bank for unauthorised charges";
    if (strstr(pat, "fake-job") || strstr(pat, "task scam"))
        return "any card or account you used to pay, and any credentials you "
               "entered on the fake 'employer portal' \xe2\x80\x94 plus, if you ran "
               "their software, treat the whole device as compromised: scan it, "
               "change passwords from a clean device, and watch for unauthorised "
               "bank activity";
    if (strstr(pat, "MFA-fatigue") || strstr(pat, "push-bombing"))
        return "every account sharing this now-compromised password, and your "
               "email (the recovery gateway) \xe2\x80\x94 the attacker already "
               "knows the password, so rotate it everywhere it is reused and "
               "switch this account to phishing-resistant MFA (a passkey or "
               "hardware key) that cannot be approved by mistake";
    if (strstr(pat, "payment-diversion"))
        return "every other payee record an attacker with this mailbox could "
               "alter \xe2\x80\x94 audit all recent bank-detail changes for staff "
               "and vendors, and check whether the email account that sent this "
               "is itself compromised (it is the likely entry point)";
    if (strstr(pat, "device-code") || strstr(pat, "OAuth"))
        return "every SaaS app connected to your Microsoft 365 tenant (SharePoint, "
               "Teams, Exchange, OneDrive) and any third-party app with consent "
               "from your account \xe2\x80\x94 revoke app consents in entra.microsoft."
               "com and audit recent OAuth grants from a clean device";
    if (strstr(pat, "ClickFix"))
        return "all credentials stored in browsers, password managers, and the OS "
               "credential store \xe2\x80\x94 assume the script exfiltrated them; "
               "change all saved passwords from a clean device";
    if (strstr(pat, "BEC") || strstr(pat, "CEO") ||
        strstr(pat, "wire-transfer") || strstr(pat, "wire transfer"))
        return "corporate email (likely the channel used to authorise the transfer "
               "and the recovery address for every downstream service) \xe2\x80\x94 "
               "treat it as compromised and change it from a different device";
    if (strstr(pat, "tech-support"))
        return "all credentials visible during the remote-access session "
               "\xe2\x80\x94 the operator could see your screen, saved logins, and "
               "password manager; change them all from a different device";
    if (strstr(pat, "urgency credential") || strstr(pat, "credential / payment") ||
        strstr(pat, "authority impersonation"))
        return "email (the recovery gateway for all other accounts), banking and "
               "payment apps, and every account sharing this password "
               "\xe2\x80\x94 credential-stuffing bots test stolen logins within "
               "minutes of harvest";
    if (strstr(pat, "QR") || strstr(pat, "quishing"))
        return "the account entered after redirect, email (recovery gateway), and "
               "every service sharing that password";
    if (strstr(pat, "investment") || strstr(pat, "pig-butchering"))
        return "other liquid assets and any exchange accounts or bank accounts used "
               "to fund the investment \xe2\x80\x94 review all recent transfers";
    if (strstr(pat, "urgency"))
        return "email (the recovery gateway) and every account sharing the password "
               "or personal information disclosed under urgency pressure";
    return NULL;
}

/* Cascade risk: the blast radius if the victim reused this password elsewhere.
 *
 * Socratic question (Perspective 18): "You've named the primary target and
 * given triage guidance for that account. But credential-stuffing bots test
 * stolen logins against hundreds of services within minutes — and 65 % of
 * people reuse passwords. If the victim's PayPal password is also their Gmail
 * password, the attacker now controls the recovery address for every other
 * account. Shouldn't post-click guidance name the accounts most likely to fall
 * in a cascade, not just the one they were phished for?
 *
 * For multi-brand co-spoof URLs (Perspective 17) the cascade is compound —
 * two credential classes harvested at once compounds the blast radius further."
 *
 * Returns a static string, or NULL when score < 60 (pre-click context has no
 * cascade to describe). Thread-safe: no allocation, reads static tables only. */
const char *
hlse_cascade_risk(const Verdict *v) {
    const char *obj;
    const char *pat;
    if (!v || v->score < 60) return NULL;

    /* Multi-brand co-spoof: compound harvest across two credential classes. */
    pat = hlse_classify_url_attack(v);
    if (pat && strstr(pat, "multi-brand co-spoof"))
        return "two credential classes were targeted at once — audit BOTH: "
               "the financial/payment account AND the identity/email account, "
               "then change any other account sharing either password; "
               "stuffing bots test stolen pairs across hundreds of services "
               "within minutes";

    obj = hlse_attacker_objective(v);
    if (!obj)
        return "change any other account sharing this password \xe2\x80\x94 "
               "credential-stuffing bots test stolen logins across "
               "hundreds of services within minutes";
    if (strstr(obj, "financial") || strstr(obj, "banking") || strstr(obj, "funds"))
        return "email (the recovery gateway for all other accounts), other "
               "banking and payment apps, and every account sharing this "
               "password \xe2\x80\x94 stuffing attacks start within minutes "
               "of a credential harvest";
    if (strstr(obj, "crypto") || strstr(obj, "seed phrase") || strstr(obj, "wallet"))
        return "other exchanges and any account using the same email or "
               "password \xe2\x80\x94 on-chain transfers are irreversible so "
               "act before funds move; a compromised seed drains ALL wallets "
               "derived from it, not just one; and if you approved any contract, "
               "audit and revoke EVERY active token approval (revoke.cash) \xe2\x80\x94 "
               "a drainer often holds approvals across several tokens at once";
    if (strstr(obj, "identity") || strstr(obj, "keystone"))
        return "every account that lists this email as its password-reset "
               "address \xe2\x80\x94 whoever controls your inbox controls "
               "account recovery for everything else; start with banking, "
               "then work through any account you care about";
    if (strstr(obj, "corporate") || strstr(obj, "employer") || strstr(obj, "enterprise"))
        return "other work apps (email, Slack, Jira, VPN, SSO), and alert your "
               "IT security team immediately \xe2\x80\x94 a single corporate "
               "credential often pivots to the entire network within hours";
    if (strstr(obj, "SIM-swap") || strstr(obj, "telecom"))
        return "every account protected only by SMS-based 2FA \xe2\x80\x94 a "
               "SIM-swap defeats those codes across all services at once; "
               "switch to an authenticator app on accounts you cannot afford "
               "to lose";
    if (strstr(obj, "password-vault"))
        return "all credentials stored in the vault, and the email address "
               "used to recover the vault itself \xe2\x80\x94 a compromised "
               "vault exposes every account you manage in one breach";
    if (strstr(obj, "gaming"))
        return "linked payment methods, the associated email, and any account "
               "sharing this password \xe2\x80\x94 compromised game accounts "
               "are listed for sale within hours, often before the owner "
               "notices";
    if (strstr(obj, "social") || strstr(obj, "contact-list"))
        return "accounts accessed via 'Sign in with [brand]', linked payment "
               "methods, and the associated email \xe2\x80\x94 attackers use "
               "a hijacked social account to target your contact list next";
    if (strstr(obj, "subscription") || strstr(obj, "stored payment"))
        return "saved payment cards on other shopping sites and any account "
               "sharing this password \xe2\x80\x94 attackers drain gift cards "
               "and place orders on saved methods immediately after compromise";
    return "any other account sharing this password \xe2\x80\x94 change them "
           "starting with email (the master reset key for everything else)";
}
