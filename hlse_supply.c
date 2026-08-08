/*
 * hlse_supply.c — Supply Chain Defense Module
 *
 * Protects against three human-layer supply chain attack vectors:
 *
 *   S1. Package typosquatting  — "pip install reqeusts" (→ requests)
 *   S2. Pastejacking           — hostile commands hidden in copied text
 *   S3. Dependency confusion   — internal package names leaking to public
 *
 * Key insight: typosquatting detection reuses the same Damerau-Levenshtein
 * algorithm used for URL typosquat detection in hlse_core.c. Package
 * registries are just another namespace where humans mistype names.
 *
 * All detection is pure functions. Zero network access. Zero dependencies
 * beyond libc.
 *
 * Build: gcc -O2 -c hlse_supply.c -I.
 */

#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <ctype.h>

#include "hlse_supply.h"
#include "hlse_util.h"

/* ═══════════════════════════════════════════════════════════════════════
 * Damerau-Levenshtein distance — delegates to shared hlse_util.
 * ═══════════════════════════════════════════════════════════════════════ */

static int
dl_distance(const char *a, const char *b) {
    return hlse_edit_distance(a, b);
}

/* Map common ecosystem aliases to the canonical registry label used in
 * REGISTRIES ("pip", "npm", "cargo", "go", "gem"). Users say "pypi" or
 * "python" for pip, "crates" for cargo, "rubygems" for gem, etc. — and the
 * CLI help itself advertises "pypi".
 *
 * Returns the canonical label, or NULL when the alias is unknown. A NULL
 * result makes the caller scan ALL registries: a security check must never
 * silently pass just because the caller spelled the ecosystem differently
 * than the internal label (that would be a false-negative — the user thinks
 * they checked the package and got a clean result). */
static const char *
canonical_ecosystem(const char *eco) {
    char low[32];
    size_t i;
    if (!eco || !eco[0]) return NULL;       /* unspecified → scan all       */
    for (i = 0; eco[i] && i < sizeof(low) - 1; i++) {
        char c = eco[i];
        low[i] = (c >= 'A' && c <= 'Z') ? (char)(c + 32) : c;
    }
    low[i] = '\0';

    if (!strcmp(low, "pip")    || !strcmp(low, "pypi")   ||
        !strcmp(low, "python") || !strcmp(low, "pip3")   ||
        !strcmp(low, "pypi.org"))                          return "pip";
    if (!strcmp(low, "npm")    || !strcmp(low, "node")   ||
        !strcmp(low, "nodejs") || !strcmp(low, "yarn")   ||
        !strcmp(low, "pnpm")   || !strcmp(low, "npmjs"))   return "npm";
    if (!strcmp(low, "cargo")  || !strcmp(low, "crates") ||
        !strcmp(low, "crates.io") || !strcmp(low, "rust"))  return "cargo";
    if (!strcmp(low, "go")     || !strcmp(low, "golang") ||
        !strcmp(low, "gomod")  || !strcmp(low, "go.mod"))   return "go";
    if (!strcmp(low, "gem")    || !strcmp(low, "rubygems") ||
        !strcmp(low, "ruby")   || !strcmp(low, "bundler"))  return "gem";
    return NULL;                            /* unknown → fail safe, scan all */
}

/* ═══════════════════════════════════════════════════════════════════════
 * S1: Package Typosquatting Detection
 *
 * Top packages for each ecosystem. Only the most popular are needed —
 * attackers target typosquats of high-download packages.
 * ═══════════════════════════════════════════════════════════════════════ */

static const char *PIP_TOP[] = {
    "requests", "numpy", "pandas", "flask", "django", "boto3",
    "tensorflow", "torch", "pytorch", "scipy", "matplotlib",
    "pillow", "cryptography", "pyyaml", "sqlalchemy", "jinja2",
    "beautifulsoup4", "selenium", "scrapy", "celery",
    "fastapi", "uvicorn", "pydantic", "httpx", "aiohttp",
    "pytest", "setuptools", "wheel", "pip", "virtualenv",
    "black", "mypy", "ruff", "isort", "flake8",
    "paramiko", "fabric", "ansible", "docker", "kubernetes",
    "stripe", "twilio", "sendgrid", "openai", "anthropic",
    "transformers", "langchain", "chromadb", "pinecone",
    "scikit-learn", "xgboost", "lightgbm", "huggingface-hub", "datasets",
    "wandb", "mlflow", "click", "rich", "typer",
    /* High-growth data / infrastructure — active typosquat targets */
    "polars", "dask", "numba", "sympy", "statsmodels",
    "gunicorn", "psycopg2", "redis", "python-dotenv", "pycryptodome",
    /* AI/LLM ecosystem 2024 — active typosquat campaigns */
    "llama-index", "llama_index", "autogen", "crewai", "litellm",
    "qdrant-client", "weaviate-client", "instructor", "haystack-ai",
    /* Azure SDK — targeted due to enterprise credential access */
    "azure-core", "azure-storage-blob", "azure-identity",
    "azure-keyvault-secrets", "azure-mgmt-core",
    /* Monitoring / observability */
    "sentry-sdk", "opentelemetry-api",
    /* Web3 / crypto — typosquat targets for seed-phrase-stealing payloads */
    "web3", "eth-account", "eth-utils", "web3py", "solana", "bitcoinlib",
    NULL
};

static const char *NPM_TOP[] = {
    "express", "react", "vue", "angular", "next", "lodash",
    "axios", "moment", "webpack", "typescript", "eslint",
    "prettier", "jest", "mocha", "chai", "cypress",
    "socket.io", "mongoose", "sequelize", "prisma",
    "tailwindcss", "postcss", "autoprefixer", "vite",
    "nodemon", "pm2", "dotenv", "cors", "helmet",
    "jsonwebtoken", "bcrypt", "passport", "uuid",
    "chalk", "commander", "inquirer", "yargs", "debug",
    "fs-extra", "glob", "rimraf", "cross-env", "concurrently",
    "openai", "langchain", "firebase", "stripe", "aws-sdk",
    "underscore", "rxjs", "date-fns", "zod", "three",
    "d3", "svelte", "nuxt", "graphql", "webpack-cli",
    /* Modern tooling — high-value typosquat targets */
    "vitest", "playwright", "dayjs", "turbo", "esbuild",
    "framer-motion", "storybook", "remix", "astro", "typeorm",
    /* AI/LLM and cloud tooling 2024 */
    "chromadb", "anthropic", "wrangler", "drizzle-orm", "hono",
    "react-query", "better-sqlite3", "sharp", "ioredis", "bullmq",
    "trpc", "next-auth", "nuxt-auth", "lucia", "pocketbase",
    /* High-download utility packages — frequent typosquat campaign targets */
    "semver", "minimist", "node-fetch", "cross-fetch",
    "node-cache", "winston", "morgan", "multer",
    "socket.io-client", "ws", "got", "supertest",
    /* Cloud providers and infra */
    "aws-cdk", "serverless", "netlify-cli", "vercel",
    /* Web3 / crypto — wallet-drainer malware ships as fake ethers/web3 pkgs */
    "ethers", "web3", "wagmi", "viem", "hardhat",
    "@solana/web3.js", "@walletconnect/client", "web3modal",
    NULL
};

static const char *CARGO_TOP[] = {
    "serde", "tokio", "reqwest", "clap", "rand", "regex",
    "chrono", "log", "env_logger", "anyhow", "thiserror",
    "serde_json", "hyper", "actix-web", "axum", "warp",
    "diesel", "sqlx", "rusqlite", "redis",
    "rayon", "crossbeam", "parking_lot", "dashmap",
    "tracing", "tower", "tonic", "prost",
    "sha2", "aes", "ring", "rustls",
    "nom", "syn", "bytes", "futures", "async-trait",
    "serde_yaml", "toml", "indexmap", "itertools", "uuid",
    /* Additional popular crates */
    "rocket", "jsonwebtoken", "mongodb", "openssl", "curve25519-dalek",
    /* 2024 high-growth / high-value typosquat targets */
    "tauri", "leptos", "dioxus", "bevy", "embassy",
    "tokio-tungstenite", "axum-core", "tower-http",
    "sea-orm", "sea-query", "dotenvy",
    /* ML / AI inference — HuggingFace candle, burn, ONNX runtime */
    "candle-core", "candle-nn", "candle-transformers",
    "burn", "burn-core", "burn-tensor",
    "ort", "ndarray", "linfa",
    /* Cryptography / PKI */
    "rcgen", "webpki", "x509-parser", "p256", "ed25519-dalek",
    "chacha20poly1305", "argon2", "pbkdf2",
    NULL
};

static const char *GO_TOP[] = {
    "gin", "echo", "fiber", "chi", "gorilla",
    "gorm", "sqlx", "pgx", "mongo-driver",
    "grpc", "protobuf", "wire", "fx",
    "zap", "logrus", "zerolog", "viper", "cobra",
    "testify", "gomock", "ginkgo",
    "aws-sdk-go", "azure-sdk-for-go", "google-cloud-go",
    "redis", "jwt-go", "validator", "cron", "migrate",
    /* High-value additions 2024 */
    "mux", "httprouter", "negroni", "iris",
    "urfave", "spf13", "hashicorp",
    "golang-jwt", "paseto", "casbin",
    "sarama", "confluent-kafka-go", "nats",
    "docker", "kubernetes", "helm",
    /* Security / crypto — targeted due to credential access */
    "go-jose", "golang-jwt", "oauth2",
    /* Secrets management — SOPS, Vault client */
    "sops", "vault",
    /* AI/LLM tooling 2024 */
    "langchaingo", "go-openai",
    NULL
};

static const char *GEM_TOP[] = {
    "rails", "rake", "bundler", "rspec", "devise", "sidekiq",
    "puma", "unicorn", "sinatra", "activerecord", "activesupport",
    "capistrano", "pundit", "cancancan", "kaminari", "paperclip",
    "carrierwave", "omniauth", "warden", "bcrypt", "dotenv-rails",
    "faraday", "httparty", "rest-client", "aws-sdk-ruby",
    "stripe", "twilio-ruby", "sendgrid-ruby",
    "nokogiri", "pg", "mysql2", "sqlite3", "redis",
    "rswag", "factory_bot_rails", "shoulda-matchers",
    /* High-value targets — active typosquat campaigns */
    "dry-validation", "dry-monads", "sorbet", "rubocop",
    /* Audit / security gems */
    "paper_trail", "brakeman",
    /* Background job / caching */
    "delayed_job", "whenever",
    NULL
};

typedef struct {
    const char        *name;
    const char *const *packages;
} Registry;

static const Registry REGISTRIES[] = {
    { "pip",   PIP_TOP },
    { "npm",   NPM_TOP },
    { "cargo", CARGO_TOP },
    { "go",    GO_TOP },
    { "gem",   GEM_TOP },
    { NULL, NULL }
};

/* Known typosquat attack patterns:
 * - Character swap: requsets → requests
 * - Missing char: reqests → requests
 * - Extra char: requestss → requests
 * - Hyphen confusion: python-dateutil vs python_dateutil
 * - Scope confusion: @types/lodash vs types-lodash              */
static int
normalize_pkg_name(const char *src, char *dst, size_t cap) {
    size_t i, j = 0;
    for (i = 0; src[i] && j < cap - 1; i++) {
        char c = src[i];
        /* Normalize: underscore → hyphen, strip whitespace */
        if (c == '_') c = '-';
        if (c == ' ' || c == '\t') continue;
        dst[j++] = (c >= 'A' && c <= 'Z') ? c + 32 : c;
    }
    dst[j] = '\0';
    return (int)j;
}

PackageVerdict
hlse_check_package(const char *pkg_name, const char *ecosystem) {
    PackageVerdict v;
    char norm[128];
    int ri;
    const char *eco_canon;

    memset(&v, 0, sizeof(v));

    if (!pkg_name || !pkg_name[0]) return v;
    normalize_pkg_name(pkg_name, norm, sizeof(norm));
    eco_canon = canonical_ecosystem(ecosystem);

    for (ri = 0; REGISTRIES[ri].name; ri++) {
        const char *const *pkgs;
        int pi;

        /* Filter by ecosystem when the caller named a recognized one. An
         * unrecognized alias yields eco_canon == NULL → scan every registry
         * (fail safe) rather than silently matching nothing.              */
        if (eco_canon && strcmp(eco_canon, REGISTRIES[ri].name) != 0)
            continue;

        pkgs = REGISTRIES[ri].packages;
        for (pi = 0; pkgs[pi]; pi++) {
            char norm_ref[128];
            int dist;

            normalize_pkg_name(pkgs[pi], norm_ref, sizeof(norm_ref));

            /* Exact match → safe. Record WHICH registry recognised it: the
             * caller uses a non-empty reason here to tell "known-good name"
             * apart from "name I have never heard of". Both are score 0 with
             * 0 matches, but they carry very different residual risk — see the
             * package blind-spot text in hlse_core.c. */
            if (strcmp(norm, norm_ref) == 0) {
                v.score = 0;
                v.n_matches = 0;
                snprintf(v.reason, sizeof(v.reason),
                         "Known package: '%s' is a recognised %s package.",
                         pkgs[pi], REGISTRIES[ri].name);
                return v;
            }

            dist = dl_distance(norm, norm_ref);
            if (dist <= 2 && dist > 0 &&
                v.n_matches < HLSE_SUPPLY_MAX_MATCHES)
            {
                int score_add = (dist == 1) ? 50 : 35;
                snprintf(v.matches[v.n_matches].legit_name,
                         sizeof(v.matches[0].legit_name), "%s", pkgs[pi]);
                snprintf(v.matches[v.n_matches].registry,
                         sizeof(v.matches[0].registry), "%s",
                         REGISTRIES[ri].name);
                v.matches[v.n_matches].distance = dist;
                v.n_matches++;

                if (score_add > v.score) v.score = score_add;
            }
        }
    }

    /* Amplifier: if exactly 1 match with distance 1, very likely typosquat */
    if (v.n_matches == 1 && v.matches[0].distance == 1) {
        v.score = 70;
        snprintf(v.reason, sizeof(v.reason),
                 "Typosquat alert: '%s' is 1 edit from '%s' (%s). "
                 "Did you mean '%s'?",
                 pkg_name, v.matches[0].legit_name,
                 v.matches[0].registry, v.matches[0].legit_name);
    } else if (v.n_matches > 0) {
        snprintf(v.reason, sizeof(v.reason),
                 "Possible typosquat: '%s' is close to %d known package(s)",
                 pkg_name, v.n_matches);
    }

    if (v.score > 100) v.score = 100;
    return v;
}

/* ═══════════════════════════════════════════════════════════════════════
 * S2: Pastejacking Detection
 *
 * Detects hostile content in text that a user copies from the web:
 *
 *   P1. Hidden newlines    — executes before user can review
 *   P2. curl|bash patterns — remote code execution
 *   P3. Unicode control    — right-to-left override, zero-width chars
 *   P4. Sudo/su injection  — privilege escalation in pasted command
 *   P5. Encoded payloads   — base64 -d | sh, python -c "..."
 *   P6. History evasion    — commands starting with space (bash)
 *   P7. Background exec    — trailing & hides process
 *   P8. Windows LOLBin     — "ClickFix" PowerShell/mshta/certutil one-liners
 * ═══════════════════════════════════════════════════════════════════════ */

/* Case-insensitive substring search. `needle` MUST be lowercase ASCII.
 * O(n*m), fine for paste-sized text; avoids allocating a lowercased copy. */
static int
ci_contains(const char *hay, const char *needle) {
    size_t nl = strlen(needle);
    if (nl == 0) return 1;
    for (; *hay; hay++) {
        size_t k = 0;
        while (k < nl && hay[k] &&
               (char)tolower((unsigned char)hay[k]) == needle[k])
            k++;
        if (k == nl) return 1;
    }
    return 0;
}

PasteVerdict
hlse_check_paste(const char *text) {
    PasteVerdict v;
    size_t len;

    memset(&v, 0, sizeof(v));
    if (!text) return v;
    len = strlen(text);
    if (len == 0) return v;

    /* P1: Hidden newlines — if text contains \n and looks like a command,
     * the first line executes immediately on terminal paste.            */
    {
        const char *nl = strchr(text, '\n');
        if (nl && (nl - text) < (int)len - 1) {
            /* Check if the first line looks like a command */
            if (text[0] != '#' && len > 5) {
                v.signals |= PASTE_HIDDEN_NEWLINE;
                v.score += 25;
                snprintf(v.reasons[v.n_reasons++], sizeof(v.reasons[0]),
                    "P1: Hidden newline at position %d — first line "
                    "auto-executes on terminal paste",
                    (int)(nl - text));
            }
        }
    }

    /* P2: curl/wget piped to shell */
    {
        int has_curl = (strstr(text, "curl ") != NULL ||
                       strstr(text, "wget ") != NULL);
        int has_pipe_sh = (strstr(text, "| sh") != NULL ||
                          strstr(text, "| bash") != NULL ||
                          strstr(text, "|sh") != NULL ||
                          strstr(text, "|bash") != NULL ||
                          strstr(text, "| sudo") != NULL ||
                          strstr(text, "| /bin/sh") != NULL ||
                          strstr(text, "| /bin/bash") != NULL);
        if (has_curl && has_pipe_sh) {
            v.signals |= PASTE_CURL_PIPE_SH;
            v.score += 40;
            if (v.n_reasons < HLSE_PASTE_MAX_REASONS)
                snprintf(v.reasons[v.n_reasons++], sizeof(v.reasons[0]),
                    "P2: Remote code execution — download piped to shell");
        }
    }

    /* P3: Unicode control characters */
    {
        size_t i;
        int rtl_found = 0, zwc_found = 0;
        for (i = 0; i + 2 < len; i++) {
            unsigned char b0 = (unsigned char)text[i];
            unsigned char b1 = (unsigned char)text[i+1];
            unsigned char b2 = (unsigned char)text[i+2];

            /* U+202E RIGHT-TO-LEFT OVERRIDE = E2 80 AE */
            if (b0 == 0xE2 && b1 == 0x80 && b2 == 0xAE) rtl_found = 1;
            /* U+200B ZERO WIDTH SPACE = E2 80 8B */
            if (b0 == 0xE2 && b1 == 0x80 && b2 == 0x8B) zwc_found = 1;
            /* U+200D ZERO WIDTH JOINER = E2 80 8D */
            if (b0 == 0xE2 && b1 == 0x80 && b2 == 0x8D) zwc_found = 1;
            /* U+FEFF BOM / ZERO WIDTH NO-BREAK = EF BB BF */
            if (b0 == 0xEF && b1 == 0xBB && b2 == 0xBF && i > 0)
                zwc_found = 1;
        }
        if (rtl_found) {
            v.signals |= PASTE_UNICODE_CONTROL;
            v.score += 50;
            if (v.n_reasons < HLSE_PASTE_MAX_REASONS)
                snprintf(v.reasons[v.n_reasons++], sizeof(v.reasons[0]),
                    "P3: RIGHT-TO-LEFT OVERRIDE character — "
                    "real content may be visually hidden");
        }
        if (zwc_found) {
            v.signals |= PASTE_UNICODE_CONTROL;
            v.score += 20;
            if (v.n_reasons < HLSE_PASTE_MAX_REASONS)
                snprintf(v.reasons[v.n_reasons++], sizeof(v.reasons[0]),
                    "P3: Zero-width Unicode character — content may differ "
                    "from what is displayed");
        }
    }

    /* P4: Sudo / su injection */
    if (strstr(text, "sudo ") || strstr(text, "su -c") ||
        strstr(text, "doas ")) {
        v.signals |= PASTE_SUDO_INJECTION;
        v.score += 15;
        if (v.n_reasons < HLSE_PASTE_MAX_REASONS)
            snprintf(v.reasons[v.n_reasons++], sizeof(v.reasons[0]),
                "P4: Privilege escalation command (sudo/su/doas)");
    }

    /* P5: Encoded payloads */
    if (strstr(text, "base64 -d") || strstr(text, "base64 --decode") ||
        strstr(text, "python -c") || strstr(text, "python3 -c") ||
        strstr(text, "perl -e") || strstr(text, "ruby -e") ||
        strstr(text, "node -e") || strstr(text, "php -r") ||
        (strstr(text, "echo ") && strstr(text, "| base64"))) {
        v.signals |= PASTE_ENCODED_PAYLOAD;
        v.score += 30;
        if (v.n_reasons < HLSE_PASTE_MAX_REASONS)
            snprintf(v.reasons[v.n_reasons++], sizeof(v.reasons[0]),
                "P5: Encoded/interpreted payload — obfuscated command");
    }

    /* P6: History evasion — starts with space */
    if (text[0] == ' ' && len > 3) {
        v.signals |= PASTE_HISTORY_EVASION;
        v.score += 15;
        if (v.n_reasons < HLSE_PASTE_MAX_REASONS)
            snprintf(v.reasons[v.n_reasons++], sizeof(v.reasons[0]),
                "P6: Leading space — command won't appear in shell history");
    }

    /* P7: Background execution */
    {
        const char *last_amp = strrchr(text, '&');
        if (last_amp && (last_amp[1] == '\0' || last_amp[1] == '\n') &&
            !(last_amp > text && last_amp[-1] == '&')) {  /* not && */
            v.signals |= PASTE_BACKGROUND_EXEC;
            v.score += 10;
            if (v.n_reasons < HLSE_PASTE_MAX_REASONS)
                snprintf(v.reasons[v.n_reasons++], sizeof(v.reasons[0]),
                    "P7: Trailing '&' — command runs in background, "
                    "harder to notice");
        }
    }

    /* P8: Windows "ClickFix" / LOLBin remote execution. ClickFix lures (fake
     * CAPTCHA or browser-update pages) tell the victim to press Win+R and
     * paste a one-liner that runs PowerShell or a living-off-the-land binary.
     * None of the Unix-centric checks above fire on these, yet ClickFix is the
     * dominant 2024-2025 initial-access technique. Matching is case-insensitive
     * and requires a download/exec qualifier so legitimate admin one-liners do
     * not trip it. */
    {
        const char *what = NULL;
        if (ci_contains(text, "powershell") &&
            (ci_contains(text, "-enc ")        || ci_contains(text, "encodedcommand") ||
             ci_contains(text, "downloadstring")|| ci_contains(text, "frombase64string") ||
             ci_contains(text, "iex")          || ci_contains(text, "invoke-expression") ||
             ci_contains(text, "-w hidden")    || ci_contains(text, "windowstyle hidden"))) {
            what = "PowerShell hidden/encoded/download-execute";
        } else if (ci_contains(text, "mshta") &&
                   (ci_contains(text, "http")  || ci_contains(text, "vbscript:") ||
                    ci_contains(text, "javascript:"))) {
            what = "mshta remote/script execution";
        } else if (ci_contains(text, "certutil") &&
                   (ci_contains(text, "urlcache") || ci_contains(text, "-decode"))) {
            what = "certutil download/decode (LOLBin)";
        } else if (ci_contains(text, "regsvr32") && ci_contains(text, "scrobj")) {
            what = "regsvr32 scrobj.dll (Squiblydoo)";
        } else if (ci_contains(text, "bitsadmin") && ci_contains(text, "/transfer")) {
            what = "bitsadmin remote file transfer (LOLBin)";
        } else if (ci_contains(text, "msiexec") && ci_contains(text, "http")) {
            what = "msiexec remote MSI install";
        } else if ((ci_contains(text, "wscript") || ci_contains(text, "cscript")) &&
                   (ci_contains(text, "http") || ci_contains(text, ".vbs") ||
                    ci_contains(text, ".js"))) {
            what = "wscript/cscript remote/script execution (LOLBin)";
        } else if (ci_contains(text, "wmic") &&
                   (ci_contains(text, "process call create") ||
                    ci_contains(text, "os get") )) {
            what = "wmic process creation (LOLBin)";
        } else if (ci_contains(text, "rundll32") &&
                   (ci_contains(text, "http") || ci_contains(text, "javascript"))) {
            what = "rundll32 remote/script execution (LOLBin)";
        } else if (ci_contains(text, "powershell") &&
                   (ci_contains(text, "invoke-restmethod") ||
                    ci_contains(text, "invoke-webrequest") ||
                    ci_contains(text, "iwr ") || ci_contains(text, "irm ") ||
                    ci_contains(text, "iwr\t") || ci_contains(text, "irm\t"))) {
            what = "PowerShell web download (iwr/irm)";
        } else if (ci_contains(text, "forfiles") &&
                   (ci_contains(text, "/p ") || ci_contains(text, "/m ")) &&
                   ci_contains(text, "/c ")) {
            what = "forfiles command execution (LOLBin)";
        } else if (ci_contains(text, "odbcconf") &&
                   (ci_contains(text, "regsvr") || ci_contains(text, "/a "))) {
            what = "odbcconf REGSVR execution (LOLBin)";
        } else if (ci_contains(text, "ms-appinstaller:") ||
                   (ci_contains(text, "appinstaller") &&
                    ci_contains(text, "http"))) {
            what = "ms-appinstaller URI bypass (ClickFix 2025)";
        } else if (ci_contains(text, "osascript") &&
                   (ci_contains(text, "do shell script") ||
                    ci_contains(text, "http") ||
                    ci_contains(text, "curl ") || ci_contains(text, "bash"))) {
            what = "osascript AppleScript shell execution (macOS ClickFix)";
        } else if ((ci_contains(text, "python") || ci_contains(text, "python3")) &&
                   (ci_contains(text, "urllib") || ci_contains(text, "urllib2") ||
                    ci_contains(text, "urlopen") || ci_contains(text, "requests.get")) &&
                   (ci_contains(text, "exec(") || ci_contains(text, "eval(") ||
                    ci_contains(text, ".read()") || ci_contains(text, "subprocess"))) {
            what = "Python download-execute one-liner";
        } else if (ci_contains(text, "regasm") &&
                   (ci_contains(text, "http") || ci_contains(text, ".dll") ||
                    ci_contains(text, ".exe"))) {
            what = "regasm.exe .NET assembly execution (LOLBin)";
        } else if (ci_contains(text, "installutil") &&
                   ci_contains(text, "http")) {
            what = "installutil.exe .NET AppDomain execution (LOLBin)";
        } else if (ci_contains(text, "msiexec") &&
                   (ci_contains(text, "/q") || ci_contains(text, "/quiet")) &&
                   ci_contains(text, "http")) {
            what = "msiexec silent remote MSI install (ClickFix)";
        } else if (ci_contains(text, "expand") &&
                   (ci_contains(text, "http") || ci_contains(text, "\\\\")) &&
                   ci_contains(text, "-f:")) {
            what = "expand.exe remote file download (LOLBin)";
        } else if (ci_contains(text, "curl") &&
                   (ci_contains(text, "-o ") || ci_contains(text, "--output ")) &&
                   (ci_contains(text, ".exe") || ci_contains(text, ".ps1") ||
                    ci_contains(text, ".dll") || ci_contains(text, ".bat"))) {
            what = "curl download of executable";
        } else if ((ci_contains(text, "wget") || ci_contains(text, "invoke-webrequest")) &&
                   (ci_contains(text, ".exe") || ci_contains(text, ".ps1") ||
                    ci_contains(text, ".dll") || ci_contains(text, ".bat"))) {
            what = "download of executable via wget/iwr";
        }
        if (what) {
            v.signals |= PASTE_WINDOWS_LOLBIN;
            v.score += 45;
            if (v.n_reasons < HLSE_PASTE_MAX_REASONS)
                snprintf(v.reasons[v.n_reasons++], sizeof(v.reasons[0]),
                    "P8: Windows ClickFix / LOLBin — %s", what);
        }
    }

    /* P9: Reverse shell payloads (Unix) */
    {
        int is_revshell = 0;
        /* bash /dev/tcp redirect: bash -i >& /dev/tcp/IP/PORT 0>&1 */
        if (strstr(text, "/dev/tcp/") || strstr(text, "/dev/udp/"))
            is_revshell = 1;
        /* nc / ncat / netcat reverse shell: nc -e or mkfifo pipe */
        if (!is_revshell &&
            (strstr(text, "nc ") || strstr(text, "ncat ") ||
             strstr(text, "netcat ")) &&
            (strstr(text, " -e ") || strstr(text, "mkfifo")))
            is_revshell = 1;
        /* Python socket reverse shell */
        if (!is_revshell &&
            (strstr(text, "socket.") || strstr(text, "connect(")) &&
            (strstr(text, "subprocess") || strstr(text, "os.dup2") ||
             strstr(text, "pty.spawn")))
            is_revshell = 1;
        /* socat reverse shell */
        if (!is_revshell &&
            strstr(text, "socat") &&
            (strstr(text, "EXEC:") || strstr(text, "TCP:")))
            is_revshell = 1;
        if (is_revshell) {
            v.score += 60;
            if (v.n_reasons < HLSE_PASTE_MAX_REASONS)
                snprintf(v.reasons[v.n_reasons++], sizeof(v.reasons[0]),
                    "P9: Reverse shell payload (/dev/tcp, nc -e, socat)");
        }
    }

    /* Compound amplifiers */
    if ((v.signals & PASTE_CURL_PIPE_SH) &&
        (v.signals & PASTE_HIDDEN_NEWLINE)) {
        v.score += 15;
        if (v.n_reasons < HLSE_PASTE_MAX_REASONS)
            snprintf(v.reasons[v.n_reasons++], sizeof(v.reasons[0]),
                "Compound: download+pipe+hidden newline — sophisticated "
                "pastejacking attack");
    }
    if ((v.signals & PASTE_SUDO_INJECTION) &&
        (v.signals & PASTE_CURL_PIPE_SH)) {
        v.score += 15;
        if (v.n_reasons < HLSE_PASTE_MAX_REASONS)
            snprintf(v.reasons[v.n_reasons++], sizeof(v.reasons[0]),
                "Compound: sudo + remote code = root-level pastejacking");
    }

    /* P10: Persistence injection — SSH key, crontab, shell startup modification.
     * Appending to ~/.ssh/authorized_keys or (cron|at)tab in a paste is a
     * classic post-exploitation persistence vector; almost never legitimate
     * in a clipboard context. Shell startup modification also covered.     */
    {
        int is_persist = 0;
        const char *why = NULL;
        if ((strstr(text, ".ssh/authorized_keys") &&
             (strstr(text, ">>") || strstr(text, "echo "))) ||
            strstr(text, "> ~/.ssh/authorized_keys")) {
            is_persist = 1; why = "SSH authorized_keys injection";
        } else if (strstr(text, "crontab") &&
                   (strstr(text, "crontab -l") ||
                    strstr(text, "(crontab") ||
                    strstr(text, "| crontab") ||
                    strstr(text, "|crontab"))) {
            is_persist = 1; why = "crontab persistence injection";
        } else if ((strstr(text, ".bashrc") || strstr(text, ".bash_profile") ||
                    strstr(text, ".zshrc")  || strstr(text, ".profile")) &&
                   (strstr(text, "curl ") || strstr(text, "wget ") ||
                    strstr(text, "/dev/tcp") || strstr(text, "bash -i"))) {
            is_persist = 1; why = "shell startup file backdoor injection";
        }
        if (is_persist) {
            v.score += 50;
            if (v.n_reasons < HLSE_PASTE_MAX_REASONS)
                snprintf(v.reasons[v.n_reasons++], sizeof(v.reasons[0]),
                    "P10: Persistence injection — %s", why);
        }
    }

    if (v.score > 100) v.score = 100;
    return v;
}

/* ═══════════════════════════════════════════════════════════════════════
 * S3: Network Safety Check (ARP / DNS / Gateway integrity)
 *
 * Pure read from /proc and /etc — no network access, no raw sockets.
 *
 *   N1. ARP poisoning    — duplicate MACs for different IPs
 *   N2. Gateway change   — default gw differs from baseline
 *   N3. DNS hijacking    — /etc/resolv.conf points to suspicious IP
 *   N4. Hosts file       — banking/exchange domains redirected
 * ═══════════════════════════════════════════════════════════════════════ */

NetworkVerdict
hlse_check_network(void) {
    NetworkVerdict v;
    memset(&v, 0, sizeof(v));

    /* N1: ARP table — detect duplicate MACs (ARP spoofing indicator) */
    {
        FILE *fp = hlse_open_system_file("/proc/net/arp");
        if (fp) {
            char line[256];
            char ips[64][16];     /* up to 64 ARP entries */
            char macs[64][18];
            int count = 0;
            int i, j;

            /* Skip header */
            if (fgets(line, sizeof(line), fp)) {
                while (fgets(line, sizeof(line), fp) && count < 64) {
                    /* Format: IP HW_type Flags HW_address Mask Device */
                    char ip[16], mac[18];
                    if (sscanf(line, "%15s %*s %*s %17s", ip, mac) == 2) {
                        /* Skip incomplete entries (00:00:00:00:00:00) */
                        if (strcmp(mac, "00:00:00:00:00:00") == 0) continue;
                        snprintf(ips[count], sizeof(ips[0]), "%s", ip);
                        snprintf(macs[count], sizeof(macs[0]), "%s", mac);
                        count++;
                    }
                }
            }
            fclose(fp);

            /* Check for duplicate MACs with different IPs */
            for (i = 0; i < count; i++) {
                for (j = i + 1; j < count; j++) {
                    if (strcmp(macs[i], macs[j]) == 0 &&
                        strcmp(ips[i], ips[j]) != 0) {
                        v.score += 60;
                        if (v.n_reasons < HLSE_NET_MAX_REASONS) {
                            snprintf(v.reasons[v.n_reasons], 255,
                                "N1: ARP POISONING — MAC %.17s shared by "
                                "%.15s and %.15s",
                                macs[i], ips[i], ips[j]);
                            v.n_reasons++;
                        }
                    }
                }
            }
        }
    }

    /* N2: Default-route integrity — multiple default routes with identical
     * metric indicate routing injection (malware or rogue DHCP).
     * Reads /proc/net/route; all values are hex little-endian.           */
    {
        FILE *fp = hlse_open_system_file("/proc/net/route");
        if (fp) {
            char line[256];
            unsigned long gw_hex[8];
            int gw_metric[8];
            int gw_count = 0;
            int i, j;

            if (fgets(line, sizeof(line), fp)) { /* skip header */
                while (fgets(line, sizeof(line), fp) && gw_count < 8) {
                    char iface[16];
                    unsigned long dest, gw, flags;
                    int metric;
                    unsigned long mask;
                    /* Iface Dest Gateway Flags RefCnt Use Metric Mask ... */
                    if (sscanf(line, "%15s %lx %lx %lx %*d %*d %d %lx",
                               iface, &dest, &gw, &flags, &metric, &mask) == 6) {
                        /* Default route: Destination==0, Flags has GATEWAY(0x2) */
                        if (dest == 0UL && (flags & 0x2UL)) {
                            gw_hex[gw_count]    = gw;
                            gw_metric[gw_count] = metric;
                            gw_count++;
                        }
                    }
                }
            }
            fclose(fp);

            /* Flag if multiple default routes share the lowest metric */
            if (gw_count >= 2) {
                int min_metric = gw_metric[0];
                int dup = 0;
                for (i = 1; i < gw_count; i++)
                    if (gw_metric[i] < min_metric) min_metric = gw_metric[i];
                for (i = 0; i < gw_count; i++)
                    if (gw_metric[i] == min_metric) dup++;
                if (dup >= 2) {
                    /* Find the two conflicting gateway IPs */
                    unsigned long ga = 0, gb = 0;
                    for (i = 0; i < gw_count && ga == 0; i++)
                        if (gw_metric[i] == min_metric) ga = gw_hex[i];
                    for (j = i; j < gw_count && gb == 0; j++)
                        if (gw_metric[j] == min_metric && gw_hex[j] != ga)
                            gb = gw_hex[j];
                    v.score += 55;
                    if (v.n_reasons < HLSE_NET_MAX_REASONS) {
                        if (gb) {
                            /* Decode hex little-endian to dotted-decimal */
                            snprintf(v.reasons[v.n_reasons++],
                                sizeof(v.reasons[0]),
                                "N2: ROUTING INJECTION — %d default routes share "
                                "metric %d (possible MITM: gateways "
                                "%lu.%lu.%lu.%lu vs %lu.%lu.%lu.%lu)",
                                dup, min_metric,
                                ga & 0xFF, (ga>>8) & 0xFF,
                                (ga>>16) & 0xFF, (ga>>24) & 0xFF,
                                gb & 0xFF, (gb>>8) & 0xFF,
                                (gb>>16) & 0xFF, (gb>>24) & 0xFF);
                        } else {
                            snprintf(v.reasons[v.n_reasons++],
                                sizeof(v.reasons[0]),
                                "N2: ROUTING INJECTION — %d default routes share "
                                "metric %d (possible MITM)", dup, min_metric);
                        }
                    }
                }
            }
        }
    }

    /* N3: DNS resolver check */
    {
        FILE *fp = hlse_open_system_file("/etc/resolv.conf");
        if (fp) {
            char line[256];
            int ns_count = 0;

            while (fgets(line, sizeof(line), fp)) {
                char ip[64];
                if (sscanf(line, "nameserver %63s", ip) == 1) {
                    ns_count++;
                    /* Known safe DNS: major public resolvers + RFC-1918 +
                     * 127.0.0.53 (systemd-resolved), 149.112 (Quad9),
                     * 208.67 (OpenDNS), 64.6 (Verisign), 185.228 (CleanBrowsing),
                     * 94.140 (AdGuard), 156.154 (Neustar/UltraDNS)             */
                    int is_known = (
                        strcmp(ip, "1.1.1.1") == 0 ||
                        strcmp(ip, "1.0.0.1") == 0 ||
                        strcmp(ip, "8.8.8.8") == 0 ||
                        strcmp(ip, "8.8.4.4") == 0 ||
                        strcmp(ip, "9.9.9.9") == 0 ||
                        strcmp(ip, "149.112.112.112") == 0 ||
                        strcmp(ip, "208.67.222.222") == 0 ||
                        strcmp(ip, "208.67.220.220") == 0 ||
                        strcmp(ip, "64.6.64.6") == 0 ||
                        strcmp(ip, "64.6.65.6") == 0 ||
                        strcmp(ip, "185.228.168.9") == 0 ||
                        strcmp(ip, "185.228.169.9") == 0 ||
                        strcmp(ip, "94.140.14.14") == 0 ||  /* AdGuard */
                        strcmp(ip, "94.140.15.15") == 0 ||
                        strcmp(ip, "94.140.14.15") == 0 ||
                        strcmp(ip, "156.154.70.1") == 0 ||  /* Neustar/UltraDNS */
                        strcmp(ip, "156.154.71.1") == 0 ||
                        strcmp(ip, "127.0.0.1") == 0 ||
                        strcmp(ip, "127.0.0.53") == 0 ||
                        strcmp(ip, "::1") == 0 ||
                        strcmp(ip, "2606:4700:4700::1111") == 0 || /* CF IPv6 */
                        strcmp(ip, "2606:4700:4700::1001") == 0 ||
                        strcmp(ip, "2001:4860:4860::8888") == 0 || /* Google IPv6 */
                        strcmp(ip, "2001:4860:4860::8844") == 0 ||
                        strcmp(ip, "2620:fe::fe") == 0 ||          /* Quad9 IPv6 */
                        strcmp(ip, "2620:fe::9") == 0 ||
                        strncmp(ip, "10.", 3) == 0 ||
                        strncmp(ip, "192.168.", 8) == 0 ||
                        (strncmp(ip, "172.", 4) == 0 &&
                         atoi(ip + 4) >= 16 && atoi(ip + 4) <= 31)); /* RFC-1918 only */
                    if (!is_known) {
                        v.score += 20;
                        if (v.n_reasons < HLSE_NET_MAX_REASONS)
                            snprintf(v.reasons[v.n_reasons++],
                                sizeof(v.reasons[0]),
                                "N3: Unfamiliar DNS resolver: %s "
                                "(verify this is your ISP or VPN)", ip);
                    }
                }
            }
            fclose(fp);

            if (ns_count == 0) {
                v.score += 15;
                if (v.n_reasons < HLSE_NET_MAX_REASONS)
                    snprintf(v.reasons[v.n_reasons++], sizeof(v.reasons[0]),
                        "N3: No DNS nameserver configured in resolv.conf");
            }
        }
    }

    /* N4: /etc/hosts banking/exchange redirect check */
    {
        FILE *fp = hlse_open_system_file("/etc/hosts");
        if (fp) {
            char line[512];
            const char *sensitive_domains[] = {
                /* US banks */
                "chase.com", "bankofamerica.com", "wellsfargo.com",
                "citi.com", "usbank.com", "capitalone.com", "pnc.com",
                /* Payment */
                "paypal.com", "venmo.com", "cashapp.com", "zelle.com",
                "stripe.com", "square.com",
                /* Crypto exchanges */
                "coinbase.com", "binance.com", "kraken.com",
                "blockchain.com", "bitfinex.com", "bybit.com",
                "okx.com", "kucoin.com", "crypto.com", "gate.io",
                /* Crypto wallets / DeFi */
                "metamask.io", "ledger.com", "trezor.io",
                "exodus.com", "trustwallet.com", "phantom.app",
                /* EU neobanks */
                "revolut.com", "wise.com", "n26.com", "ing.com",
                "transferwise.com",
                /* JP banks */
                "smbc.co.jp", "mufg.jp", "mizuhobank.co.jp",
                "rakuten-bank.co.jp", "japanpost.jp",
                /* KR banks */
                "kbstar.com", "ibk.co.kr", "nonghyup.com", "shinhan.com",
                /* CN payment */
                "alipay.com", "pay.weixin.qq.com",
                NULL
            };

            while (fgets(line, sizeof(line), fp)) {
                int di;
                if (line[0] == '#' || line[0] == '\n') continue;
                /* Skip localhost entries */
                if (strstr(line, "127.0.0.1") && strstr(line, "localhost"))
                    continue;
                if (strstr(line, "::1") && strstr(line, "localhost"))
                    continue;

                for (di = 0; sensitive_domains[di]; di++) {
                    if (strstr(line, sensitive_domains[di])) {
                        v.score += 50;
                        if (v.n_reasons < HLSE_NET_MAX_REASONS)
                            snprintf(v.reasons[v.n_reasons++],
                                sizeof(v.reasons[0]),
                                "N4: HOSTS FILE REDIRECT — banking domain "
                                "'%s' redirected (possible pharming attack)",
                                sensitive_domains[di]);
                        break;
                    }
                }
            }
            fclose(fp);
        }
    }

    if (v.score > 100) v.score = 100;
    return v;
}
