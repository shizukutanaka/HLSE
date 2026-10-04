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
    /* Highest-download infra packages — every one has had a documented
     * typosquat incident (colourama→colorama PyPI 2017, python3-dateutil
     * shipped malware Dec 2019, urllib3/requests-family dist-1 lures)   */
    "colorama", "urllib3", "six", "certifi", "idna",
    "charset-normalizer", "python-dateutil", "tqdm", "pyjwt",
    "markupsafe", "werkzeug", "packaging", "attrs",
    "botocore", "rsa", "pygments", "docutils", "humanize",
    "opencv-python", "importlib-metadata",
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
    /* Documented npm supply-chain victims — ua-parser-js (Oct 2021
     * cryptominer/RAT hijack), coa+rc (Nov 2021), node-ipc (Mar 2022
     * sabotage), event-stream (flatmap-stream payload 2018), colors+
     * faker (Jan 2022 maintainer sabotage) — typosquats of these are
     * worth flagging because the real packages are ubiquitous      */
    "ua-parser-js", "coa", "rc", "node-ipc", "event-stream",
    "colors", "faker", "bootstrap", "jquery", "core-js",
    "tslib", "is-core-module", "inherits", "safe-buffer",
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
    int best_dist = 99, best_idx = -1;

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
                hlse_sanitize_display(v.reason);
                return v;
            }

            dist = dl_distance(norm, norm_ref);
            /* dist 1-2: typosquat band. dist 3: slopsquat advisory — a
             * name that close to a top package but absent from the
             * snapshot is exactly where AI-hallucinated names land and
             * where attackers register them. Low score: LOG, not ALERT. */
            if (dist <= 3 && dist > 0 &&
                v.n_matches < HLSE_SUPPLY_MAX_MATCHES)
            {
                int score_add = (dist == 1) ? 50 : (dist == 2) ? 35 : 15;
                snprintf(v.matches[v.n_matches].legit_name,
                         sizeof(v.matches[0].legit_name), "%s", pkgs[pi]);
                snprintf(v.matches[v.n_matches].registry,
                         sizeof(v.matches[0].registry), "%s",
                         REGISTRIES[ri].name);
                v.matches[v.n_matches].distance = dist;
                v.n_matches++;
                if (dist < best_dist) { best_dist = dist; best_idx = v.n_matches - 1; }

                if (score_add > v.score) v.score = score_add;
            }
        }
    }

    /* Amplifier: a single distance-1 neighbour and NO other dist≤2 match →
     * very likely typosquat. Dist-3 slopsquat matches are advisory only:
     * they must not dilute the amplifier (reqeusts ~ requests@1 plus a
     * reqwest@3 still fires) nor inflate the near-match count that gates
     * it (reqests ~ requests@1 + reqwest@2 stays at the 2-match ALERT
     * band). */
    {
        int n_close = 0, i;
        for (i = 0; i < v.n_matches; i++)
            if (v.matches[i].distance <= 2) n_close++;
        if (n_close == 1 && best_dist == 1) {
            v.score = 70;
            snprintf(v.reason, sizeof(v.reason),
                     "Typosquat alert: '%s' is 1 edit from '%s' (%s). "
                     "Did you mean '%s'?",
                     pkg_name, v.matches[best_idx].legit_name,
                     v.matches[best_idx].registry,
                     v.matches[best_idx].legit_name);
        } else if (v.n_matches > 0 && best_dist == 3) {
            snprintf(v.reason, sizeof(v.reason),
                     "Slopsquat candidate: '%s' is 3 edits from '%s' (%s) and "
                     "not a known package — AI-hallucinated names are "
                     "predictable attacker registrations; verify it exists "
                     "before installing",
                     pkg_name, v.matches[best_idx].legit_name,
                     v.matches[best_idx].registry);
        } else if (v.n_matches > 0) {
            snprintf(v.reason, sizeof(v.reason),
                     "Possible typosquat: '%s' is close to %d known package(s)",
                     pkg_name, v.n_matches);
        }
    }

    if (v.score > 100) v.score = 100;
    /* Reason text embeds the caller-supplied package name. */
    hlse_sanitize_display(v.reason);
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
                       strstr(text, "wget ") != NULL ||
                       strstr(text, "fetch ") != NULL ||
                       strstr(text, "lynx ") != NULL);
        int has_pipe_sh = (strstr(text, "| sh") != NULL ||
                          strstr(text, "| bash") != NULL ||
                          strstr(text, "|sh") != NULL ||
                          strstr(text, "|bash") != NULL ||
                          strstr(text, "| sudo") != NULL ||
                          strstr(text, "| /bin/sh") != NULL ||
                          strstr(text, "| /bin/bash") != NULL ||
                          /* interpreter cradles — same RCE class */
                          strstr(text, "| python") != NULL ||
                          strstr(text, "| perl") != NULL ||
                          strstr(text, "| node") != NULL ||
                          strstr(text, "| ruby") != NULL ||
                          strstr(text, "| php") != NULL ||
                          strstr(text, "|pwsh") != NULL ||
                          strstr(text, "| pwsh") != NULL ||
                          strstr(text, "| powershell") != NULL ||
                          strstr(text, "| zsh") != NULL ||
                          strstr(text, "| fish") != NULL ||
                          strstr(text, "| dash") != NULL ||
                          strstr(text, "| ksh") != NULL);
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

    /* P9: Destructive commands — the classic baited one-liner */
    if (strstr(text, "rm -rf /") || strstr(text, "rm -rf ~") ||
        strstr(text, "rm -rf $HOME") || strstr(text, "rm -fr /") ||
        strstr(text, ":(){ :|:") ||
        strstr(text, "mkfs.") || strstr(text, "mkfs /") ||
        strstr(text, "mkfs -") || strstr(text, "mke2fs /") ||
        strstr(text, "of=/dev/sd") || strstr(text, "of=/dev/nvme") ||
        strstr(text, "of=/dev/hd") || strstr(text, "of=/dev/vd") ||
        strstr(text, "of=/dev/mmc") || strstr(text, "of=/dev/xvd") ||
        strstr(text, "if=/dev/mem") || strstr(text, "if=/dev/kmem") ||
        strstr(text, "if=/dev/sd") || strstr(text, "if=/dev/nvme") ||
        strstr(text, "blkdiscard /") || strstr(text, "blkdiscard -") ||
        strstr(text, "shred ") || strstr(text, "> /dev/sd") ||
        strstr(text, "chmod -R 777") || strstr(text, "chmod -R 777 /") ||
        /* c238: storage/volume/RAID destruction */
        strstr(text, "nvme format") || strstr(text, "nvme sanitize") ||
        strstr(text, "sg_sanitize") || strstr(text, "sg_format") ||
        strstr(text, "sg_write_buffer") ||
        (strstr(text, "hdparm") &&
         (strstr(text, "--security-erase") ||
          strstr(text, "--security-disable"))) ||
        (strstr(text, "storcli") && strstr(text, "delete")) ||
        (strstr(text, "perccli") && strstr(text, "delete")) ||
        (strstr(text, "megacli") &&
         (strstr(text, "-CfgLdDel") || strstr(text, "-CfgClr"))) ||
        (strstr(text, "arcconf") && strstr(text, "delete")) ||
        (strstr(text, "hpssacli") && strstr(text, "delete")) ||
        (strstr(text, "omconfig") && strstr(text, "action=delete")) ||
        (strstr(text, "mdadm") &&
         (strstr(text, "--stop") || strstr(text, "--zero-superblock") ||
          strstr(text, "--fail") || strstr(text, "--remove"))) ||
        strstr(text, "pvremove ") || strstr(text, "vgremove ") ||
        strstr(text, "lvremove ") || strstr(text, "lvreduce ") ||
        strstr(text, "dmsetup remove") ||
        (ci_contains(text, "cryptsetup") &&
         (ci_contains(text, "erase") || ci_contains(text, "luksformat"))) ||
        strstr(text, "zfs destroy") || strstr(text, "zpool destroy") ||
        strstr(text, "zpool labelclear") ||
        (strstr(text, "btrfs") &&
         (strstr(text, "subvolume delete") ||
          strstr(text, "device delete"))) ||
        strstr(text, "sfdisk --delete") || strstr(text, "sfdisk /") ||
        (strstr(text, "parted") &&
         (strstr(text, " rm ") || strstr(text, "mklabel"))) ||
        strstr(text, "fdisk /") || strstr(text, "gdisk /") ||
        strstr(text, "cgdisk /") ||
        (strstr(text, "camcontrol") &&
         (strstr(text, "format") || strstr(text, "sanitize"))) ||
        (strstr(text, "vdo ") &&
         (strstr(text, "remove") || strstr(text, "delete") ||
          strstr(text, "stop"))) ||
        (strstr(text, "stratis") && strstr(text, "destroy")) ||
        /* c242: BSD partition/crypto destruction + mkfs-family
         * newfs aliases */
        (ci_contains(text, "gpart") &&
         (ci_contains(text, "destroy") || ci_contains(text, "delete") ||
          ci_contains(text, "wipe"))) ||
        (ci_contains(text, "geli") &&
         (ci_contains(text, "kill") || ci_contains(text, "clear") ||
          ci_contains(text, "detach"))) ||
        (ci_contains(text, "gbde") &&
         (ci_contains(text, "destroy") || ci_contains(text, "nuke") ||
          ci_contains(text, "init"))) ||
        (ci_contains(text, "newfs") && ci_contains(text, "/dev/")) ||
        (ci_contains(text, "growfs") && ci_contains(text, "-y")) ||
        /* c240: macOS + tape/firmware/raw-sector destruction */
        (ci_contains(text, "diskutil") &&
         (ci_contains(text, "erasedisk") || ci_contains(text, "erasevolume") ||
          ci_contains(text, "zerodisk") || ci_contains(text, "secureerase") ||
          ci_contains(text, "partitiondisk") ||
          ci_contains(text, "deletecontainer") ||
          ci_contains(text, "deletevolume") ||
          ci_contains(text, "apfs delete") || ci_contains(text, "apfs erase"))) ||
        ci_contains(text, "sg_erase") ||
        (ci_contains(text, "hdparm") &&
         (ci_contains(text, "--write-sector") ||
          ci_contains(text, "--fwdownload") ||
          ci_contains(text, "--dco-identify") ||
          ci_contains(text, "--dco-restore") ||
          ci_contains(text, "--trim-sector-ranges"))) ||
        (ci_contains(text, "mt ") &&
         (ci_contains(text, " -f") &&
          (ci_contains(text, "erase") || ci_contains(text, "compression"))))) {
        v.signals |= PASTE_DESTRUCTIVE;
        v.score += 60;
        if (v.n_reasons < HLSE_PASTE_MAX_REASONS)
            snprintf(v.reasons[v.n_reasons++], sizeof(v.reasons[0]),
                "P9: Destructive payload — recursive delete/disk wipe/"
                "fork bomb");
    }

    /* P10: Credential-file access — reading private keys/credentials is
     * the pre-exfiltration step of pastejacking */
    if (strstr(text, ".ssh/id_") || strstr(text, "id_rsa") ||
        strstr(text, "id_ed25519") || strstr(text, ".ssh/authorized_keys") ||
        strstr(text, ".aws/credentials") || strstr(text, ".aws/config") ||
        strstr(text, ".gnupg/") || strstr(text, ".kube/config") ||
        strstr(text, ".docker/config.json") || strstr(text, ".netrc") ||
        strstr(text, ".git-credentials") || strstr(text, "shadow") ||
        strstr(text, "/etc/passwd") || strstr(text, ".pgpass") ||
        strstr(text, ".my.cnf") || strstr(text, ".pypirc") ||
        strstr(text, ".s3cfg") || strstr(text, ".boto") ||
        strstr(text, ".env") || strstr(text, "master.passwd") ||
        strstr(text, "/etc/security") || strstr(text, "/etc/group") ||
        strstr(text, "/etc/sudoers") || strstr(text, "sudoers.d") ||
        strstr(text, "/etc/login.defs") || strstr(text, "config/gcloud") ||
        strstr(text, ".azure") || strstr(text, "_history") ||
        strstr(text, ".viminfo") || strstr(text, ".lesshst") ||
        strstr(text, ".wget-hsts") || strstr(text, "auth.log") ||
        strstr(text, "/var/log/secure") || strstr(text, "/var/log/btmp") ||
        strstr(text, "/var/log/wtmp") || strstr(text, "/var/log/lastlog") ||
        strstr(text, "/var/log/faillog")) {
        v.signals |= PASTE_CRED_ACCESS;
        v.score += 40;
        if (v.n_reasons < HLSE_PASTE_MAX_REASONS)
            snprintf(v.reasons[v.n_reasons++], sizeof(v.reasons[0]),
                "P10: Credential/key file access — private key, cloud "
                "creds, or auth database read (pre-exfiltration)");
    }

    /* P11: Persistence writes — appending to rc/config/ssh/crontab
     * installs the payload to run on every login. Copy/move/install
     * verbs only fire on system-level targets (routine home-dir
     * backups must stay clean).                                 */
    if (((strstr(text, ">>") || strstr(text, "echo ") ||
          strstr(text, "crontab") || strstr(text, "at now") ||
          strstr(text, "systemctl enable") || strstr(text, "launchctl load") ||
          strstr(text, "tee /") || strstr(text, "tee .") ||
          strstr(text, "tee ~") || strstr(text, "tee -") ||
          strstr(text, "curl ") ||
          strstr(text, "wget ")) &&
         (strstr(text, ".bashrc") || strstr(text, ".zshrc") ||
          strstr(text, ".profile") || strstr(text, "authorized_keys") ||
          strstr(text, "crontab") || strstr(text, "systemctl enable") ||
          strstr(text, "launchctl") || strstr(text, "rc.local") ||
          strstr(text, ".xinitrc") || strstr(text, ".zshenv") ||
          strstr(text, ".bash_profile") || strstr(text, ".bash_login") ||
          strstr(text, ".zprofile") || strstr(text, ".zlogin") ||
          strstr(text, ".xprofile") || strstr(text, ".pam_environment") ||
          strstr(text, "ld.so.preload") || strstr(text, "cron.d") ||
          strstr(text, "spool/cron") || strstr(text, "autostart") ||
          strstr(text, "systemd/system") || strstr(text, "inetd") ||
          strstr(text, "xinetd") || strstr(text, "/etc/profile") ||
          strstr(text, "profile.d") || strstr(text, "init.d") ||
          strstr(text, ".forward") || strstr(text, ".ssh/config") ||
          strstr(text, "/etc/zshrc") || strstr(text, "/etc/zprofile") ||
          strstr(text, "/etc/zshenv") || strstr(text, ".ssh/rc") ||
          strstr(text, "motd.d") || strstr(text, "pam.d") ||
          strstr(text, "sshd_config") || strstr(text, "rc.d") ||
          strstr(text, "systemd/user") || strstr(text, "udev/rules") ||
          strstr(text, "sysctl.d") || strstr(text, "ld.so.conf") ||
          strstr(text, "pacman.d") || strstr(text, "/etc/environment") ||
          strstr(text, "/etc/timezone") || strstr(text, "/etc/hosts") ||
          strstr(text, "resolv.conf") || strstr(text, "nsswitch") ||
          strstr(text, ".vimrc") || strstr(text, ".tmux.conf") ||
          strstr(text, "config.fish") || strstr(text, ".netrc") ||
          strstr(text, ".rhosts") || strstr(text, "hosts.equiv") ||
          strstr(text, ".npmrc") || strstr(text, ".curlrc") ||
          strstr(text, ".gitconfig") || strstr(text, ".xsession") ||
          strstr(text, ".bash_logout") || strstr(text, ".zlogout") ||
          strstr(text, "ssh_config") || strstr(text, ".gtkrc") ||
          strstr(text, ".Xresources") || strstr(text, ".xmodmaprc") ||
          strstr(text, ".inputrc") || strstr(text, ".screenrc") ||
          strstr(text, ".muttrc") || strstr(text, ".mailrc") ||
          strstr(text, ".procmailrc") || strstr(text, ".pinerc") ||
          strstr(text, ".lynxrc") || strstr(text, ".wgetrc") ||
          strstr(text, ".git-crypt") || strstr(text, ".config/git") ||
          strstr(text, ".gnomerc") || strstr(text, ".kderc") ||
          strstr(text, "kdeglobals") || strstr(text, "kglobalshortcutsrc") ||
          strstr(text, "kwinrc") || strstr(text, ".config/pulse") ||
          strstr(text, ".config/systemd") ||
          strstr(text, ".local/share/applications") ||
          strstr(text, "environment.d") || strstr(text, ".ssh/environment") ||
          strstr(text, ".ssh/sshrc") ||
          strstr(text, "native-messaging-hosts") ||
          strstr(text, "NativeMessagingHosts") ||
          strstr(text, ".vscode/extensions") || strstr(text, ".config/Code") ||
          strstr(text, ".gcloud") || strstr(text, "sources.list") ||
          strstr(text, "apt/preferences") || strstr(text, "apt.conf.d") ||
          strstr(text, "yum.repos.d") || strstr(text, "modprobe.d") ||
          strstr(text, "sysctl.d") || strstr(text, "polkit-1") ||
          strstr(text, "dbus-1") || strstr(text, "sudoers.d") ||
          strstr(text, "spool/cron") || strstr(text, "cron.d") ||
          strstr(text, "daemon.json") || strstr(text, ".git/hooks") ||
          strstr(text, ".gitmodules") || strstr(text, ".gitattributes") ||
          strstr(text, "known_hosts") || strstr(text, "profile.d") ||
          strstr(text, ".pam_environment") || strstr(text, "modules-load.d") ||
          strstr(text, "tmpfiles.d") || strstr(text, "binfmt.d") ||
          strstr(text, "hwdb.d") || strstr(text, "firewalld") ||
          strstr(text, "fail2ban") || strstr(text, "logrotate.d") ||
          strstr(text, "rsyslog.d") || strstr(text, "audit/rules.d") ||
          strstr(text, "auditd.conf") || strstr(text, "ld.so.preload") ||
          strstr(text, "fstab") || strstr(text, "crypttab") ||
          strstr(text, "exports") || strstr(text, "netgroup") ||
          strstr(text, "auto.master") || strstr(text, "hostapd") ||
          strstr(text, "wpa_supplicant") || strstr(text, "dhclient") ||
          strstr(text, "dhcpcd") || strstr(text, "netplan") ||
          strstr(text, "systemd/network") || strstr(text, "resolvconf") ||
          strstr(text, "hosts.allow") || strstr(text, "hosts.deny") ||
          strstr(text, "ipsec.conf") || strstr(text, "ppp/peers") ||
          strstr(text, "wireguard") || strstr(text, "wg0.conf") ||
          strstr(text, "openvpn") || strstr(text, "vtund") ||
          strstr(text, "dnsmasq") || strstr(text, "unbound.conf") ||
          strstr(text, "named.conf") || strstr(text, "msmtprc") ||
          strstr(text, "fetchmailrc") || strstr(text, "aliases") ||
          strstr(text, "mailname") || strstr(text, "main.cf") ||
          strstr(text, "master.cf") || strstr(text, "postfix") ||
          strstr(text, "dovecot") || strstr(text, "saslauthd") ||
          strstr(text, "opendkim") || strstr(text, ".bash_profile") ||
          strstr(text, ".ssh/rc") || strstr(text, ".xinitrc") ||
          strstr(text, ".xprofile") || strstr(text, ".xserverrc") ||
          strstr(text, ".pam.d") || strstr(text, "pam.d"))) ||
        ((strstr(text, "cp ") || strstr(text, "mv ") ||
          strstr(text, "install ")) &&
         (strstr(text, "cron.d") || strstr(text, "spool/cron") ||
          strstr(text, "systemd/system") || strstr(text, "inetd") ||
          strstr(text, "xinetd") || strstr(text, "init.d") ||
          strstr(text, "/etc/profile") || strstr(text, "profile.d") ||
          strstr(text, "ld.so") || strstr(text, "rc.local") ||
          strstr(text, "autostart") || strstr(text, "authorized_keys")))) {
        v.signals |= PASTE_PERSIST_WRITE;
        v.score += 45;
        if (v.n_reasons < HLSE_PASTE_MAX_REASONS)
            snprintf(v.reasons[v.n_reasons++], sizeof(v.reasons[0]),
                "P11: Persistence write — appends/enables code to run "
                "on every login or boot");
    }

    /* P12: eval/exec of fetched content — the non-pipe form of the
     * download cradle (P2 only catches the `| sh` shape) */
    if ((strstr(text, "eval") || strstr(text, "exec") ||
         ci_contains(text, "source ") || ci_contains(text, ". /") ||
         strstr(text, "sh <(")) &&
        (strstr(text, "$(") || strstr(text, "`") ||
         strstr(text, "curl") || strstr(text, "wget") ||
         strstr(text, "fetch"))) {
        v.signals |= PASTE_EVAL_FETCH;
        v.score += 45;
        if (v.n_reasons < HLSE_PASTE_MAX_REASONS)
            snprintf(v.reasons[v.n_reasons++], sizeof(v.reasons[0]),
                "P12: Eval/source of fetched content — same RCE class as "
                "the pipe-to-shell cradle without the pipe");
    }

    /* P12b: download-then-execute chaining — `curl x > s && bash s`,
     * `wget x; sh s`, `curl x && sudo bash s`. P2 needs a literal
     * `| sh` and P12 needs an eval/source verb; the `&&`/`;` exec
     * chain is the third shape of the same download cradle.       */
    if ((strstr(text, "curl ") || strstr(text, "wget ") ||
         strstr(text, "fetch ") || strstr(text, "lynx ") ||
         strstr(text, "scp ") || strstr(text, "sftp ") ||
         strstr(text, "rsync ") || strstr(text, "tftp ") ||
         strstr(text, "base64 -d") || strstr(text, "base64 -D") ||
         strstr(text, "base64 --decode") || strstr(text, "openssl enc") ||
         strstr(text, "openssl aes") || strstr(text, "gpg -d") ||
         strstr(text, "gpg --decrypt") || strstr(text, "xxd -r")) &&
        (strstr(text, "&& bash") || strstr(text, "&& sh") ||
         strstr(text, "&& chmod") || strstr(text, "&& sudo") ||
         strstr(text, "&& ./") || strstr(text, "&& /") ||
         strstr(text, "; bash") || strstr(text, "; sh") ||
         strstr(text, "; ./") ||
         strstr(text, "; chmod") || strstr(text, "; sudo") ||
         strstr(text, "; /"))) {
        v.signals |= PASTE_EVAL_FETCH;
        v.score += 45;
        if (v.n_reasons < HLSE_PASTE_MAX_REASONS)
            snprintf(v.reasons[v.n_reasons++], sizeof(v.reasons[0]),
                "P12b: Download-then-execute chain — remote content "
                "fetched and run via &&/;");
    }

    /* P13: Listener / privilege-escalation one-liners — a bind shell,
     * a staging/exfil HTTP server, or a SUID bit install. These are
     * pastejacked post-exploitation verbs, not admin commands: nobody
     * needs `nc -l` or `chmod +s` in pasted content.            */
    if (strstr(text, "nc -l") || strstr(text, "ncat -l") ||
        strstr(text, "netcat -l") || strstr(text, " -lv") ||
        strstr(text, "ncat --listen") || strstr(text, "nc -p ")) {
        v.signals |= PASTE_LISTENER_PRIV;
        v.score += 45;
        if (v.n_reasons < HLSE_PASTE_MAX_REASONS)
            snprintf(v.reasons[v.n_reasons++], sizeof(v.reasons[0]),
                "P13: Bind-shell listener — 'nc -l'/'ncat -l' opens a "
                "shell port for the attacker to connect back to");
    }
    if (strstr(text, "chmod +s") || strstr(text, "chmod u+s") ||
        strstr(text, "chmod 4") || strstr(text, "chmod 6") ||
        strstr(text, "setuid") || strstr(text, "u+s ")) {
        v.signals |= PASTE_LISTENER_PRIV;
        v.score += 55;
        if (v.n_reasons < HLSE_PASTE_MAX_REASONS)
            snprintf(v.reasons[v.n_reasons++], sizeof(v.reasons[0]),
                "P13: SUID/setuid bit install — pasted privilege "
                "escalation primitive");
    }
    if ((strstr(text, "-m http.server") || strstr(text, "php -S ") ||
         strstr(text, "SimpleHTTPServer") || strstr(text, "busybox httpd") ||
         strstr(text, "-ehttpd")) &&
        (strstr(text, "python") || strstr(text, "php") ||
         strstr(text, "busybox") || strstr(text, "ruby") ||
         strstr(text, "-m "))) {
        v.signals |= PASTE_LISTENER_PRIV;
        v.score += 35;
        if (v.n_reasons < HLSE_PASTE_MAX_REASONS)
            snprintf(v.reasons[v.n_reasons++], sizeof(v.reasons[0]),
                "P13: Ad-hoc HTTP server — staged payload hosting / "
                "loot-exfil listener");
    }

    /* P14: Webshell write — a script tag or web extension plus a request
     * superglobal plus an exec verb is unambiguous webshell vocabulary;
     * nobody pastes that benignly.                                   */
    if (((strstr(text, "<?php") || strstr(text, "<?=") ||
          strstr(text, "<%") || strstr(text, ".php") ||
          strstr(text, ".asp") || strstr(text, ".jsp") ||
          strstr(text, ".cgi") || strstr(text, ".war")) &&
         (strstr(text, "$_GET") || strstr(text, "$_POST") ||
          strstr(text, "$_REQUEST") || strstr(text, "$_COOKIE") ||
          strstr(text, "$_FILES") || strstr(text, "getParameter")) &&
         (strstr(text, "system(") || strstr(text, "eval(") ||
          strstr(text, "exec(") || strstr(text, "shell_exec(") ||
          strstr(text, "passthru(") || strstr(text, "assert(") ||
          strstr(text, "popen(") || strstr(text, "proc_open(") ||
          strstr(text, "getRuntime"))) ||
        ((strstr(text, "<%") || strstr(text, ".asp") ||
          strstr(text, ".aspx")) &&
         (strstr(text, "eval") || strstr(text, "exec")) &&
         strstr(text, "request")) ||
        (strstr(text, "getRuntime().exec") && strstr(text, ".jsp")) ||
        ci_contains(text, "<%eval") || ci_contains(text, "<% eval") ||
        ci_contains(text, "<%execute") || ci_contains(text, "<% execute") ||
        ci_contains(text, "<%createobject") || ci_contains(text, "<% createobject") ||
        ci_contains(text, "<%wscript") || ci_contains(text, "<% wscript")) {
        v.signals |= PASTE_EVAL_FETCH;
        v.score += 50;
        if (v.n_reasons < HLSE_PASTE_MAX_REASONS)
            snprintf(v.reasons[v.n_reasons++], sizeof(v.reasons[0]),
                "P14: Webshell write — script tag/web ext + request "
                "input + exec verb (dropped web shell)");
    }

    /* P15: decode-then-pipe — `base64 -d | sh` / `openssl enc -d | sh`;
     * the decoder replaces the download side of the cradle (P2 needs a
     * fetch verb and P12 needs eval/source).                        */
    if ((strstr(text, "base64 -d") || strstr(text, "base64 -D") ||
         strstr(text, "base64 --decode") || strstr(text, "enc -d") ||
         strstr(text, "openssl enc") || strstr(text, "gpg -d") ||
         strstr(text, "gpg --decrypt")) &&
        (strstr(text, "| sh") || strstr(text, "|sh") ||
         strstr(text, "| bash") || strstr(text, "|bash") ||
         strstr(text, "| python") || strstr(text, "|python") ||
         strstr(text, "| perl") || strstr(text, "| node") ||
         strstr(text, "| pwsh") || strstr(text, "| powershell"))) {
        v.signals |= PASTE_EVAL_FETCH;
        v.score += 45;
        if (v.n_reasons < HLSE_PASTE_MAX_REASONS)
            snprintf(v.reasons[v.n_reasons++], sizeof(v.reasons[0]),
                "P15: Decode-then-pipe — base64/openssl decode piped "
                "to an interpreter");
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
        } else if (ci_contains(text, "pcalua") &&
                   (ci_contains(text, "-a ") || ci_contains(text, "http") ||
                    ci_contains(text, "\\\\"))) {
            what = "pcalua program-launch LOLBin";
        } else if (ci_contains(text, "control.exe") &&
                   ci_contains(text, ".cpl")) {
            what = "control.exe CPL payload load";
        } else if (ci_contains(text, "esentutl") &&
                   ci_contains(text, "/y")) {
            what = "esentutl copy LOLBin (locked-file/ADS exfil)";
        } else if (ci_contains(text, "desktopimgdownldr") &&
                   ci_contains(text, "/lockscreenurl:")) {
            what = "desktopimgdownldr remote download (LOLBIN)";
        } else if (ci_contains(text, "syncappvpublishingserver") &&
                   ci_contains(text, "\";")) {
            what = "syncappvpublishingserver command injection (LOLBin)";
        } else if (ci_contains(text, "hh.exe") &&
                   (ci_contains(text, "http") || ci_contains(text, ".chm"))) {
            what = "hh.exe remote CHM execution (LOLBin)";
        } else if (ci_contains(text, "cmstp") && ci_contains(text, "/s")) {
            what = "cmstp INF-profile execution (LOLBin/UAC bypass)";
        } else if (ci_contains(text, "xwizard") ||
                   (ci_contains(text, "appvlp") &&
                    ci_contains(text, "http"))) {
            what = "xwizard/appvlp proxy execution (LOLBin)";
        } else if ((ci_contains(text, "cscript") ||
                    ci_contains(text, "wscript")) &&
                   ci_contains(text, "//e:")) {
            what = "script-engine extension bypass (//e: exec)";
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
                   (ci_contains(text, "http") || ci_contains(text, "/u ") ||
                    ci_contains(text, "/u\t"))) {
            what = "installutil.exe .NET AppDomain execution (LOLBin)";
        } else if (ci_contains(text, "regsvcs") &&
                   (ci_contains(text, "http") || ci_contains(text, ".dll") ||
                    ci_contains(text, ".exe"))) {
            what = "regsvcs.exe .NET assembly execution (LOLBin)";
        } else if (ci_contains(text, "msfvenom")) {
            what = "msfvenom payload generation (Metasploit)";
        } else if (ci_contains(text, "dnscmd") &&
                   ci_contains(text, "serverlevelplugindll")) {
            what = "dnscmd server-level plugin DLL load (DNS persistence)";
        } else if (ci_contains(text, "curl") &&
                   (ci_contains(text, "-t ") || ci_contains(text, "-t\t") ||
                    ci_contains(text, "--upload"))) {
            what = "curl file upload (data exfiltration channel)";
        } else if (ci_contains(text, "chisel") &&
                   (ci_contains(text, " client") ||
                    ci_contains(text, " server"))) {
            what = "chisel reverse tunnel (covert channel / LOLBin)";
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
        } else if ((ci_contains(text, "iwr ") || ci_contains(text, "irm ") ||
                    ci_contains(text, "iwr\t") || ci_contains(text, "irm\t") ||
                    ci_contains(text, "invoke-webrequest") ||
                    ci_contains(text, "invoke-restmethod")) &&
                   (ci_contains(text, "iex") ||
                    ci_contains(text, "invoke-expression") ||
                    ci_contains(text, "| iex"))) {
            what = "PowerShell download-execute cradle (iwr|iex)";
        } else if ((ci_contains(text, "pip install") ||
                    ci_contains(text, "pip3 install") ||
                    ci_contains(text, "pipx install") ||
                    ci_contains(text, "npm install") ||
                    ci_contains(text, "pnpm add") ||
                    ci_contains(text, "yarn add ") ||
                    ci_contains(text, "gem install ")) &&
                   (ci_contains(text, "--index-url") ||
                    ci_contains(text, "--extra-index-url") ||
                    ci_contains(text, "--registry") ||
                    ci_contains(text, "--source "))) {
            what = "alt-index package install (dependency-confusion channel)";
        } else if (ci_contains(text, "mpcmdrun") &&
                   (ci_contains(text, "-downloadfile") ||
                    ci_contains(text, "-url"))) {
            what = "mpcmdrun.exe file download (Defender LOLBin)";
        } else if (ci_contains(text, "odbcconf") &&
                   (ci_contains(text, "/f") || ci_contains(text, ".rsp") ||
                    ci_contains(text, "regsvr"))) {
            what = "odbcconf config-file DLL execution (LOLBin)";
        } else if (ci_contains(text, "ie4uinit") &&
                   (ci_contains(text, "-") || ci_contains(text, ".inf") ||
                    ci_contains(text, "basesettings"))) {
            what = "ie4uinit INF/settings execution (LOLBin)";
        } else if (ci_contains(text, "ieadvpack") &&
                   ci_contains(text, "/r")) {
            what = "ieadvpack INF execution (LOLBin)";
        } else if (ci_contains(text, "rasautou") &&
                   (ci_contains(text, "-f") || ci_contains(text, ".dll"))) {
            what = "rasautou RAS-dialer execution (LOLBin)";
        } else if (ci_contains(text, "mavinject") &&
                   (ci_contains(text, "injectrunning") ||
                    ci_contains(text, ".dll"))) {
            what = "mavinject.exe DLL injection (LOLBin)";
        } else if ((ci_contains(text, "expand") ||
                    ci_contains(text, "extrac32") ||
                    ci_contains(text, "diantz") ||
                    ci_contains(text, "extexport")) &&
                   (ci_contains(text, "http") || ci_contains(text, "\\\\"))) {
            what = "cabinet/extexport remote file pull (LOLBin)";
        } else if (ci_contains(text, "syncappvpublishingserver") &&
                   (ci_contains(text, "n;") || ci_contains(text, ";") ||
                    ci_contains(text, "cmd") || ci_contains(text, "powershell"))) {
            what = "SyncAppvPublishingServer sync-command execution (LOLBin)";
        } else if (ci_contains(text, "wbadmin") &&
                   (ci_contains(text, "-backuptarget:") ||
                    ci_contains(text, "\\\\"))) {
            what = "wbadmin backup exfiltration to remote share (LOLBin)";
        } else if (ci_contains(text, "finger") &&
                   ci_contains(text, "@")) {
            what = "finger remote data fetch (LOLBin channel)";
        } else if (ci_contains(text, "regini") &&
                   (ci_contains(text, ".ini") || ci_contains(text, "http"))) {
            what = "regini registry-script import (LOLBin)";
        /* Ransomware preparation classics — bcdedit disables recovery /
         * forces safeboot, wevtutil wipes the event logs, wusa installs
         * attacker .msu packages (documented Fin7 vector)              */
        } else if (ci_contains(text, "bcdedit") &&
                   (ci_contains(text, "/set") || ci_contains(text, "safeboot") ||
                    ci_contains(text, "recoveryenabled") ||
                    ci_contains(text, "bootstatuspolicy"))) {
            what = "bcdedit boot/recovery tampering (LOLBin)";
        } else if (ci_contains(text, "wevtutil") &&
                   (ci_contains(text, " cl ") || ci_contains(text, "clear-log") ||
                    ci_contains(text, " cl"))) {
            what = "wevtutil event-log clearing (anti-forensics)";
        } else if (ci_contains(text, "wusa") &&
                   ci_contains(text, ".msu")) {
            what = "wusa .msu package install (LOLBin)";
        /* netsh portproxy tunnels C2 through the host's own network
         * stack; cmdkey /add plants stored credentials for lateral
         * movement, /list enumerates them                            */
        } else if (ci_contains(text, "netsh") &&
                   ci_contains(text, "portproxy")) {
            what = "netsh portproxy tunnel (LOLBin)";
        } else if (ci_contains(text, "cmdkey") &&
                   (ci_contains(text, "/add") || ci_contains(text, "/list"))) {
            what = "cmdkey stored-credential planting/enumeration";
        /* dnscmd /serverlevelplugindll loads an arbitrary DLL into the
         * DNS service (documented persistence); /config disables WPAD
         * protections                                                  */
        } else if (ci_contains(text, "dnscmd") &&
                   (ci_contains(text, "plugin") || ci_contains(text, "/config"))) {
            what = "dnscmd server plugin/config abuse (LOLBin)";
        /* wsl -e/-c and bash -c execute payloads inside the WSL
         * subsystem where host EDR sees only a loader                */
        } else if (ci_contains(text, "wsl") &&
                   (ci_contains(text, "-e") || ci_contains(text, "-c") ||
                    ci_contains(text, ".sh") || ci_contains(text, "bash"))) {
            what = "wsl subsystem payload execution (LOLBin)";
        } else if (ci_contains(text, "certoc") &&
                   ci_contains(text, "-")) {
            what = "certoc certificate-store DLL loading (LOLBin)";
        /* Ransomware pre-encryption prep — icacls /deny locks admins
         * out before encryption, takeown /r takes recursive ownership,
         * cipher /w wipes free space, fsutil usn deletejournal and
         * wevtutil destroy the forensic record, manage-bde -off kills
         * BitLocker, diskpart /s runs scripted volume ops          */
        } else if (ci_contains(text, "icacls") &&
                   ci_contains(text, "/deny")) {
            what = "icacls deny-ACL lockout (ransomware prep)";
        } else if (ci_contains(text, "takeown") &&
                   (ci_contains(text, "/r") || ci_contains(text, " /d"))) {
            what = "takeown recursive ownership grab (ransomware prep)";
        } else if (ci_contains(text, "cipher") &&
                   ci_contains(text, "/w")) {
            what = "cipher free-space secure wipe (anti-forensics)";
        } else if (ci_contains(text, "fsutil") &&
                   ci_contains(text, "usn")) {
            what = "fsutil USN journal wipe (anti-forensics)";
        } else if (ci_contains(text, "manage-bde") &&
                   (ci_contains(text, "-off") || ci_contains(text, "-disable") ||
                    ci_contains(text, "-autounlock"))) {
            what = "manage-bde BitLocker disable (ransomware prep)";
        } else if (ci_contains(text, "diskpart") &&
                   ci_contains(text, "/s")) {
            what = "diskpart scripted volume operation (wiper class)";
        } else if (ci_contains(text, "secedit") &&
                   (ci_contains(text, "/configure") || ci_contains(text, "/import"))) {
            what = "secedit policy import (host-policy weakening)";
        } else if (ci_contains(text, "rasphone") &&
                   (ci_contains(text, "-d") || ci_contains(text, ".pbk"))) {
            what = "rasphone phonebook dial-out (LOLBin)";
        /* schtasks /create is ubiquitous legitimate admin — only the
         * privilege-escalated forms (/ru SYSTEM, /rl HIGHEST, /xml
         * import) are the documented attacker-persistence shape   */
        } else if (ci_contains(text, "schtasks") &&
                   ci_contains(text, "/create") &&
                   (ci_contains(text, "/ru") || ci_contains(text, "/rl") ||
                    ci_contains(text, "/xml"))) {
            what = "schtasks privileged task creation (persistence)";
        /* ntdsutil snapshot/ifm extracts ntds.dit — the domain
         * controller credential dump (the single highest-value
         * Windows LOLBin); pubprn/printui proxy-execute remote
         * scriptlets/driver DLLs, verclsid runs an arbitrary COM
         * CLSID, runonce /alternateshellstartup swaps the shell,
         * settingsynchost -load* embeds an executable payload   */
        } else if (ci_contains(text, "ntdsutil") &&
                   (ci_contains(text, "snapshot") || ci_contains(text, "ifm") ||
                    ci_contains(text, "create full") ||
                    ci_contains(text, "install from media") ||
                    ci_contains(text, "ac i ntds"))) {
            what = "ntdsutil ntds.dit extraction (credential dump)";
        } else if (ci_contains(text, "pubprn") &&
                   (ci_contains(text, "script:") || ci_contains(text, "http") ||
                    ci_contains(text, "\\\\"))) {
            what = "pubprn remote-script proxy execution (LOLBin)";
        } else if (ci_contains(text, "printui") &&
                   (ci_contains(text, "\\\\") || ci_contains(text, "http") ||
                    ci_contains(text, "/u"))) {
            what = "printui remote-driver DLL load (LOLBin)";
        } else if (ci_contains(text, "verclsid") &&
                   ci_contains(text, "/s")) {
            what = "verclsid arbitrary CLSID execution (LOLBin)";
        } else if (ci_contains(text, "runonce") &&
                   ci_contains(text, "alternateshellstartup")) {
            what = "runonce alternate-shell substitution (persistence)";
        } else if (ci_contains(text, "settingsynchost") &&
                   ci_contains(text, "-load")) {
            what = "settingsynchost embedded payload load (LOLBin)";
        /* sc create/config with binpath is the canonical service
         * persistence form; control + .cpl loads an arbitrary
         * Control Panel applet; findstr /v "" prints every line —
         * a whole-file read primitive hidden inside a grep      */
        } else if (ci_contains(text, "sc create") &&
                   (ci_contains(text, "binpath") || ci_contains(text, "obj"))) {
            what = "sc service creation (persistence primitive)";
        } else if (ci_contains(text, "sc config") &&
                   (ci_contains(text, "binpath") || ci_contains(text, "obj"))) {
            what = "sc service reconfig (persistence primitive)";
        } else if (ci_contains(text, "control") &&
                   ci_contains(text, ".cpl")) {
            what = "control applet load (.cpl payload)";
        } else if (ci_contains(text, "findstr") &&
                   ci_contains(text, "\"\"")) {
            what = "findstr whole-file read primitive (LOLBin)";
        /* LSASS memory dump — procdump/procdump64 and the
         * comsvcs.dll MiniDump rundll32 form are THE credential-
         * theft primitives (documented in nearly every intrusion) */
        } else if (ci_contains(text, "procdump") &&
                   (ci_contains(text, "lsass") || ci_contains(text, "-ma"))) {
            what = "procdump LSASS memory dump (credential theft)";
        } else if (ci_contains(text, "comsvcs") &&
                   ci_contains(text, "minidump")) {
            what = "comsvcs.dll MiniDump (LSASS credential theft)";
        /* tsecimp -f imports a TAPI XML that launches commands;
         * Microsoft.Workflow.Compiler compiles/executes XOML
         * workflow payloads (both LOLBAS-listed)                 */
        } else if (ci_contains(text, "tsecimp") &&
                   (ci_contains(text, "-f") || ci_contains(text, ".xml"))) {
            what = "tsecimp TAPI-XML payload execution (LOLBin)";
        } else if (ci_contains(text, "workflow.compiler") &&
                   (ci_contains(text, ".xoml") || ci_contains(text, ".cs") ||
                    ci_contains(text, ".xml"))) {
            what = "Workflow.Compiler XOML payload (LOLBin)";
        /* pnputil -i -a installs a driver package — the BYOVD
         * (bring-your-own-vulnerable-driver) primitive           */
        } else if (ci_contains(text, "pnputil") &&
                   (ci_contains(text, "-i") || ci_contains(text, "-a") ||
                    ci_contains(text, ".inf"))) {
            what = "pnputil driver install (BYOVD primitive)";
        /* net user/localgroup /add plants accounts, net share x=
         * exposes a drive, net use \\ leaks credentials to the
         * attacker share — the persistence/lateral account set   */
        /* net1.exe is the documented 'net' alias attackers run to
         * dodge 'net ' command monitoring — same primitives       */
        } else if ((ci_contains(text, "net user") ||
                    ci_contains(text, "net1 user") ||
                    ci_contains(text, "net.exe user")) &&
                   ci_contains(text, "/add")) {
            what = "net user account creation (backdoor primitive)";
        } else if ((ci_contains(text, "net localgroup") ||
                    ci_contains(text, "net1 localgroup") ||
                    ci_contains(text, "net.exe localgroup")) &&
                   ci_contains(text, "/add")) {
            what = "net localgroup admin grant (backdoor primitive)";
        } else if ((ci_contains(text, "net share") ||
                    ci_contains(text, "net1 share") ||
                    ci_contains(text, "net.exe share")) &&
                   ci_contains(text, "=")) {
            what = "net share drive exposure (exfil/lateral)";
        } else if ((ci_contains(text, "net use") ||
                    ci_contains(text, "net1 use") ||
                    ci_contains(text, "net.exe use")) &&
                   ci_contains(text, "\\\\")) {
            what = "net use remote-share mount (credential send)";
        /* ftp -s:script executes the embedded ! commands; iexpress
         * builds a self-extracting installer; robocopy to a UNC
         * destination is the classic bulk-exfil channel          */
        } else if (ci_contains(text, "ftp") &&
                   ci_contains(text, "-s:")) {
            what = "ftp script execution (LOLBin)";
        } else if (ci_contains(text, "iexpress") &&
                   (ci_contains(text, "-") || ci_contains(text, "/n") ||
                    ci_contains(text, ".sed"))) {
            what = "iexpress self-installer build (LOLBin)";
        } else if (ci_contains(text, "robocopy") &&
                   ci_contains(text, "\\\\")) {
            what = "robocopy exfiltration to remote share (LOLBin)";
        /* LOLBAS wave: ieexec fetches and runs a remote .NET app,
         * infdefaultinstall runs an .inf [DefaultInstall] payload,
         * msdeploy syncs attacker packages / runs commands        */
        } else if (ci_contains(text, "ieexec") &&
                   (ci_contains(text, "http") || ci_contains(text, ".exe") ||
                    ci_contains(text, ".dll"))) {
            what = "ieexec remote .NET execution (LOLBin)";
        } else if (ci_contains(text, "infdefaultinstall") &&
                   ci_contains(text, ".inf")) {
            what = "infdefaultinstall .inf payload (LOLBin)";
        } else if (ci_contains(text, "msdeploy") &&
                   (ci_contains(text, "-verb:") || ci_contains(text, "-source:") ||
                    ci_contains(text, "-dest:"))) {
            what = "msdeploy package/command execution (LOLBin)";
        /* rasdial /phonebook dials an attacker-supplied .pbk whose
         * entry can carry dial-up scripts (LOLBin)                */
        } else if (ci_contains(text, "rasdial") &&
                   (ci_contains(text, ".pbk") || ci_contains(text, "/phonebook"))) {
            what = "rasdial attacker phonebook dial (LOLBin)";
        /* regedit imports .reg (install primitive); '/e ' exports
         * instead, and exporting SAM/SECURITY/SYSTEM hives is
         * credential theft                                        */
        } else if (ci_contains(text, "regedit") &&
                   (ci_contains(text, "/s") ||
                    (ci_contains(text, ".reg") &&
                     !ci_contains(text, "/e ")))) {
            what = "regedit registry import (install primitive)";
        } else if (ci_contains(text, "regedit") &&
                   ci_contains(text, "/e") &&
                   (ci_contains(text, "\\sam") || ci_contains(text, "\\security") ||
                    ci_contains(text, "\\system"))) {
            what = "regedit SAM/SYSTEM hive export (credential theft)";
        /* reg add into autostart keys (Run/RunOnce/IFEO/
         * SilentProcessExit/Winlogon shell) is the classic
         * registry-persistence write                             */
        } else if ((ci_contains(text, "reg add") ||
                    ci_contains(text, "reg.exe add")) &&
                   (ci_contains(text, "currentversion\\run") ||
                    ci_contains(text, "image file execution") ||
                    ci_contains(text, "silentprocessexit") ||
                    ci_contains(text, "ms-settings") ||
                    (ci_contains(text, "winlogon") &&
                     (ci_contains(text, "shell") || ci_contains(text, "userinit"))))) {
            what = "reg add autostart/IFEO write (persistence primitive)";
        /* winrs -r runs a remote shell; tttracer/ttdinject trace
         * and inject DLLs via Time Travel Debugging (LOLBAS)      */
        } else if (ci_contains(text, "winrs") &&
                   ci_contains(text, "-r:")) {
            what = "winrs remote shell (LOLBin)";
        } else if (ci_contains(text, "tttracer") &&
                   (ci_contains(text, "-out") || ci_contains(text, "-dump") ||
                    ci_contains(text, ".exe") || ci_contains(text, ".dll"))) {
            what = "tttracer TTD trace/load (LOLBin)";
        } else if (ci_contains(text, "ttdinject") &&
                   (ci_contains(text, "/dll") || ci_contains(text, ".dll") ||
                    ci_contains(text, "/commandline"))) {
            what = "ttdinject TTD DLL injection (LOLBin)";
        /* runscripthelper runs the WSUS postinstall script; te.exe
         * is the TAEF test-harness executor; presentationhost
         * fetches and runs a remote .xbap (all LOLBAS)            */
        } else if (ci_contains(text, "runscripthelper") &&
                   (ci_contains(text, "\\\\") || ci_contains(text, ".exe") ||
                    ci_contains(text, ".bat") || ci_contains(text, ".dll") ||
                    ci_contains(text, ".ps1"))) {
            what = "runscripthelper postinstall exec (LOLBin)";
        } else if (ci_contains(text, "te.exe") &&
                   (ci_contains(text, ".dll") || ci_contains(text, ".wsc") ||
                    ci_contains(text, ".xap"))) {
            what = "te.exe TAEF payload exec (LOLBin)";
        } else if (ci_contains(text, "presentationhost") &&
                   (ci_contains(text, "http") || ci_contains(text, ".xbap") ||
                    ci_contains(text, "\\\\"))) {
            what = "presentationhost remote .xbap exec (LOLBin)";
        /* replace.exe x c:\windows\... writes attacker files into
         * system dirs — the write-into-system primitive           */
        } else if (ci_contains(text, "replace") &&
                   (ci_contains(text, "system32") || ci_contains(text, "syswow64"))) {
            what = "replace.exe write-into-system (LOLBin)";
        /* .NET compiler chain — csc/vbc/jsc/ilasm/resgen build
         * payloads on the host, certreq mints certs, diaghub
         * loads unsigned DLLs, desktopimgdownldr/wlrmdr fetch
         * and schedule exec (all LOLBAS)                          */
        } else if ((ci_contains(text, "csc ") || ci_contains(text, "csc.exe")) &&
                   (ci_contains(text, ".cs") || ci_contains(text, "/out") ||
                    ci_contains(text, "/t:") || ci_contains(text, "/target"))) {
            what = "csc on-host compile (LOLBin)";
        } else if ((ci_contains(text, "vbc ") || ci_contains(text, "vbc.exe")) &&
                   (ci_contains(text, ".vb") || ci_contains(text, "/out") ||
                    ci_contains(text, "/target"))) {
            what = "vbc on-host compile (LOLBin)";
        } else if ((ci_contains(text, "jsc ") || ci_contains(text, "jsc.exe")) &&
                   (ci_contains(text, ".js") || ci_contains(text, "/out"))) {
            what = "jsc on-host compile (LOLBin)";
        } else if (ci_contains(text, "ilasm") &&
                   (ci_contains(text, ".il") || ci_contains(text, "/exe") ||
                    ci_contains(text, "/dll") || ci_contains(text, "/output"))) {
            what = "ilasm assembly build (LOLBin)";
        } else if (ci_contains(text, "resgen") &&
                   (ci_contains(text, ".txt") || ci_contains(text, ".resx") ||
                    ci_contains(text, ".resources"))) {
            what = "resgen resource build (LOLBin)";
        } else if (ci_contains(text, "aspnet_compiler") &&
                   (ci_contains(text, "/") || ci_contains(text, "-v") ||
                    ci_contains(text, "-p"))) {
            what = "aspnet_compiler build (LOLBin)";
        } else if (ci_contains(text, "certreq") &&
                   (ci_contains(text, "-new") || ci_contains(text, ".inf") ||
                    ci_contains(text, ".csr"))) {
            what = "certreq certificate mint (LOLBin)";
        } else if (ci_contains(text, "diaghub") &&
                   (ci_contains(text, "/") || ci_contains(text, ".dll"))) {
            what = "diaghub unsigned-DLL load (LOLBin)";
        } else if (ci_contains(text, "desktopimgdownldr") &&
                   (ci_contains(text, "/") || ci_contains(text, "http"))) {
            what = "desktopimgdownldr fetch (LOLBin)";
        } else if (ci_contains(text, "wlrmdr") &&
                   (ci_contains(text, "-o") || ci_contains(text, "-f") ||
                    ci_contains(text, ".exe"))) {
            what = "wlrmdr scheduled-exec (LOLBin)";
        /* rundll32 DLL targets — url.dll FileProtocolHandler runs a
         * local file, zipfldr RouteTheCall opens the payload,
         * shell32 ShellExec/OpenAs_RunDLL launches the binary,
         * advpack LaunchINFSection runs an INF section            */
        } else if (ci_contains(text, "fileprotocolhandler") ||
                   ci_contains(text, "routethecall") ||
                   ci_contains(text, "shellexec_rundll") ||
                   ci_contains(text, "openas_rundll") ||
                   ci_contains(text, "launchinfsection")) {
            what = "rundll32 proxy-exec DLL target (LOLBin)";
        /* powershell -ep bypass / -ex bypass / -executionpolicy
         * bypass|unrestricted — the signature ExecutionPolicy
         * bypass that -enc/-w-hidden gates alone do not cover   */
        } else if ((ci_contains(text, "powershell") || ci_contains(text, "pwsh")) &&
                   (ci_contains(text, "-ep ") || ci_contains(text, "-ex ") ||
                    ci_contains(text, "-exec") ||
                    ci_contains(text, "-executionpolicy")) &&
                   (ci_contains(text, "bypass") ||
                    ci_contains(text, "unrestricted"))) {
            what = "powershell ExecutionPolicy bypass (LOLBin)";
        /* reg save hklm\sam|security|system — SeBackupPrivilege
         * hive dump, the CLI-native credential-theft primitive
         * (regedit /e was already covered)                        */
        } else if ((ci_contains(text, "reg ") || ci_contains(text, "reg.exe")) &&
                   ci_contains(text, "save") &&
                   (ci_contains(text, "\\sam") ||
                    ci_contains(text, "\\security") ||
                    ci_contains(text, "\\system"))) {
            what = "reg save SAM/SECURITY/SYSTEM hive dump";
        /* AV/EDR service kill — sc/net/taskkill targeting security
         * products by service or process name                    */
        } else if ((ci_contains(text, "sc ") || ci_contains(text, "sc.exe") ||
                    ci_contains(text, "net ") || ci_contains(text, "net1 ") ||
                    ci_contains(text, "taskkill") || ci_contains(text, "tskill")) &&
                   (ci_contains(text, "stop") || ci_contains(text, "delete") ||
                    ci_contains(text, "config") || ci_contains(text, "/f") ||
                    ci_contains(text, "start=dis") || ci_contains(text, "/im") ||
                    ci_contains(text, "tskill")) &&
                   (ci_contains(text, "windefend") || ci_contains(text, "msmpeng") ||
                    ci_contains(text, "wdnissvc") || ci_contains(text, "wscsvc") ||
                    ci_contains(text, "securityhealthservice") ||
                    ci_contains(text, "windows defender") ||
                    ci_contains(text, "avast") || ci_contains(text, "avguard") ||
                    ci_contains(text, "malwarebytes") || ci_contains(text, "mbamservice") ||
                    ci_contains(text, "sentinelagent") || ci_contains(text, "sophos") ||
                    ci_contains(text, "savservice") || ci_contains(text, "mcshield") ||
                    ci_contains(text, "ekrn") || ci_contains(text, "csfalcon") ||
                    ci_contains(text, "csagent") || ci_contains(text, "crowdstrike") ||
                    ci_contains(text, "elastic-endpoint") || ci_contains(text, "sharedaccess"))) {
            what = "AV/EDR service or process kill";
        /* netsh firewall/advfirewall off/disable/allowedprogram —
         * firewall kill or punch-through                          */
        } else if (ci_contains(text, "netsh") &&
                   (ci_contains(text, "advfirewall") || ci_contains(text, "firewall")) &&
                   (ci_contains(text, "state off") || ci_contains(text, "opmode disable") ||
                    ci_contains(text, "allowedprogram") || ci_contains(text, "portopening") ||
                    ci_contains(text, "add helper"))) {
            what = "netsh firewall disable/punch (LOLBin)";
        } else if (ci_contains(text, "netsh") &&
                   ci_contains(text, "add helper")) {
            what = "netsh helper-DLL load (LOLBin)";
        /* reagentc /disable — kills Windows Recovery Environment
         * (ransomware recovery-prep, same class as bcdedit)       */
        } else if (ci_contains(text, "reagentc") &&
                   ci_contains(text, "/disable")) {
            what = "reagentc recovery-disable (LOLBin)";
        /* wbadmin delete backup|catalog|systemstatebackup —
         * backup destruction (ransomware prep)                    */
        } else if (ci_contains(text, "wbadmin") && ci_contains(text, "delete")) {
            what = "wbadmin backup destruction (LOLBin)";
        /* package/cert/payload install primitives — dism
         * add-package, pkgmgr /iu, ocsetup, certmgr -add,
         * msxsl script-let, makecab payload pack, tscon session
         * hijack, arp -s static-ARP poison                        */
        } else if (ci_contains(text, "dism") && ci_contains(text, "add-package")) {
            what = "dism package install (LOLBin)";
        } else if (ci_contains(text, "pkgmgr") && ci_contains(text, "/iu")) {
            what = "pkgmgr package install (LOLBin)";
        } else if (ci_contains(text, "ocsetup") && ci_contains(text, " ")) {
            what = "ocsetup component install (LOLBin)";
        } else if (ci_contains(text, "certmgr") && ci_contains(text, "-add")) {
            what = "certmgr cert-store install (LOLBin)";
        } else if (ci_contains(text, "msxsl") &&
                   (ci_contains(text, ".xsl") || ci_contains(text, ".xml"))) {
            what = "msxsl script-let exec (LOLBin)";
        } else if (ci_contains(text, "makecab") &&
                   (ci_contains(text, ".exe") || ci_contains(text, ".dll") ||
                    ci_contains(text, ".ps1") || ci_contains(text, ".bat") ||
                    ci_contains(text, ".js") || ci_contains(text, ".ddf"))) {
            what = "makecab payload pack (LOLBin)";
        } else if (ci_contains(text, "tscon") && ci_contains(text, "/dest")) {
            what = "tscon session hijack (LOLBin)";
        } else if (ci_contains(text, "arp ") && ci_contains(text, "-s ")) {
            what = "arp static-poison entry (LOLBin)";
        } else if (ci_contains(text, "sc ") && ci_contains(text, "sdset") &&
                   ci_contains(text, "d:")) {
            what = "sc sdset SDDL tamper (LOLBin)";
        /* ── Unix-side post-compromise primitives ──────────────
         * UID-0 account creation — useradd/adduser -u 0|--uid 0|-ou */
        } else if ((ci_contains(text, "useradd") || ci_contains(text, "adduser") ||
                    ci_contains(text, "usermod")) &&
                   (ci_contains(text, "-u 0") || ci_contains(text, "-u0") ||
                    ci_contains(text, "--uid 0") || ci_contains(text, "-ou ") ||
                    ci_contains(text, "uid=0") ||
                    ci_contains(text, "-ag sudo") || ci_contains(text, "-g sudo") ||
                    ci_contains(text, "-ag wheel") || ci_contains(text, "-g wheel"))) {
            what = "uid-0 / wheel account grant";
        /* SELinux + audit kill — the defense-off set: setenforce 0,
         * auditctl -D (delete all rules), stop/kill auditd        */
        } else if (ci_contains(text, "setenforce") && ci_contains(text, " 0")) {
            what = "setenforce 0 (SELinux off)";
        } else if (ci_contains(text, "auditctl") &&
                   (ci_contains(text, "-d") || ci_contains(text, "-d"))) {
            what = "auditctl rules wipe";
        } else if ((ci_contains(text, "systemctl") || ci_contains(text, "service") ||
                    ci_contains(text, "killall") || ci_contains(text, "pkill")) &&
                   ci_contains(text, "auditd") &&
                   (ci_contains(text, "stop") || ci_contains(text, "kill") ||
                    ci_contains(text, "disable") || ci_contains(text, "mask"))) {
            what = "auditd service kill";
        /* shell-history tamper — history -c, unset HISTFILE,
         * HISTFILE=/dev/null, rm/redirect/truncate .bash_history */
        } else if (ci_contains(text, "history -c") ||
                   ci_contains(text, "unset histfile") ||
                   ci_contains(text, "histfile=/dev/null") ||
                   ci_contains(text, "histfilesize=0") ||
                   (ci_contains(text, "bash_history") &&
                    (ci_contains(text, "rm") || ci_contains(text, "/dev/null") ||
                     ci_contains(text, "truncate") || ci_contains(text, "shred")))) {
            what = "shell-history wipe";
        /* firewall flush — iptables/ip6tables -F|-X|flush,
         * nft flush ruleset, ufw disable, pfctl -d,
         * firewall-cmd --add-port punch                          */
        } else if ((ci_contains(text, "iptables") || ci_contains(text, "ip6tables")) &&
                   (ci_contains(text, "-f") || ci_contains(text, "-x") ||
                    ci_contains(text, "flush") || ci_contains(text, "-z") ||
                    ((ci_contains(text, "-t nat") || ci_contains(text, "masquerade") ||
                      ci_contains(text, "dnat")) &&
                     !ci_contains(text, " -l") && !ci_contains(text, "--list")))) {
            what = "iptables flush/NAT pivot";
        } else if (ci_contains(text, "nft") && ci_contains(text, "flush")) {
            what = "nft ruleset flush";
        } else if (ci_contains(text, "ufw") && ci_contains(text, "disable")) {
            what = "ufw disable";
        } else if (ci_contains(text, "pfctl") && ci_contains(text, "-d")) {
            what = "pfctl pf disable";
        } else if (ci_contains(text, "firewall-cmd") &&
                   (ci_contains(text, "--add-port") || ci_contains(text, "--add-service") ||
                    ci_contains(text, "--direct") || ci_contains(text, "--panic"))) {
            what = "firewall-cmd punch/panic";
        /* ssh tunneling — -R reverse tunnel, -D dynamic SOCKS,
         * -Nf/-fN background-no-command; -L stays unflagged
         * (ci can't split -L forward from -l login)              */
        } else if ((ci_contains(text, "ssh") || ci_contains(text, "autossh")) &&
                   (ci_contains(text, "-r ") || ci_contains(text, " -d ") ||
                    ci_contains(text, "-nf") || ci_contains(text, "-fn"))) {
            what = "ssh tunnel / reverse forward";
        /* sudoers append — >> /etc/sudoers or NOPASSWD grant     */
        } else if (ci_contains(text, "sudoers") &&
                   (ci_contains(text, "nopasswd") || ci_contains(text, ">>") ||
                    ci_contains(text, "tee"))) {
            what = "sudoers privilege append";
        /* namespace/container escape — systemd-run transient
         * unit exec, nsenter into host ns, unshare new userns,
         * docker --privileged / host-mount / host-net-pid        */
        } else if (ci_contains(text, "systemd-run") &&
                   (ci_contains(text, "--scope") || ci_contains(text, "--system") ||
                    ci_contains(text, "--pty") || ci_contains(text, "--unit") ||
                    ci_contains(text, "--user") || ci_contains(text, "--uid") ||
                    ci_contains(text, "-t ") || ci_contains(text, " -- "))) {
            what = "systemd-run transient-unit exec";
        } else if (ci_contains(text, "nsenter") &&
                   (ci_contains(text, "-t") || ci_contains(text, "-m") ||
                    ci_contains(text, "-p") || ci_contains(text, "-n"))) {
            what = "nsenter namespace escape";
        } else if (ci_contains(text, "unshare") &&
                   (ci_contains(text, "-u") || ci_contains(text, "--user") ||
                    ci_contains(text, "--net") || ci_contains(text, "--pid"))) {
            what = "unshare userns escape";
        } else if (ci_contains(text, "docker") &&
                   (ci_contains(text, "--privileged") || ci_contains(text, "-v /:") ||
                    ci_contains(text, "/:/host") || ci_contains(text, "--net=host") ||
                    ci_contains(text, "--pid=host") || ci_contains(text, "--ipc=host"))) {
            what = "docker privileged/host-mount escape";
        /* decoder+exec / attribute tamper / cap-enum /
         * ptrace-attach / TLS channel                          */
        } else if (ci_contains(text, "xxd") && ci_contains(text, "-r")) {
            what = "xxd hex-decode payload build";
        } else if (ci_contains(text, "chattr") &&
                   (ci_contains(text, "-i") || ci_contains(text, "+i"))) {
            what = "chattr immutable-flag tamper";
        } else if (ci_contains(text, "wipefs") &&
                   (ci_contains(text, "-a") || ci_contains(text, "/dev/"))) {
            what = "wipefs disk-signature wipe";
        } else if (ci_contains(text, "find") && ci_contains(text, "-perm") &&
                   (ci_contains(text, "4000") || ci_contains(text, "2000") ||
                    ci_contains(text, "u=s"))) {
            what = "find SUID/SGID enum";
        } else if (ci_contains(text, "getcap") && ci_contains(text, "-r")) {
            what = "getcap capability enum";
        } else if ((ci_contains(text, "gdb") || ci_contains(text, "strace") ||
                    ci_contains(text, "ltrace")) && ci_contains(text, "-p")) {
            what = "ptrace process attach";
        } else if (ci_contains(text, "openssl") &&
                   (ci_contains(text, "s_client") || ci_contains(text, "enc -d"))) {
            what = "openssl TLS/decrypt channel";
        } else if (ci_contains(text, "awk") && ci_contains(text, "system(")) {
            what = "awk system() exec";
        } else if (ci_contains(text, "xclip") && ci_contains(text, "-o")) {
            what = "xclip clipboard harvest";
        /* ── macOS post-compromise primitives ──────────────────
         * launchctl persistence — bootstrap/submit/kickstart
         * into a domain (load/-w fires via the existing rule)   */
        } else if (ci_contains(text, "launchctl") &&
                   (ci_contains(text, "bootstrap") || ci_contains(text, "submit") ||
                    ci_contains(text, "kickstart") || ci_contains(text, "load") ||
                    ci_contains(text, "enable "))) {
            what = "launchctl persistence/service exec";
        /* Gatekeeper off — spctl --master-disable/--add/--disable */
        } else if (ci_contains(text, "spctl") &&
                   (ci_contains(text, "--master-disable") ||
                    ci_contains(text, "--add") || ci_contains(text, "--disable"))) {
            what = "spctl gatekeeper off/whitelist";
        /* quarantine strip — the classic dropper step:
         * xattr -d com.apple.quarantine / -rc / -c              */
        } else if (ci_contains(text, "xattr") &&
                   (ci_contains(text, "quarantine") || ci_contains(text, "-rc") ||
                    ci_contains(text, "-cr ") || ci_contains(text, " -c "))) {
            what = "xattr quarantine strip";
        /* keychain credential theft — security find-generic/
         * find-internet-password, export, unlock/dump-keychain */
        } else if (ci_contains(text, "security") &&
                   (ci_contains(text, "find-generic-password") ||
                    ci_contains(text, "find-internet-password") ||
                    ci_contains(text, "export") || ci_contains(text, "unlock-keychain") ||
                    ci_contains(text, "dump-keychain"))) {
            what = "keychain credential access";
        /* directory-service account writes — dscl -create/
         * -append, pwpolicy -setpassword, dseditgroup -o edit  */
        } else if (ci_contains(text, "dscl") &&
                   (ci_contains(text, "-create") || ci_contains(text, "-append"))) {
            what = "dscl account create/grant";
        } else if (ci_contains(text, "pwpolicy") &&
                   (ci_contains(text, "-setpassword") ||
                    ci_contains(text, "-setaccountpolicies"))) {
            what = "pwpolicy password set";
        } else if (ci_contains(text, "dseditgroup") &&
                   (ci_contains(text, "-o edit") || ci_contains(text, "-a "))) {
            what = "dseditgroup group grant";
        /* package install / payload extract / record wipe —
         * installer -pkg, pkgutil --expand/--forget             */
        } else if (ci_contains(text, "installer") && ci_contains(text, "-pkg")) {
            what = "installer package exec";
        } else if (ci_contains(text, "pkgutil") &&
                   (ci_contains(text, "--expand") || ci_contains(text, "--forget") ||
                    ci_contains(text, "--install"))) {
            what = "pkgutil extract/forget";
        /* persistence plist writes — defaults write loginitems/
         * autolaunched/launchagents/launchdaemons               */
        } else if (ci_contains(text, "defaults") && ci_contains(text, "write") &&
                   (ci_contains(text, "loginitems") || ci_contains(text, "autolaunched") ||
                    ci_contains(text, "launchagents") || ci_contains(text, "launchdaemons"))) {
            what = "defaults persistence write";
        /* SIP off — csrutil disable / enable --without          */
        } else if (ci_contains(text, "csrutil") &&
                   (ci_contains(text, "disable") || ci_contains(text, "--without"))) {
            what = "csrutil SIP disable";
        /* traffic redirect — networksetup -set*proxy/-setdns*   */
        } else if (ci_contains(text, "networksetup") &&
                   (ci_contains(text, "-setwebproxy") ||
                    ci_contains(text, "-setsecurewebproxy") ||
                    ci_contains(text, "-setsocksfirewallproxy") ||
                    ci_contains(text, "-setdnsservers"))) {
            what = "networksetup proxy/dns redirect";
        /* pfctl enable + ruleset load (-d disable covered above) */
        } else if (ci_contains(text, "pfctl") &&
                   (ci_contains(text, "-e") || ci_contains(text, "-f "))) {
            what = "pfctl pf enable/ruleset load";
        /* remote access enable — systemsetup -setremotelogin on /
         * -setremoteappleevents on (SSH / Remote Events)         */
        } else if (ci_contains(text, "systemsetup") &&
                   (ci_contains(text, "remotelogin on") ||
                    ci_contains(text, "remoteappleevents on") ||
                    ci_contains(text, "wakeonnetworkaccess on"))) {
            what = "systemsetup remote-access enable";
        /* TCC privacy reset — tccutil reset                     */
        } else if (ci_contains(text, "tccutil") && ci_contains(text, "reset")) {
            what = "tccutil privacy reset";
        /* signature strip / adhoc forge — codesign
         * --remove-signature / -s - / --sign -                  */
        } else if (ci_contains(text, "codesign") &&
                   (ci_contains(text, "--remove-signature") ||
                    ci_contains(text, "--sign -") || ci_contains(text, "-s - "))) {
            what = "codesign strip/adhoc sign";
        /* kext load — kextload / kmutil load                    */
        } else if (ci_contains(text, "kextload") ||
                   (ci_contains(text, "kmutil") && ci_contains(text, "load"))) {
            what = "kernel extension load";
        /* mobileconfig install — profiles install               */
        } else if (ci_contains(text, "profiles") && ci_contains(text, "install")) {
            what = "profiles mobileconfig install";
        /* log wipe — log erase (anti-forensic)                  */
        } else if (ci_contains(text, "log") && ci_contains(text, "erase")) {
            what = "log erase wipe";
        /* Quick Look plugin exec — qlmanage -p                  */
        } else if (ci_contains(text, "qlmanage") && ci_contains(text, "-p")) {
            what = "qlmanage plugin exec";
        /* backup delete — tmutil delete (ransomware prep)       */
        } else if (ci_contains(text, "tmutil") && ci_contains(text, "delete")) {
            what = "tmutil backup delete";
        /* plist write — plutil -replace/-insert                 */
        } else if (ci_contains(text, "plutil") &&
                   (ci_contains(text, "-replace") || ci_contains(text, "-insert"))) {
            what = "plutil plist write";
        /* boot-arg tamper — nvram boot-args                     */
        } else if (ci_contains(text, "nvram") && ci_contains(text, "boot-args")) {
            what = "nvram boot-args tamper";
        /* full system dump — sysdiagnose -f                     */
        } else if (ci_contains(text, "sysdiagnose") && ci_contains(text, "-f")) {
            what = "sysdiagnose data harvest";
        /* on-host compile+run — xcrun swift                     */
        } else if (ci_contains(text, "xcrun") &&
                   (ci_contains(text, " swift ") || ci_contains(text, " swiftc "))) {
            what = "xcrun swift compile+run";
        /* JXA payload — osascript -l JavaScript                 */
        } else if (ci_contains(text, "osascript") && ci_contains(text, "javascript")) {
            what = "osascript JXA payload";
        /* ── GTFOBins exec primitives — a flag on a benign tool
         * that runs arbitrary code (the binary stays signed)   */
        } else if (ci_contains(text, "tar") &&
                   (ci_contains(text, "--checkpoint-action") ||
                    ci_contains(text, "--use-compress"))) {
            what = "tar checkpoint/compress exec";
        } else if (ci_contains(text, "git") &&
                   (ci_contains(text, "-c core.pager") ||
                    ci_contains(text, "-c core.fsmonitor") ||
                    ci_contains(text, "-c core.sshcommand") ||
                    ci_contains(text, "-c core.hookspath") ||
                    ci_contains(text, "ext::"))) {
            what = "git config/ext-transport exec";
        } else if (ci_contains(text, "ssh") &&
                   (ci_contains(text, "proxycommand") ||
                    ci_contains(text, "localcommand") ||
                    ci_contains(text, "permitlocalcommand"))) {
            what = "ssh ProxyCommand/LocalCommand exec";
        } else if (ci_contains(text, "find") &&
                   (ci_contains(text, "-exec ") || ci_contains(text, "-execdir"))) {
            what = "find -exec command run";
        } else if ((ci_contains(text, "vim") || ci_contains(text, " vi ") ||
                    ci_contains(text, " ex ") || ci_contains(text, "vi -c") ||
                    ci_contains(text, "ex -c")) &&
                   (ci_contains(text, "-c ") || ci_contains(text, "--cmd"))) {
            what = "vi/ex -c command exec";
        } else if (ci_contains(text, "man ") && ci_contains(text, "-p ")) {
            what = "man -P pager exec";
        } else if (ci_contains(text, "expect") && ci_contains(text, "spawn")) {
            what = "expect spawn exec";
        } else if (ci_contains(text, "tcpdump") && ci_contains(text, "-z ")) {
            what = "tcpdump -z postrotate exec";
        } else if (ci_contains(text, "split") && ci_contains(text, "--filter")) {
            what = "split --filter exec";
        } else if (ci_contains(text, "watch") &&
                   (ci_contains(text, "-x ") || ci_contains(text, "--exec"))) {
            what = "watch -x exec";
        } else if (ci_contains(text, "emacs") && ci_contains(text, "--eval")) {
            what = "emacs --eval exec";
        } else if (ci_contains(text, "script") &&
                   (ci_contains(text, "-qc") || ci_contains(text, "-c ") ||
                    ci_contains(text, "-qec"))) {
            what = "script -c pty exec";
        } else if (ci_contains(text, "capsh") &&
                   (ci_contains(text, "--shell") || ci_contains(text, " -- ") ||
                    ci_contains(text, "--addamb"))) {
            what = "capsh capability exec";
        } else if (ci_contains(text, "tcc") && ci_contains(text, "-run")) {
            what = "tcc -run C exec";
        } else if (ci_contains(text, "jrunscript") &&
                   (ci_contains(text, "-e ") || ci_contains(text, "-f "))) {
            what = "jrunscript Nashorn exec";
        } else if (ci_contains(text, "lua") &&
                   (ci_contains(text, "os.execute") || ci_contains(text, "io.popen") ||
                    ci_contains(text, " -e "))) {
            what = "lua os.execute exec";
        } else if (ci_contains(text, "busybox") &&
                   (ci_contains(text, " sh") || ci_contains(text, " wget") ||
                    ci_contains(text, " httpd") || ci_contains(text, " telnet"))) {
            what = "busybox applet exec/fetch";
        } else if (ci_contains(text, "setsid") &&
                   (ci_contains(text, " sh") || ci_contains(text, " bash") ||
                    ci_contains(text, " nc") || ci_contains(text, "/bin/") ||
                    ci_contains(text, "python") || ci_contains(text, "perl"))) {
            what = "setsid detached exec";
        /* ── privilege / account / destructive primitives ── */
        } else if (ci_contains(text, "pkexec") ||
                   ci_contains(text, "runuser -u") ||
                   (ci_contains(text, "chroot") &&
                    (ci_contains(text, " /") || ci_contains(text, " -")))) {
            what = "root-exec primitive (chroot/pkexec/runuser)";
        } else if (ci_contains(text, "chsh") && ci_contains(text, "-s")) {
            what = "chsh login-shell change";
        } else if (ci_contains(text, "passwd") &&
                   (ci_contains(text, "-l ") || ci_contains(text, "-d "))) {
            what = "passwd lock/delete";
        } else if (ci_contains(text, "chpasswd")) {
            what = "chpasswd batch password set";
        } else if (ci_contains(text, "journalctl") &&
                   ci_contains(text, "--vacuum")) {
            what = "journalctl journal wipe";
        } else if (ci_contains(text, "dmesg") && ci_contains(text, "-c")) {
            what = "dmesg ring clear";
        } else if (ci_contains(text, "mknod")) {
            what = "mknod device create";
        } else if (ci_contains(text, "insmod")) {
            what = "insmod kernel module load";
        } else if ((ci_contains(text, "rmmod") ||
                    (ci_contains(text, "modprobe") && ci_contains(text, "-r"))) &&
                   (ci_contains(text, "iptable") || ci_contains(text, "nf_") ||
                    ci_contains(text, "apparmor") || ci_contains(text, "selinux"))) {
            what = "security module unload";
        } else if (ci_contains(text, "kill") && ci_contains(text, "-9 -1")) {
            what = "kill-all (-9 -1) DoS";
        } else if (ci_contains(text, "init 0") || ci_contains(text, "init 6") ||
                   ci_contains(text, "telinit 0") || ci_contains(text, "telinit 6")) {
            what = "runlevel halt/reboot";
        } else if (ci_contains(text, "printenv")) {
            what = "printenv env/secrets dump";
        /* ── network pivot / clock tamper / remote mounts ── */
        } else if (ci_contains(text, "ip_forward") &&
                   (ci_contains(text, "=1") || ci_contains(text, " 1") ||
                    ci_contains(text, ">"))) {
            what = "ip_forward pivot enable";
        } else if ((ci_contains(text, "ip route") || ci_contains(text, "route ")) &&
                   (ci_contains(text, " add") || ci_contains(text, " replace"))) {
            what = "route add pivot";
        } else if (ci_contains(text, "date") &&
                   (ci_contains(text, " -s") || ci_contains(text, "--set"))) {
            what = "date clock set";
        } else if (ci_contains(text, "timedatectl") &&
                   (ci_contains(text, "set-time") || ci_contains(text, "set-ntp"))) {
            what = "timedatectl clock tamper";
        } else if (ci_contains(text, "mount") &&
                   (ci_contains(text, "-t cifs") || ci_contains(text, "-t nfs") ||
                    ci_contains(text, "-t smb") || ci_contains(text, "cifs"))) {
            what = "remote filesystem mount";
        } else if (ci_contains(text, "sshfs") && ci_contains(text, ":")) {
            what = "sshfs remote mount";
        } else if ((ci_contains(text, "lxc") || ci_contains(text, "incus")) &&
                   ci_contains(text, " exec")) {
            what = "lxc/incus container exec";
        /* ── attack-tool names — the tool IS the signal ─────── */
        } else if (ci_contains(text, "mimikatz") || ci_contains(text, "lazagne") ||
                   ci_contains(text, "pwdump") || ci_contains(text, "fgdump") ||
                   ci_contains(text, "sharphound") || ci_contains(text, "rubeus.exe") ||
                   ci_contains(text, "rubeus -") ||
                   ci_contains(text, "msfconsole") || ci_contains(text, "meterpreter") ||
                   ci_contains(text, "msfvenom") || ci_contains(text, "impacket") ||
                   ci_contains(text, "ntlmrelayx") || ci_contains(text, "secretsdump") ||
                   ci_contains(text, "getuserspns") || ci_contains(text, "getnpusers") ||
                   ci_contains(text, "psexec") || ci_contains(text, "psexesvc") ||
                   ci_contains(text, "smbexec") || ci_contains(text, "wmiexec") ||
                   ci_contains(text, "atexec") || ci_contains(text, "dcomexec") ||
                   ci_contains(text, "crackmapexec") || ci_contains(text, "netexec") ||
                   ci_contains(text, "nxc ") ||
                   (ci_contains(text, "bloodhound") &&
                    (ci_contains(text, ".py") || ci_contains(text, "python") ||
                     ci_contains(text, " -")))) {
            what = "credential/lateral attack tool";
        } else if (ci_contains(text, "hashcat") || ci_contains(text, "john --") ||
                   (ci_contains(text, "hydra") && ci_contains(text, " -")) ||
                   ci_contains(text, "aircrack") || ci_contains(text, "airodump") ||
                   ci_contains(text, "aireplay") || ci_contains(text, "wifite") ||
                   (ci_contains(text, "reaver") && ci_contains(text, " -")) ||
                   (ci_contains(text, "fluxion") && ci_contains(text, " -"))) {
            what = "password/wireless attack tool";
        } else if (ci_contains(text, "sqlmap") ||
                   (ci_contains(text, "nikto") && ci_contains(text, " -")) ||
                   (ci_contains(text, "nmap") && ci_contains(text, " -")) ||
                   ci_contains(text, "masscan") || ci_contains(text, "nuclei") ||
                   ci_contains(text, "gobuster") || ci_contains(text, "ffuf") ||
                   ci_contains(text, "wpscan") || ci_contains(text, "enum4linux") ||
                   ci_contains(text, "smbmap") || ci_contains(text, "arp-scan") ||
                   ci_contains(text, "hping") || ci_contains(text, "tcpreplay") ||
                   ci_contains(text, "dirb") || ci_contains(text, "dirsearch") ||
                   ci_contains(text, "feroxbuster") || ci_contains(text, "dalfox")) {
            what = "recon/scan attack tool";
        } else if (ci_contains(text, "ettercap") || ci_contains(text, "bettercap") ||
                   ci_contains(text, "dsniff") || ci_contains(text, "mitmproxy") ||
                   ci_contains(text, "sslstrip") || ci_contains(text, "sslsplit") ||
                   ci_contains(text, "responder.py") || ci_contains(text, "mitm6")) {
            what = "MitM/sniffing attack tool";
        /* ── tunneling / C2 proxy tools ── */
        } else if (ci_contains(text, "ngrok") || ci_contains(text, "cloudflared") ||
                   ci_contains(text, "frpc") || ci_contains(text, "frps") ||
                   ci_contains(text, "ligolo") || ci_contains(text, "sshuttle") ||
                   ci_contains(text, "dnscat") || ci_contains(text, "dns2tcp") ||
                   ci_contains(text, "ptunnel") || ci_contains(text, "icmpsh") ||
                   ci_contains(text, "icmptunnel") || ci_contains(text, "iodined") ||
                   ci_contains(text, "proxychains") || ci_contains(text, "torsocks") ||
                   ci_contains(text, "tshd") || ci_contains(text, "zrok") ||
                   (ci_contains(text, "gost") && ci_contains(text, " -")) ||
                   (ci_contains(text, "rathole") &&
                    (ci_contains(text, " -") || ci_contains(text, ".toml"))) ||
                   (ci_contains(text, "chisel") &&
                    (ci_contains(text, " server") || ci_contains(text, " client") ||
                     ci_contains(text, " --"))) ||
                   (ci_contains(text, "iodine") && ci_contains(text, "-f "))) {
            what = "tunneling/C2 proxy tool";
        /* ── privesc enums + exploit names ── */
        } else if (ci_contains(text, "linpeas") || ci_contains(text, "winpeas") ||
                   (ci_contains(text, "linenum") &&
              !ci_contains(text, "linenumber")) || ci_contains(text, "mimipenguin") ||
                   ci_contains(text, "pspy") || ci_contains(text, "linux-exploit") ||
                   ci_contains(text, "dirtyc0w") || ci_contains(text, "dirtycow") ||
                   ci_contains(text, "pwnkit") || ci_contains(text, "ysoserial")) {
            what = "privesc enum/exploit tool";
        /* ── cloud CLI exfil + remote exec ── */
        } else if (ci_contains(text, "rclone") &&
                   (ci_contains(text, "copy") || ci_contains(text, " move") ||
                    ci_contains(text, "sync") || ci_contains(text, "lsd"))) {
            what = "rclone cloud exfil";
        } else if (ci_contains(text, "aws") && ci_contains(text, "s3") &&
                   (ci_contains(text, " cp") || ci_contains(text, " sync") ||
                    ci_contains(text, " mv") || ci_contains(text, " rm"))) {
            what = "aws s3 exfil";
        } else if (ci_contains(text, "aws") && ci_contains(text, "ssm") &&
                   (ci_contains(text, "send-command") ||
                    ci_contains(text, "start-session"))) {
            what = "aws ssm remote exec";
        } else if (ci_contains(text, "gsutil") &&
                   (ci_contains(text, " cp") || ci_contains(text, " rsync") ||
                    ci_contains(text, " mv"))) {
            what = "gsutil cloud exfil";
        } else if (ci_contains(text, "azcopy") &&
                   (ci_contains(text, " copy") || ci_contains(text, " sync"))) {
            what = "azcopy cloud exfil";
        } else if (ci_contains(text, "az ") &&
                   (ci_contains(text, "run-command") ||
                    (ci_contains(text, "storage") &&
                     (ci_contains(text, "upload") || ci_contains(text, "download") ||
                      ci_contains(text, " copy"))))) {
            what = "az storage exfil/run-command";
        } else if (ci_contains(text, "gcloud") &&
                   (ci_contains(text, "compute ssh") ||
                    ci_contains(text, "compute scp"))) {
            what = "gcloud compute ssh/scp";
        /* ── k8s / container exec ── */
        } else if (ci_contains(text, "kubectl") &&
                   (ci_contains(text, " exec") || ci_contains(text, " cp ") ||
                    ci_contains(text, " port-forward") || ci_contains(text, " apply") ||
                    ci_contains(text, " attach") || ci_contains(text, " run "))) {
            what = "kubectl exec/apply";
        } else if (ci_contains(text, "helm") &&
                   (ci_contains(text, " install") || ci_contains(text, " upgrade"))) {
            what = "helm install/upgrade";
        } else if ((ci_contains(text, "docker") || ci_contains(text, "podman") ||
                    ci_contains(text, "nerdctl")) &&
                   (ci_contains(text, " exec") || ci_contains(text, " cp "))) {
            what = "container exec/cp";
        } else if (ci_contains(text, "crictl") && ci_contains(text, " exec")) {
            what = "crictl exec";
        /* ── db query exec / redis abuse ── */
        } else if (ci_contains(text, "mysql") && ci_contains(text, "-e ")) {
            what = "mysql -e query exec";
        } else if (ci_contains(text, "psql") && ci_contains(text, "-c ")) {
            what = "psql -c query exec";
        } else if (ci_contains(text, "redis-cli") &&
                   (ci_contains(text, "config") || ci_contains(text, "eval") ||
                    ci_contains(text, "slaveof") || ci_contains(text, "replicaof") ||
                    ci_contains(text, "module load"))) {
            what = "redis-cli abuse";
        } else if ((ci_contains(text, "mongosh") || ci_contains(text, "mongo ")) &&
                   ci_contains(text, "--eval")) {
            what = "mongo eval exec";
        /* ── package-manager remote installs — install IS exec ──
         * the non-registry-source form (URL/git+/local-bundle) is
         * the deliverable: postinstall hooks, setup.py, or maint
         * scripts run the attacker's bytes                  */
        } else if ((((ci_contains(text, "npm") || ci_contains(text, "pnpm")) &&
                    (ci_contains(text, " install ") || ci_contains(text, " add ") ||
                     ci_contains(text, " i "))) ||
                   ci_contains(text, "yarn add ") || ci_contains(text, "yarn install ") ||
                   ci_contains(text, "bun add ") || ci_contains(text, "bun install ")) &&
                   (ci_contains(text, "http") || ci_contains(text, "git+") ||
                    ci_contains(text, "file:") || ci_contains(text, ".tgz") ||
                    ci_contains(text, ".tar") || ci_contains(text, ".zip"))) {
            what = "npm-family remote package install";
        } else if ((ci_contains(text, "pip ") || ci_contains(text, "pip3") ||
                    ci_contains(text, "pipx") || ci_contains(text, "poetry add ") ||
                    ci_contains(text, "poetry install ")) &&
                   (ci_contains(text, " install ") || ci_contains(text, " add ") ||
                    (ci_contains(text, " -r ") && ci_contains(text, "http"))) &&
                   (ci_contains(text, "http") || ci_contains(text, "git+") ||
                    ci_contains(text, ".whl") || ci_contains(text, ".zip") ||
                    ci_contains(text, ".tar"))) {
            what = "python remote package install";
        } else if ((ci_contains(text, "uvx") &&
                    ci_contains(text, "http")) ||
                   (ci_contains(text, "gem install ") &&
                    (ci_contains(text, "http") || ci_contains(text, ".gem"))) ||
                   (ci_contains(text, "cargo install ") &&
                    (ci_contains(text, "--git") || ci_contains(text, "http") ||
                     ci_contains(text, "--path"))) ||
                   (ci_contains(text, "composer") &&
                    ci_contains(text, " require ") && ci_contains(text, "http"))) {
            what = "remote package install/exec";
        /* ── OS package remote/local-bundle installs ── */
        } else if ((ci_contains(text, "apt") || ci_contains(text, "apt-get")) &&
                   ci_contains(text, " install ") &&
                   (ci_contains(text, ".deb") || ci_contains(text, "http"))) {
            what = "apt bundle/URL install";
        } else if (ci_contains(text, "dpkg") && ci_contains(text, "-i ") &&
                   ci_contains(text, ".deb")) {
            what = "dpkg bundle install";
        } else if (((ci_contains(text, "rpm") &&
                    (ci_contains(text, " -i") || ci_contains(text, " -u"))) ||
                   (ci_contains(text, "dnf") && ci_contains(text, " install ")) ||
                   (ci_contains(text, "yum") && ci_contains(text, " install ")) ||
                   (ci_contains(text, "zypper") && ci_contains(text, " install ")) ||
                   (ci_contains(text, "pacman") && ci_contains(text, " -u ")) ||
                   (ci_contains(text, "xbps-install")) ||
                   (ci_contains(text, "brew") && ci_contains(text, " install ")) ||
                   (ci_contains(text, "winget") && ci_contains(text, " install ")) ||
                   (ci_contains(text, "choco") && ci_contains(text, " install ")) ||
                   (ci_contains(text, "scoop") && ci_contains(text, " install "))) &&
                   ci_contains(text, "http")) {
            what = "remote OS package install";
        } else if ((ci_contains(text, "apk") && ci_contains(text, " add ") &&
                   (ci_contains(text, "http") ||
                    ci_contains(text, "--allow-untrusted"))) ||
                   (ci_contains(text, "snap") && ci_contains(text, " install ") &&
                    (ci_contains(text, ".snap") ||
                     ci_contains(text, "--dangerous"))) ||
                   (ci_contains(text, "flatpak") && ci_contains(text, " install ") &&
                    (ci_contains(text, "http") || ci_contains(text, ".flatpakref") ||
                     ci_contains(text, ".flatpak"))) ||
                   (ci_contains(text, "choco") && ci_contains(text, " install ") &&
                    ci_contains(text, ".nupkg"))) {
            what = "remote/bundle package install";
        /* ── config-management remote exec — pull/exec primitives ── */
        } else if (ci_contains(text, "ansible-pull") &&
                   ci_contains(text, "http")) {
            what = "ansible-pull playbook fetch+run";
        } else if ((ci_contains(text, "ansible-playbook") &&
                    ci_contains(text, "http")) ||
                   (ci_contains(text, "ansible-galaxy") &&
                    ci_contains(text, " install ") &&
                    (ci_contains(text, "http") || ci_contains(text, " -r ")))) {
            what = "ansible remote playbook install";
        } else if ((ci_contains(text, "ansible") &&
                    (ci_contains(text, " -m shell") ||
                     ci_contains(text, " -m command") ||
                     ci_contains(text, " -m raw"))) ||
                   (ci_contains(text, "salt") &&
                    (ci_contains(text, "cmd.run") || ci_contains(text, "cmd.shell") ||
                     ci_contains(text, "cmd.exec_code"))) ||
                   (ci_contains(text, "salt-call") && ci_contains(text, "cmd"))) {
            what = "remote ad-hoc command exec";
        /* ── c234: miner exec / terminal injection / agent kill /
         * env exfil / winrm / timestomp / misc residuals ── */
        } else if (ci_contains(text, "xmrig") || ci_contains(text, "minerd") ||
                   ci_contains(text, "cpuminer") || ci_contains(text, "xmr-stak") ||
                   ci_contains(text, "ethminer") || ci_contains(text, "bzminer") ||
                   ci_contains(text, "lolminer") || ci_contains(text, "phoenixminer") ||
                   ci_contains(text, "nanominer") || ci_contains(text, "gminer") ||
                   ci_contains(text, "teamredminer") || ci_contains(text, "nbminer") ||
                   ci_contains(text, "cgminer") || ci_contains(text, "sgminer") ||
                   ci_contains(text, "bfgminer") || ci_contains(text, "minerd") ||
                   ci_contains(text, "claymore -o") || ci_contains(text, "claymore.exe") ||
                   ci_contains(text, "trex miner") ||
                   ci_contains(text, "stratum+") || ci_contains(text, "stratum:") ||
                   ci_contains(text, "donate-level") ||
                   ci_contains(text, "nicehash") || ci_contains(text, "nanopool") ||
                   ci_contains(text, "supportxmr") || ci_contains(text, "minergate") ||
                   ci_contains(text, "f2pool") || ci_contains(text, "antpool") ||
                   ci_contains(text, "viabtc") || ci_contains(text, "2miners") ||
                   ci_contains(text, "flypool") || ci_contains(text, "herominers") ||
                   ci_contains(text, "unmineable") || ci_contains(text, "miningpool")) {
            what = "cryptominer exec / pool config";
        } else if (ci_contains(text, "tmux send-keys") ||
                   ci_contains(text, "send-keys ") ||
                   (ci_contains(text, "screen") &&
                    ci_contains(text, "-x stuff"))) {
            what = "terminal session injection";
        } else if ((ci_contains(text, "pkill") || ci_contains(text, "killall") ||
                    ci_contains(text, "kill -9")) &&
                   (ci_contains(text, "osquery") || ci_contains(text, "filebeat") ||
                    ci_contains(text, "datadog-agent") || ci_contains(text, "fluentd") ||
                    ci_contains(text, "fluent-bit") || ci_contains(text, "splunk") ||
                    ci_contains(text, "newrelic") || ci_contains(text, "telegraf") ||
                    ci_contains(text, "wazuh") || ci_contains(text, "auditbeat") ||
                    ci_contains(text, "metricbeat") || ci_contains(text, "packetbeat") ||
                    ci_contains(text, "qualys") || ci_contains(text, "rapid7") ||
                    ci_contains(text, "insight-agent") || ci_contains(text, "sysmon") ||
                    ci_contains(text, "velociraptor") || ci_contains(text, "falcon") ||
                    ci_contains(text, "sentinel") || ci_contains(text, "elastic-agent"))) {
            what = "monitoring/EDR agent kill";
        } else if ((strstr(text, "env |") || strstr(text, "env|") ||
                    strstr(text, "printenv") || strstr(text, "env >") ||
                    strstr(text, "printenv >")) &&
                   (strstr(text, "| nc") || strstr(text, "|nc") ||
                    strstr(text, "nc ") || strstr(text, "| curl") ||
                    strstr(text, "|curl") || strstr(text, "curl -F") ||
                    strstr(text, "curl -d") || strstr(text, "wget --post") ||
                    strstr(text, "| wget") || strstr(text, "| socat"))) {
            what = "env-var dump piped to network (secrets exfil)";
        } else if (strstr(text, "| sudo -S") || strstr(text, "|sudo -S") ||
                   strstr(text, "| su -") || strstr(text, "|su -") ||
                   strstr(text, "su -c ")) {
            what = "stdin-password / su exec pipe";
        } else if ((ci_contains(text, "docker.sock") &&
                    (ci_contains(text, " -v ") || ci_contains(text, "--volume"))) ||
                   (ci_contains(text, "docker") &&
                    ci_contains(text, "--socket"))) {
            what = "docker socket mount (host control)";
        } else if (ci_contains(text, "credential.helper") &&
                   (ci_contains(text, "store") || ci_contains(text, "get") ||
                    ci_contains(text, "!"))) {
            what = "git credential.helper theft config";
        } else if (((ci_contains(text, "enter-pssession") ||
                    ci_contains(text, "new-pssession") ||
                    ci_contains(text, "invoke-command") ||
                    ci_contains(text, "invoke-wmimethod") ||
                    ci_contains(text, "invoke-cimmethod")) &&
                   (ci_contains(text, "-computername") ||
                    ci_contains(text, "-computer ") || ci_contains(text, "-cn "))) ||
                  (ci_contains(text, "winrm") &&
                   ci_contains(text, "quickconfig"))) {
            what = "WinRM / PSRemoting remote exec";
        } else if (ci_contains(text, "touch") &&
                   (ci_contains(text, " -r") || ci_contains(text, " -t") ||
                    ci_contains(text, " -d") || ci_contains(text, "--reference"))) {
            what = "timestomp (anti-forensic timestamp)";
        } else if (ci_contains(text, "batch -f") || ci_contains(text, "| batch") ||
                   ci_contains(text, "|batch")) {
            what = "batch (at-family) queued exec";
        /* ── c235: interpreter -e+exec-verb / npx-URL / git upload-pack /
         * exec -a / setcap+setfacl / netns+setpriv / misc ── */
        } else if ((ci_contains(text, "node -e") || ci_contains(text, "nodejs -e") ||
                    ci_contains(text, "node --eval") || ci_contains(text, "python -c") ||
                    ci_contains(text, "python2 -c") || ci_contains(text, "python3 -c") ||
                    ci_contains(text, "perl -e") || ci_contains(text, "ruby -e") ||
                    ci_contains(text, "php -r") || ci_contains(text, "lua -e") ||
                    ci_contains(text, "luajit -e") || ci_contains(text, "gawk -e") ||
                    ci_contains(text, "rscript -e") || ci_contains(text, "pwsh -c")) &&
                   (ci_contains(text, "child_process") || ci_contains(text, "os.system") ||
                    ci_contains(text, "subprocess") || ci_contains(text, "os.popen") ||
                    ci_contains(text, "pty.spawn") || ci_contains(text, "system(") ||
                    ci_contains(text, "exec(") || ci_contains(text, "popen(") ||
                    ci_contains(text, "spawn") || ci_contains(text, "shell_exec") ||
                    ci_contains(text, "passthru(") || ci_contains(text, "getruntime") ||
                    ci_contains(text, "os.execute") || ci_contains(text, "eval(") ||
                    ci_contains(text, "commands.getoutput") || ci_contains(text, "loadstring"))) {
            what = "interpreter -e/-c inline exec";
        } else if ((ci_contains(text, "npx") || ci_contains(text, "pnpm dlx") ||
                    ci_contains(text, "bunx") || ci_contains(text, "yarn dlx")) &&
                   (ci_contains(text, "http") || ci_contains(text, "git+"))) {
            what = "npx-family remote package exec";
        } else if (ci_contains(text, "git clone") &&
                   (ci_contains(text, "--upload-pack") || ci_contains(text, " -u "))) {
            what = "git clone upload-pack exec";
        } else if (ci_contains(text, "exec -a")) {
            what = "argv0 masquerade (exec -a)";
        } else if (ci_contains(text, "setcap") &&
                   (ci_contains(text, "+ep") || ci_contains(text, "+ei"))) {
            what = "file-capability grant (setcap)";
        } else if (ci_contains(text, "setfacl") &&
                   ci_contains(text, " -m") &&
                   (ci_contains(text, "/etc/") || ci_contains(text, "/root"))) {
            what = "acl grant on system file (setfacl)";
        } else if (ci_contains(text, "swapoff -") ||
                   ci_contains(text, "swapoff /")) {
            what = "swap disable (ransomware-prep class)";
        } else if (ci_contains(text, "ip netns exec") ||
                   ci_contains(text, "netns exec") ||
                   (ci_contains(text, "setpriv") &&
                    (ci_contains(text, "--reuid") || ci_contains(text, "--inh-caps") ||
                     ci_contains(text, "--bounding-set") || ci_contains(text, "--ruid") ||
                     ci_contains(text, "--euid")))) {
            what = "namespace / privilege-context exec";
        } else if (ci_contains(text, "bwrap") &&
                   (ci_contains(text, "--bind") || ci_contains(text, "--dev-bind") ||
                    ci_contains(text, "--ro-bind"))) {
            what = "bwrap bind-mount (namespace escape)";
        } else if (ci_contains(text, "emacs") &&
                   (ci_contains(text, " -l ") || ci_contains(text, "--eval") ||
                    ci_contains(text, "-batch"))) {
            what = "emacs batch/elisp exec";
        } else if (ci_contains(text, "sed") &&
                   (ci_contains(text, "1e ") || ci_contains(text, "1e'") ||
                    ci_contains(text, "1e\"") || ci_contains(text, " e ") ||
                    ci_contains(text, " e'"))) {
            what = "sed e-flag exec";
        } else if (ci_contains(text, "rsync") && ci_contains(text, "--rsh")) {
            what = "rsync remote-shell exec";
        } else if ((ci_contains(text, "update-rc.d") || ci_contains(text, "chkconfig") ||
                    ci_contains(text, "rc-update")) &&
                   (ci_contains(text, " defaults") || ci_contains(text, " on") ||
                    ci_contains(text, " add") || ci_contains(text, " enable"))) {
            what = "sysvinit service enable";
        /* ── c236: env-var injection (loader/interpreter/vcs/shell/proxy/
         * path hijack) + lateral movement (remote schtasks/sc/reg/at,
         * admin shares) + Defender exclusions + cred-enumeration ── */
        } else if (ci_contains(text, "ld_preload=") ||
                   ci_contains(text, "ld_library_path=") ||
                   ci_contains(text, "dyld_insert_libraries=") ||
                   ci_contains(text, "dyld_fallback") ||
                   ci_contains(text, "ld_audit=") ||
                   ci_contains(text, "ld_profile=") ||
                   ci_contains(text, "gconv_path=") ||
                   ci_contains(text, "glibc_tunables=") ||
                   ci_contains(text, "node_options=") ||
                   ci_contains(text, "pythonpath=") ||
                   ci_contains(text, "pythonhome=") ||
                   ci_contains(text, "pythonstartup=") ||
                   ci_contains(text, "rubylib=") ||
                   ci_contains(text, "rubyopt=") ||
                   ci_contains(text, "perl5opt=") ||
                   ci_contains(text, "perl5lib=") ||
                   ci_contains(text, "perl5db=") ||
                   ci_contains(text, "java_tool_options=") ||
                   ci_contains(text, "_java_options=") ||
                   ci_contains(text, "jdk_java_options=") ||
                   ci_contains(text, "phprc=") ||
                   ci_contains(text, "php_ini_scan_dir=") ||
                   ci_contains(text, "gem_home=") ||
                   ci_contains(text, "gem_path=") ||
                   ci_contains(text, "git_ssh_command=") ||
                   ci_contains(text, "git_ssh=") ||
                   ci_contains(text, "git_proxy_command=") ||
                   ci_contains(text, "git_external_diff=") ||
                   ci_contains(text, "git_askpass=") ||
                   ci_contains(text, "ssh_askpass=") ||
                   ci_contains(text, "svn_ssh=") ||
                   ci_contains(text, "cvs_rsh=") ||
                   ci_contains(text, "prompt_command=") ||
                   ci_contains(text, "bash_env=") ||
                   ci_contains(text, "zdotdir=") ||
                   ci_contains(text, "inputrc=") ||
                   ci_contains(text, "http_proxy=") ||
                   ci_contains(text, "https_proxy=") ||
                   ci_contains(text, "all_proxy=") ||
                   ci_contains(text, "ftp_proxy=") ||
                   ci_contains(text, "rsync_proxy=") ||
                   ci_contains(text, "path=/tmp") ||
                   ci_contains(text, "path=/dev/shm") ||
                   ci_contains(text, "path=/var/tmp") ||
                   ci_contains(text, "path=.") ||
                   ci_contains(text, "path=/usr/tmp")) {
            what = "env-var injection (loader/interpreter/proxy/path hijack)";
        } else if ((ci_contains(text, "schtasks") &&
                    (ci_contains(text, " /s ") || ci_contains(text, " /s\\"))) ||
                   ci_contains(text, "sc \\") || ci_contains(text, "sc.exe \\") ||
                   ci_contains(text, "reg add \\") ||
                   ci_contains(text, "at \\")) {
            what = "remote admin primitive (schtasks/sc/reg/at \\host)";
        } else if (strstr(text, "\\\\") &&
                   (strstr(text, "\\c$") || strstr(text, "\\d$") ||
                    strstr(text, "\\admin$") || strstr(text, "\\ipc$") ||
                    strstr(text, "\\print$"))) {
            what = "admin-share path (\\\\host\\c$/admin$/ipc$)";
        } else if (ci_contains(text, "add-mppreference") ||
                   ci_contains(text, "set-mppreference") ||
                   ci_contains(text, "-exclusionpath") ||
                   ci_contains(text, "-exclusionprocess") ||
                   ci_contains(text, "-exclusionextension") ||
                   ci_contains(text, "-disablerealtimemonitoring") ||
                   ci_contains(text, "-disableioavprotection") ||
                   ci_contains(text, "-disablebehaviormonitoring") ||
                   ci_contains(text, "-disablescriptscanning") ||
                   ci_contains(text, "-disableblockatfirstseen") ||
                   ci_contains(text, "-disabletamperprotection") ||
                   ci_contains(text, "-disablearchive") ||
                   ci_contains(text, "-disableemailscanning") ||
                   ci_contains(text, "-disablenetworkprotection")) {
            what = "Defender exclusion/disable (AV weakening)";
        } else if (ci_contains(text, "vaultcmd") ||
                   ci_contains(text, "keymgr") ||
                   (ci_contains(text, "netsh wlan") &&
                    (ci_contains(text, "key") || ci_contains(text, "export")))) {
            what = "credential-store enumeration";
        } else if (ci_contains(text, "explorer") &&
                   (ci_contains(text, "http") || ci_contains(text, "shell:") ||
                    strstr(text, "\\\\"))) {
            what = "explorer remote-open (URL/shell:/UNC)";
        } else if ((ci_contains(text, "start-process") &&
                    ci_contains(text, "-verb runas")) ||
                   ci_contains(text, "runas /netonly")) {
            what = "runas/elevation attempt";
        } else if (ci_contains(text, "fsutil") &&
                   (ci_contains(text, "setzerodata") ||
                    ci_contains(text, "setvaliddata") ||
                    ci_contains(text, "behavior set"))) {
            what = "fsutil data-wipe/behavior change";
        } else if (ci_contains(text, "diskpart") &&
                   (ci_contains(text, "clean") || ci_contains(text, "create") ||
                    ci_contains(text, "format") || ci_contains(text, "select disk"))) {
            what = "diskpart partition destructive op";
        /* ── c237: PowerShell cmdlets (in-memory load, persistence,
         * accounts, remoting, install, policy-bypass, MOTW strip) +
         * audit/anti-forensics + destructive Windows + sudo/key ops ── */
        } else if (ci_contains(text, "add-type") ||
                   ci_contains(text, "assembly]::load") ||
                   ci_contains(text, "assembly.load") ||
                   ci_contains(text, "loadwithpartialname") ||
                   ci_contains(text, "assembly]::loadfrom") ||
                   ci_contains(text, "assembly]::loadfile")) {
            what = "PowerShell/.NET in-memory assembly load";
        } else if ((ci_contains(text, "new-service") &&
                    ci_contains(text, "-binarypathname")) ||
                   ci_contains(text, "register-scheduledtask") ||
                   ci_contains(text, "new-scheduledtask") ||
                   ci_contains(text, "set-scheduledtask") ||
                   ((ci_contains(text, "new-itemproperty") ||
                     ci_contains(text, "set-itemproperty") ||
                     ci_contains(text, "new-item")) &&
                    (ci_contains(text, "\\run") || ci_contains(text, "runonce") ||
                     ci_contains(text, "\\ifeo") || ci_contains(text, "winlogon") ||
                     ci_contains(text, "image file") || ci_contains(text, "shell\\")))) {
            what = "PowerShell persistence install (service/task/runkey)";
        } else if (ci_contains(text, "set-executionpolicy") &&
                   (ci_contains(text, "bypass") || ci_contains(text, "unrestricted"))) {
            what = "execution-policy bypass (cmdlet form)";
        } else if (ci_contains(text, "unblock-file") ||
                   (ci_contains(text, "zone.identifier") &&
                    (ci_contains(text, "remove") || ci_contains(text, "del") ||
                     ci_contains(text, "clear")))) {
            what = "MOTW strip (Unblock-File/Zone.Identifier removal)";
        } else if (ci_contains(text, "new-localuser") ||
                   ci_contains(text, "add-localgroupmember") ||
                   ci_contains(text, "enable-localuser") ||
                   (ci_contains(text, "set-localuser") &&
                    ci_contains(text, "-password")) ||
                   ci_contains(text, "new-aduser") ||
                   ci_contains(text, "add-adgroupmember") ||
                   ci_contains(text, "set-adaccountpassword")) {
            what = "account creation/group grant (PowerShell)";
        } else if (ci_contains(text, "enable-psremoting") ||
                   ci_contains(text, "enable-wsmancredssp") ||
                   ci_contains(text, "install-module") ||
                   ci_contains(text, "install-package") ||
                   ci_contains(text, "install-script") ||
                   ((ci_contains(text, "add-windowscapability") ||
                     ci_contains(text, "enable-windowsoptionalfeature")) &&
                    (ci_contains(text, "telnet") || ci_contains(text, "smb1") ||
                     ci_contains(text, "snmp") || ci_contains(text, "tftp")))) {
            what = "PS remoting/gallery-install/legacy-feature enable";
        } else if (ci_contains(text, "auditpol") &&
                   (ci_contains(text, "/clear") || ci_contains(text, "/remove") ||
                    ci_contains(text, "/set") || ci_contains(text, "/backup"))) {
            what = "audit-policy wipe (auditpol)";
        } else if (ci_contains(text, "shutdown") &&
                   (ci_contains(text, " /s") || ci_contains(text, " /r") ||
                    ci_contains(text, " /m") || ci_contains(text, " /p") ||
                    ci_contains(text, " -s") || ci_contains(text, " -r"))) {
            what = "shutdown/reboot (local or remote)";
        } else if ((ci_contains(text, "format") &&
                    (ci_contains(text, " c:") || ci_contains(text, " d:") ||
                     ci_contains(text, " e:") || ci_contains(text, " f:") ||
                     ci_contains(text, " /q") || ci_contains(text, " /y"))) ||
                   ci_contains(text, "format.com") ||
                   ci_contains(text, "del /s") || ci_contains(text, "del /f /s") ||
                   ci_contains(text, "rmdir /s") || ci_contains(text, "rd /s")) {
            what = "format/recursive-delete (Windows destructive)";
        } else if (ci_contains(text, "attrib ") &&
                   (ci_contains(text, "+h") || ci_contains(text, "+s") ||
                    ci_contains(text, " -h") || ci_contains(text, " -s"))) {
            what = "attrib hidden/system flag (evasion)";
        } else if ((ci_contains(text, "net config") &&
                    ci_contains(text, "/hidden")) ||
                   (ci_contains(text, "netsh") &&
                    (ci_contains(text, " -r ") || ci_contains(text, " -f ")))) {
            what = "hidden-server flag / remote or scripted netsh";
        } else if ((ci_contains(text, "klist") &&
                    (ci_contains(text, "purge") || ci_contains(text, "get"))) ||
                   ci_contains(text, "sudoedit") ||
                   ci_contains(text, "sudo -e") ||
                   (ci_contains(text, "net time") &&
                    ci_contains(text, "/set"))) {
            what = "ticket/sudo-edit/time-set primitive";
        } else if (ci_contains(text, "get-credential") ||
                   ci_contains(text, "convertfrom-securestring") ||
                   ci_contains(text, "convertto-securestring") ||
                   ci_contains(text, "export-clixml") ||
                   ci_contains(text, "import-clixml")) {
            what = "credential materialization (PS cred cmdlets)";
        } else if (ci_contains(text, "gpg --export-secret") ||
                   (ci_contains(text, "pkcs12") && ci_contains(text, "-export")) ||
                   ci_contains(text, "ssh-keygen -y") ||
                   ci_contains(text, "keytool -exportcert") ||
                   ci_contains(text, "keytool -genkey") ||
                   ci_contains(text, "makecert") ||
                   ci_contains(text, "new-selfsignedcertificate") ||
                   ci_contains(text, "iam create-access-key") ||
                   (ci_contains(text, "aws configure set") &&
                    (ci_contains(text, "access") || ci_contains(text, "secret")))) {
            what = "key-material export/creation";
        } else if ((ci_contains(text, "puppet") && ci_contains(text, " apply ") &&
                    ci_contains(text, "http")) ||
                   ((ci_contains(text, "chef-client") ||
                     ci_contains(text, "chef-solo")) &&
                    ci_contains(text, " -r ") && ci_contains(text, "http")) ||
                   (ci_contains(text, "make") && ci_contains(text, " -f ") &&
                    ci_contains(text, "http")) ||
                   ci_contains(text, "at -f ")) {
            what = "remote recipe/makefile exec";
        /* ── c238: systemctl/service/runlevel control + account mgmt +
         * firewall rule-add + sysctl security keys + kernel-module
         * load + boot/store-config + sniff/spoof tools ── */
        } else if (ci_contains(text, "systemctl") &&
                   (ci_contains(text, " stop") || ci_contains(text, " disable") ||
                    ci_contains(text, " mask") || ci_contains(text, " kill") ||
                    ci_contains(text, " halt") || ci_contains(text, " poweroff") ||
                    ci_contains(text, " reboot") || ci_contains(text, " kexec") ||
                    ci_contains(text, " suspend") || ci_contains(text, " hibernate") ||
                    ci_contains(text, " emergency") || ci_contains(text, " rescue") ||
                    ci_contains(text, " isolate") || ci_contains(text, " restart"))) {
            what = "systemctl stop/mask/shutdown verb";
        } else if ((ci_contains(text, "service ") &&
                    (ci_contains(text, " stop") || ci_contains(text, " start") ||
                     ci_contains(text, " restart") || ci_contains(text, " disable"))) ||
                   (ci_contains(text, "loginctl") &&
                    (ci_contains(text, "poweroff") || ci_contains(text, "reboot") ||
                     ci_contains(text, "suspend") || ci_contains(text, "hibernate") ||
                     ci_contains(text, "halt") || ci_contains(text, "kill") ||
                     ci_contains(text, "terminate"))) ||
                   (ci_contains(text, "busybox") &&
                    (ci_contains(text, "poweroff") || ci_contains(text, "halt") ||
                     ci_contains(text, "reboot"))) ||
                   ci_contains(text, "init 1") || ci_contains(text, "init s") ||
                   ci_contains(text, "init s") || ci_contains(text, "telinit 1") ||
                   ci_contains(text, "telinit s") || ci_contains(text, "telinit s") ||
                   ci_contains(text, "reboot -") || ci_contains(text, "reboot now") ||
                   ci_contains(text, "poweroff -") || ci_contains(text, "halt -") ||
                   (ci_contains(text, "shutdown") &&
                    (ci_contains(text, " -h") || ci_contains(text, " -h") ||
                     ci_contains(text, " -p") || ci_contains(text, " -r")))) {
            what = "service/runlevel/power primitive";
        } else if (ci_contains(text, "userdel ") || ci_contains(text, "groupdel ") ||
                   (ci_contains(text, "gpasswd") &&
                    (ci_contains(text, " -a") || ci_contains(text, " -d") ||
                     ci_contains(text, " -a") || ci_contains(text, " -m"))) ||
                   (ci_contains(text, "usermod") &&
                    (ci_contains(text, " -p") || ci_contains(text, " -l") ||
                     ci_contains(text, " -u") || ci_contains(text, " -s"))) ||
                   (ci_contains(text, "passwd") &&
                    (ci_contains(text, " -d") || ci_contains(text, " -u") ||
                     ci_contains(text, " -e"))) ||
                   (ci_contains(text, "faillock") &&
                    ci_contains(text, "--reset")) ||
                   (ci_contains(text, "pam_tally2") &&
                    (ci_contains(text, "--reset") || ci_contains(text, " -r"))) ||
                   (ci_contains(text, "faillog") && ci_contains(text, " -r")) ||
                   (ci_contains(text, "lastlog") &&
                    (ci_contains(text, "clear") || ci_contains(text, " -r"))) ||
                   (ci_contains(text, "chage") &&
                    (ci_contains(text, "-m -1") || ci_contains(text, "-m 0") ||
                     ci_contains(text, "-e -1") || ci_contains(text, "-e 0") ||
                     ci_contains(text, "-i -1") || ci_contains(text, "-i 0")))) {
            what = "account-create/password/lockout-reset";
        } else if (((ci_contains(text, "iptables") ||
                     ci_contains(text, "ip6tables")) &&
                    ci_contains(text, "--policy")) ||
                   (ci_contains(text, "ufw") &&
                    ci_contains(text, "default allow"))) {
            what = "firewall default-policy neutralize";
        } else if (ci_contains(text, "sysctl") &&
                   (ci_contains(text, " -w") || ci_contains(text, "=")) &&
                   (ci_contains(text, "randomize_va_space") ||
                    ci_contains(text, "core_pattern") ||
                    ci_contains(text, "suid_dumpable") ||
                    ci_contains(text, "kptr_restrict") ||
                    ci_contains(text, "dmesg_restrict") ||
                    ci_contains(text, "yama") ||
                    ci_contains(text, "modules_disabled") ||
                    ci_contains(text, "kexec_load") ||
                    ci_contains(text, "unprivileged_bpf") ||
                    ci_contains(text, "unprivileged_userns") ||
                    ci_contains(text, "uselib") ||
                    ci_contains(text, "perf_event_paranoid") ||
                    ci_contains(text, "accept_redirects") ||
                    ci_contains(text, "accept_source_route") ||
                    ci_contains(text, "send_redirects") ||
                    ci_contains(text, "rp_filter") ||
                    ci_contains(text, "tcp_syncookies") ||
                    ci_contains(text, "icmp_echo_ignore") ||
                    ci_contains(text, "log_martians") ||
                    ci_contains(text, "mmap_min_addr") ||
                    ci_contains(text, "protected_hardlinks") ||
                    ci_contains(text, "protected_symlinks") ||
                    ci_contains(text, "protected_fifos") ||
                    ci_contains(text, "protected_regular") ||
                    ci_contains(text, "kernel.sysrq"))) {
            what = "sysctl security-parameter write";
        } else if ((ci_contains(text, "modprobe") &&
                    (ci_contains(text, " /") || ci_contains(text, "--force") ||
                     ci_contains(text, " -f "))) ||
                   (ci_contains(text, "dkms") &&
                    (ci_contains(text, "install") || ci_contains(text, "add")))) {
            what = "kernel-module load (modprobe/dkms)";
        } else if ((ci_contains(text, "ldconfig") &&
                    (ci_contains(text, " /") || ci_contains(text, " -n "))) ||
                   ci_contains(text, "ssh-copy-id") ||
                   (ci_contains(text, "ssh-add") &&
                    (ci_contains(text, " /") || ci_contains(text, "~/") ||
                     ci_contains(text, " -d"))) ||
                   (ci_contains(text, "apt-key") && ci_contains(text, "add")) ||
                   (ci_contains(text, "rpm") && ci_contains(text, "--import"))) {
            what = "ldconfig/ssh-key/trust-store primitive";
        } else if ((ci_contains(text, "mokutil") &&
                    (ci_contains(text, "--disable") || ci_contains(text, "--import") ||
                     ci_contains(text, " -i "))) ||
                   (ci_contains(text, "efibootmgr") &&
                    (ci_contains(text, " -c") || ci_contains(text, " -b") ||
                     ci_contains(text, " -d") || ci_contains(text, " -b"))) ||
                   (ci_contains(text, "efivar") && ci_contains(text, " -w")) ||
                   (ci_contains(text, "update-alternatives") &&
                    ci_contains(text, "--install"))) {
            what = "secure-boot/boot-entry/alternatives primitive";
        } else if ((ci_contains(text, "tcpdump") && ci_contains(text, " -w")) ||
                   (ci_contains(text, "tshark") && ci_contains(text, " -w")) ||
                   ci_contains(text, "dumpcap") || ci_contains(text, "ngrep") ||
                   ci_contains(text, "tcpflow") || ci_contains(text, "arpspoof") ||
                   ci_contains(text, "dnsspoof") || ci_contains(text, "macof") ||
                   ci_contains(text, "yersinia") || ci_contains(text, "slowloris") ||
                   ci_contains(text, "nping") ||
                   (ci_contains(text, "ostinato") && ci_contains(text, " -"))) {
            what = "sniff/spoof/DoS tool primitive";
        /* ── c239: GUI/input injection + screen/mic capture +
         * web-terminal/VNC backdoors + eBPF + exfil upload +
         * AD-recon/C2/RAT/phishing names + SUID install +
         * sqlite cred-db + LOLBin names ── */
        } else if (ci_contains(text, "xdotool") || ci_contains(text, "ydotool") ||
                   ci_contains(text, "wtype") ||
                   (ci_contains(text, "xhost") && ci_contains(text, " +")) ||
                   (ci_contains(text, "import") && ci_contains(text, "-window")) ||
                   ci_contains(text, "scrot") ||
                   ci_contains(text, "gnome-screenshot") ||
                   ci_contains(text, "flameshot") ||
                   (ci_contains(text, "maim") && ci_contains(text, " -")) ||
                   (ci_contains(text, "spectacle") && ci_contains(text, " -")) ||
                   ci_contains(text, "wf-recorder") || ci_contains(text, "xwd") ||
                   (ci_contains(text, "obs") && ci_contains(text, "--start")) ||
                   (ci_contains(text, "ffmpeg") &&
                    (ci_contains(text, "-f x11grab") || ci_contains(text, "avfoundation") ||
                     ci_contains(text, "-f pulse") || ci_contains(text, "-f alsa") ||
                     ci_contains(text, "-f gdigrab") || ci_contains(text, "-f v4l2") ||
                     ci_contains(text, "-f dshow"))) ||
                   ci_contains(text, "parecord") || ci_contains(text, "arecord") ||
                   ci_contains(text, "parec") ||
                   (ci_contains(text, "sox") &&
                    (ci_contains(text, " -d") || ci_contains(text, " -t"))) ||
                   ci_contains(text, "logkeys") || ci_contains(text, "evsieve") ||
                   (ci_contains(text, "keyd") && ci_contains(text, "monitor"))) {
            what = "GUI-injection/screen-mic capture";
        } else if (ci_contains(text, "ttyd") || ci_contains(text, "gotty") ||
                   ci_contains(text, "shellinabox") || ci_contains(text, "tmate") ||
                   ci_contains(text, "teleconsole") || ci_contains(text, "sish") ||
                   ci_contains(text, "wstunnel") || ci_contains(text, "regeorg") ||
                   ci_contains(text, "pivotnacci") || ci_contains(text, "wetty") ||
                   ci_contains(text, "x11vnc") || ci_contains(text, "vncserver") ||
                   ci_contains(text, "x0vncserver") || ci_contains(text, "tigervnc") ||
                   ci_contains(text, "wayvnc") || ci_contains(text, "bpftool") ||
                   ci_contains(text, "bpftrace")) {
            what = "web-terminal/VNC/eBPF backdoor primitive";
        } else if ((ci_contains(text, "curl") &&
                    ((ci_contains(text, "@") &&
                      (ci_contains(text, " -f") || ci_contains(text, " -d") ||
                       ci_contains(text, "--form") || ci_contains(text, "--data"))) ||
                     ci_contains(text, " -t ") || ci_contains(text, "--upload-file"))) ||
                   (ci_contains(text, "wget") && ci_contains(text, "--post-file"))) {
            what = "curl/wget file-upload exfil form";
        } else if (ci_contains(text, "certipy") || ci_contains(text, "adidnsdump") ||
                   ci_contains(text, "windapsearch") || ci_contains(text, "ldeep") ||
                   ci_contains(text, "pywerview") || ci_contains(text, "rusthound") ||
                   ci_contains(text, "adenum") || ci_contains(text, "ldapdomaindump") ||
                   ci_contains(text, "snaffler") || ci_contains(text, "pingcastle") ||
                   ci_contains(text, "sharploader") || ci_contains(text, "sharpshooter") ||
                   ci_contains(text, "pezor") || ci_contains(text, "gadgettojscript") ||
                   ci_contains(text, "phant0m") || ci_contains(text, "stracciatella") ||
                   ci_contains(text, "invisibilitycloak") || ci_contains(text, "eventlogmaster") ||
                   ci_contains(text, "persistence-finder") || ci_contains(text, "fakessh") ||
                   ci_contains(text, "mailsniper") || ci_contains(text, "cewler") ||
                   ci_contains(text, "poshc2") || ci_contains(text, "nighthawk") ||
                   ci_contains(text, "bruteratel") || ci_contains(text, "brute ratel") ||
                   ci_contains(text, "cobaltstrike") || ci_contains(text, "cobalt strike") ||
                   (ci_contains(text, "bloodhound") && ci_contains(text, " -")) ||
                   (ci_contains(text, "sliver") && ci_contains(text, " -")) ||
                   (ci_contains(text, "havoc") && ci_contains(text, " -")) ||
                   (ci_contains(text, "mythic") && ci_contains(text, " -")) ||
                   (ci_contains(text, "covenant") && ci_contains(text, " -")) ||
                   (ci_contains(text, "empire") && ci_contains(text, " -")) ||
                   (ci_contains(text, "merlin") && ci_contains(text, " -")) ||
                   (ci_contains(text, "viper") && ci_contains(text, " -")) ||
                   (ci_contains(text, "donut") && ci_contains(text, " -")) ||
                   (ci_contains(text, "freeze") && ci_contains(text, " -")) ||
                   (ci_contains(text, "scarecrow") && ci_contains(text, " -")) ||
                   (ci_contains(text, "parallax") && ci_contains(text, " -")) ||
                   (ci_contains(text, "xenomorph") && ci_contains(text, " -")) ||
                   (ci_contains(text, "redline") && ci_contains(text, " -")) ||
                   (ci_contains(text, "raccoon") && ci_contains(text, " -")) ||
                   (ci_contains(text, "vidar") && ci_contains(text, " -")) ||
                   (ci_contains(text, "bumblebee") && ci_contains(text, " -"))) {
            what = "AD-recon/C2/offensive-tool name";
        } else if (ci_contains(text, "asyncrat") || ci_contains(text, "njrat") ||
                   ci_contains(text, "nanocore") || ci_contains(text, "remcos") ||
                   ci_contains(text, "xworm") || ci_contains(text, "venomrat") ||
                   ci_contains(text, "purecrypter") || ci_contains(text, "azorult") ||
                   ci_contains(text, "agenttesla") || ci_contains(text, "agent tesla") ||
                   ci_contains(text, "formbook") || ci_contains(text, "lokibot") ||
                   ci_contains(text, "guloader") || ci_contains(text, "smokeloader") ||
                   ci_contains(text, "icedid") || ci_contains(text, "qakbot") ||
                   ci_contains(text, "qbot") || ci_contains(text, "emotet") ||
                   ci_contains(text, "trickbot") || ci_contains(text, "dridex") ||
                   ci_contains(text, "ursnif") || ci_contains(text, "spyeye") ||
                   ci_contains(text, "danabot") || ci_contains(text, "flubot") ||
                   ci_contains(text, "sharkbot") || ci_contains(text, "ermac") ||
                   ci_contains(text, "spynote") || ci_contains(text, "spymax") ||
                   ci_contains(text, "ahmyth") || ci_contains(text, "droidjack") ||
                   ci_contains(text, "androrat") || ci_contains(text, "omnirat") ||
                   ci_contains(text, "quasarrat") || ci_contains(text, "beef-xss") ||
                   ci_contains(text, "setoolkit") || ci_contains(text, "gophish") ||
                   ci_contains(text, "evilginx") || ci_contains(text, "modlishka") ||
                   ci_contains(text, "zphisher") || ci_contains(text, "shellphish") ||
                   ci_contains(text, "blackeye") || ci_contains(text, "advphishing") ||
                   ci_contains(text, "king-phisher") || ci_contains(text, "wifiphisher") ||
                   ci_contains(text, "wifipumpkin") || ci_contains(text, "airgeddon")) {
            what = "malware-family/phishing-kit name";
        } else if ((ci_contains(text, "install") &&
                    (ci_contains(text, " -m 4") || ci_contains(text, " -m 2") ||
                     ci_contains(text, " -m u+s") || ci_contains(text, " -m +s"))) ||
                   (ci_contains(text, "robocopy") && ci_contains(text, " /b")) ||
                   (ci_contains(text, "runas") && ci_contains(text, "/savecred")) ||
                   (ci_contains(text, "sqlite3") &&
                    (ci_contains(text, "cookies") || ci_contains(text, "logins") ||
                     ci_contains(text, "moz_logins") || ci_contains(text, "login data") ||
                     ci_contains(text, "web data") || ci_contains(text, "places.sqlite"))) ||
                   (ci_contains(text, "msbuild") &&
                    (ci_contains(text, " \\\\") || ci_contains(text, "http"))) ||
                   (ci_contains(text, "esentutl") && ci_contains(text, " /y")) ||
                   ci_contains(text, "extrac32") || ci_contains(text, "wextract") ||
                   ci_contains(text, "pcwrun") || ci_contains(text, "masvc") ||
                   (ci_contains(text, "oobe") && ci_contains(text, " -")) ||
                   (ci_contains(text, "ieexec") &&
                    (ci_contains(text, " http") || ci_contains(text, " \\\\"))) ||
                   (ci_contains(text, "ie4uinit") && ci_contains(text, " -show")) ||
                   (ci_contains(text, "installutil") &&
                    (ci_contains(text, " http") || ci_contains(text, " \\\\") ||
                     ci_contains(text, " /u"))) ||
                   (ci_contains(text, "regasm") &&
                    (ci_contains(text, " http") || ci_contains(text, " \\\\") ||
                     ci_contains(text, " /u"))) ||
                   (ci_contains(text, "regsvcs") &&
                    (ci_contains(text, " http") || ci_contains(text, " \\\\") ||
                     ci_contains(text, " /u"))) ||
                   (ci_contains(text, "msxsl") &&
                    (ci_contains(text, " http") || ci_contains(text, " \\\\"))) ||
                   (ci_contains(text, "ilasm") &&
                    (ci_contains(text, " http") || ci_contains(text, " \\\\"))) ||
                   (ci_contains(text, "verclsid") &&
                    ci_contains(text, " /s") && ci_contains(text, " /c")) ||
                   (ci_contains(text, "syncappvpublishingserver") &&
                    (ci_contains(text, "\";") || ci_contains(text, "';"))) ||
                   (ci_contains(text, "pcalua") && ci_contains(text, " -a")) ||
                   (ci_contains(text, "procdump") &&
                    (ci_contains(text, " -ma") || ci_contains(text, " -mm") ||
                     ci_contains(text, "lsass")))) {
            what = "suid-install/cred-db/lolbin-name primitive";
        /* c240: process-memory/core scrape + namespace/dbus exec +
         * stream/upload exfil + file-serve hosts + MITM + macOS
         * defense-off/exec/account primitives ── */
        } else if ((ci_contains(text, "lldb") && ci_contains(text, " -p")) ||
                   ci_contains(text, "gcore") || ci_contains(text, "eu-stack") ||
                   ci_contains(text, "procstat") ||
                   (ci_contains(text, "coredumpctl") &&
                    (ci_contains(text, " dump") || ci_contains(text, " gdb") ||
                     ci_contains(text, " debug"))) ||
                   ((ci_contains(text, "cat ") || ci_contains(text, "head ") ||
                     ci_contains(text, "xxd ") || ci_contains(text, "strings ") ||
                     ci_contains(text, "hexdump") || ci_contains(text, "tail ") ||
                     ci_contains(text, "od ")) &&
                    (ci_contains(text, " /dev/mem") ||
                     ci_contains(text, " /dev/kmem") ||
                     ci_contains(text, " /dev/port"))) ||
                   (ci_contains(text, "/proc/") &&
                    ((ci_contains(text, "/mem") &&
                      !ci_contains(text, "/meminfo")) ||
                     ci_contains(text, "/environ") ||
                     ci_contains(text, "/maps") ||
                     ci_contains(text, "kcore")))) {
            what = "memory/core scrape primitive";
        } else if ((ci_contains(text, "unshare") &&
                    (ci_contains(text, " -r") || ci_contains(text, " -u") ||
                     ci_contains(text, " -m") || ci_contains(text, "-rm") ||
                     ci_contains(text, "-ur") ||
                     ci_contains(text, "--map-root") ||
                     ci_contains(text, "--user") ||
                     ci_contains(text, "--mount") ||
                     ci_contains(text, "--fork"))) ||
                   (ci_contains(text, "machinectl") &&
                    (ci_contains(text, "shell") || ci_contains(text, "exec"))) ||
                   (ci_contains(text, "busctl") && ci_contains(text, " call")) ||
                   (ci_contains(text, "dbus-send") && ci_contains(text, "--system")) ||
                   (ci_contains(text, "loginctl") &&
                    ci_contains(text, "enable-linger"))) {
            what = "namespace/dbus/systemd exec primitive";
        } else if (((ci_contains(text, "nc ") || ci_contains(text, "ncat") ||
                     ci_contains(text, "netcat")) && ci_contains(text, " <")) ||
                   ((ci_contains(text, "tar") || ci_contains(text, "dd ") ||
                     ci_contains(text, "cat ")) &&
                    (ci_contains(text, "| nc") || ci_contains(text, "|nc") ||
                     ci_contains(text, "| ssh") || ci_contains(text, "|ssh") ||
                     ci_contains(text, "| socat") ||
                     ci_contains(text, "|socat"))) ||
                   (ci_contains(text, "nsupdate") &&
                    (ci_contains(text, " -k") || ci_contains(text, " -y"))) ||
                   (ci_contains(text, "openssl") &&
                    ci_contains(text, "s_server")) ||
                   ci_contains(text, "cryptcat") ||
                   ci_contains(text, "php -s") ||
                   ci_contains(text, "-m http.server") ||
                   ci_contains(text, "ruby -run") ||
                   ci_contains(text, "darkhttpd") ||
                   ci_contains(text, "miniserve") || ci_contains(text, "webfsd") ||
                   ci_contains(text, "thttpd") || ci_contains(text, "smbserver") ||
                   ci_contains(text, "updog") || ci_contains(text, "twistd") ||
                   ci_contains(text, "-m smtpd") ||
                   ((ci_contains(text, "ifconfig") ||
                     ci_contains(text, "ip link")) &&
                    ci_contains(text, "promisc")) ||
                   (ci_contains(text, "ip neigh") &&
                    (ci_contains(text, "add") || ci_contains(text, "replace") ||
                     ci_contains(text, "del")))) {
            what = "stream-exfil/serve-host/mitm primitive";
        } else if ((ci_contains(text, "spctl") &&
                    (ci_contains(text, "global-disable") ||
                     ci_contains(text, "--add"))) ||
                   (ci_contains(text, "csrutil") &&
                    (ci_contains(text, " clear") ||
                     ci_contains(text, "authenticated-root"))) ||
                   (ci_contains(text, "fdesetup") &&
                    (ci_contains(text, "disable") ||
                     ci_contains(text, "remove") ||
                     ci_contains(text, "authrestart"))) ||
                   (ci_contains(text, "profiles") &&
                    (ci_contains(text, " -i") || ci_contains(text, " -i") ||
                     ci_contains(text, "install") ||
                     ci_contains(text, "remove"))) ||
                   (ci_contains(text, "launchctl") &&
                    (ci_contains(text, "bootout") ||
                     ci_contains(text, "disable"))) ||
                   (ci_contains(text, "dscl") &&
                    (ci_contains(text, " create") ||
                     ci_contains(text, " -create") ||
                     ci_contains(text, " passwd") ||
                     ci_contains(text, " -passwd") ||
                     ci_contains(text, " append") ||
                     ci_contains(text, " -append") ||
                     ci_contains(text, " delete") ||
                     ci_contains(text, " -delete") ||
                     ci_contains(text, " change") ||
                     ci_contains(text, " -change"))) ||
                   (ci_contains(text, "sysadminctl") &&
                    (ci_contains(text, "-adduser") ||
                     ci_contains(text, "-deleteuser") ||
                     ci_contains(text, "-resetpassword") ||
                     ci_contains(text, "-securetokeno") ||
                     ci_contains(text, "-disablesecuretoken") ||
                     ci_contains(text, "-autologin"))) ||
                   (ci_contains(text, "pwpolicy") &&
                    (ci_contains(text, "setaccount") ||
                     ci_contains(text, "setuser") ||
                     ci_contains(text, "setpass") ||
                     ci_contains(text, " -u"))) ||
                   (ci_contains(text, "defaults write") &&
                    (ci_contains(text, "loginhook") ||
                     ci_contains(text, "logouthook") ||
                     ci_contains(text, "autorun"))) ||
                   (ci_contains(text, "hdiutil") && ci_contains(text, "http")) ||
                   ci_contains(text, "do shell script") ||
                   (ci_contains(text, "security") &&
                    (ci_contains(text, "authorizationdb") ||
                     ci_contains(text, "set-keychain"))) ||
                   (ci_contains(text, "kickstart") &&
                    (ci_contains(text, "-activate") ||
                     ci_contains(text, "-configure") ||
                     ci_contains(text, "-install") ||
                     ci_contains(text, "-restart"))) ||
                   ci_contains(text, "screencapture") ||
                   ci_contains(text, "pbpaste") ||
                   (ci_contains(text, "sntp") && ci_contains(text, " -s")) ||
                   (ci_contains(text, "scutil") && ci_contains(text, "--nc")) ||
                   (ci_contains(text, "cupsctl") &&
                    ci_contains(text, "--remote")) ||
                   (ci_contains(text, "networksetup") &&
                    (ci_contains(text, "-setautologin") ||
                     ci_contains(text, "-setvnc"))) ||
                   (ci_contains(text, "shortcuts") &&
                    ci_contains(text, " run ")) ||
                   (ci_contains(text, "automator") &&
                    ci_contains(text, " -i"))) {
            what = "macOS defense-off/exec/account primitive";
        /* c241: Windows audit/ACL/AD/defense primitives + Unix
         * mount/SELinux/audit-off/xfrm/ebtables/bridge/monitor +
         * session-record + BSD + DNS/infra destructive forms ── */
        } else if ((ci_contains(text, "wevtutil") &&
                    ci_contains(text, " sl")) ||
                   (ci_contains(text, "logman") &&
                    (ci_contains(text, " create") ||
                     ci_contains(text, " delete") ||
                     ci_contains(text, " update") ||
                     ci_contains(text, " stop"))) ||
                   ci_contains(text, "pktmon") ||
                   (ci_contains(text, "netsh") &&
                    ci_contains(text, "advfirewall") &&
                    (ci_contains(text, " add ") ||
                     ci_contains(text, " delete ") ||
                     ci_contains(text, " set "))) ||
                   (ci_contains(text, "cmdkey") &&
                    ci_contains(text, " /generic")) ||
                   (ci_contains(text, "net group") &&
                    ci_contains(text, " /add")) ||
                   (ci_contains(text, "sc ") &&
                    (ci_contains(text, " failure") ||
                     ci_contains(text, " sdset"))) ||
                   (ci_contains(text, "icacls") &&
                    ci_contains(text, " /deny")) ||
                   (ci_contains(text, "cacls") &&
                    ci_contains(text, " /g") &&
                    !ci_contains(text, "icacls")) ||
                   (ci_contains(text, "subinacl") &&
                    (ci_contains(text, " /grant") ||
                     ci_contains(text, " /deny"))) ||
                   (ci_contains(text, "wbadmin") &&
                    ci_contains(text, "stop job")) ||
                   ci_contains(text, "dsquery") || ci_contains(text, "dsadd") ||
                   ci_contains(text, "dsmod") || ci_contains(text, "dsrm") ||
                   (ci_contains(text, "csvde") &&
                    ci_contains(text, " -f")) ||
                   (ci_contains(text, "ldifde") &&
                    ci_contains(text, " -f")) ||
                   (ci_contains(text, "netdom") &&
                    (ci_contains(text, " add") ||
                     ci_contains(text, " remove") ||
                     ci_contains(text, " join"))) ||
                   ci_contains(text, "nltest") ||
                   (ci_contains(text, "w32tm") &&
                    ci_contains(text, " /config")) ||
                   (ci_contains(text, "route ") &&
                    ci_contains(text, " delete")) ||
                   (ci_contains(text, "reg ") &&
                    (ci_contains(text, " save") ||
                     ci_contains(text, " export")) &&
                    (ci_contains(text, "sam") ||
                     ci_contains(text, "security") ||
                     ci_contains(text, "system") ||
                     ci_contains(text, "ntds"))) ||
                   (ci_contains(text, "msiexec") &&
                    ci_contains(text, " /x")) ||
                   (ci_contains(text, "schtasks") &&
                    ci_contains(text, " /delete")) ||
                   ci_contains(text, "rwinsta") ||
                   ci_contains(text, "tskill") || ci_contains(text, "tsshutdn") ||
                   (ci_contains(text, "dsacls") &&
                    ci_contains(text, " /g")) ||
                   (ci_contains(text, "pnputil") &&
                    (ci_contains(text, "/add-driver") ||
                     ci_contains(text, "/delete-driver")))) {
            what = "windows audit/ACL/AD/defense primitive";
        } else if ((ci_contains(text, "mount") &&
                    (ci_contains(text, "--bind") ||
                     ci_contains(text, "--rbind") ||
                     ci_contains(text, "remount"))) ||
                   (ci_contains(text, "setenforce") &&
                    ci_contains(text, "permissive")) ||
                   (ci_contains(text, "semodule") &&
                    (ci_contains(text, " -i") || ci_contains(text, " -r") ||
                     ci_contains(text, " -e") || ci_contains(text, " -d") ||
                     ci_contains(text, "--install") ||
                     ci_contains(text, "--remove"))) ||
                   (ci_contains(text, "setsebool") &&
                    (ci_contains(text, " -") || ci_contains(text, " on") ||
                     ci_contains(text, " off"))) ||
                   (ci_contains(text, "semanage") &&
                    (ci_contains(text, " -a") || ci_contains(text, " -m") ||
                     ci_contains(text, " -d") || ci_contains(text, " -r") ||
                     ci_contains(text, "--add") || ci_contains(text, "--modify") ||
                     ci_contains(text, "--delete") ||
                     ci_contains(text, "permissive"))) ||
                   ci_contains(text, "aa-disable") ||
                   ci_contains(text, "aa-teardown") ||
                   (ci_contains(text, "auditctl") &&
                    (ci_contains(text, " -e 0") || ci_contains(text, " -e0") ||
                     ci_contains(text, " -e 2") || ci_contains(text, " -e2") ||
                     ci_contains(text, " -d"))) ||
                   (ci_contains(text, "ip xfrm") &&
                    (ci_contains(text, "add") || ci_contains(text, "update") ||
                     ci_contains(text, "delete") || ci_contains(text, "flush"))) ||
                   (ci_contains(text, "ebtables") &&
                    (ci_contains(text, " -a") || ci_contains(text, " -i") ||
                     ci_contains(text, " -p") || ci_contains(text, " -f") ||
                     ci_contains(text, "--policy"))) ||
                   (ci_contains(text, "brctl") &&
                    (ci_contains(text, "addbr") || ci_contains(text, "addif") ||
                     ci_contains(text, "delbr") || ci_contains(text, "delif"))) ||
                   ((ci_contains(text, "iw ") ||
                     ci_contains(text, "iwconfig")) &&
                    ci_contains(text, "monitor")) ||
                   ci_contains(text, "airmon-ng") ||
                   ci_contains(text, "ltrace") ||
                   (ci_contains(text, "strace") &&
                    (ci_contains(text, " -f") || ci_contains(text, " -e"))) ||
                   (ci_contains(text, "script ") &&
                    ci_contains(text, " -q")) ||
                   ci_contains(text, "ttyrec") ||
                   (ci_contains(text, "asciinema") &&
                    ci_contains(text, " rec")) ||
                   ci_contains(text, "sysdig") || ci_contains(text, "falco ") ||
                   ci_contains(text, "kldload") || ci_contains(text, "kldunload") ||
                   (ci_contains(text, "ipfw") &&
                    (ci_contains(text, "add") || ci_contains(text, "flush") ||
                     ci_contains(text, "delete") || ci_contains(text, "pipe") ||
                     ci_contains(text, "queue"))) ||
                   (ci_contains(text, "svc ") &&
                    ci_contains(text, " -d")) ||
                   (ci_contains(text, "rcctl") &&
                    (ci_contains(text, "stop") || ci_contains(text, "disable") ||
                     ci_contains(text, "restart"))) ||
                   (ci_contains(text, "kexec") &&
                    (ci_contains(text, " -l") || ci_contains(text, " -e"))) ||
                   (ci_contains(text, "grubby") &&
                    ci_contains(text, "--args")) ||
                   ci_contains(text, "grub2-set-default") ||
                   ci_contains(text, "grub-set-default") ||
                   (ci_contains(text, "dracut") &&
                    (ci_contains(text, "--add") ||
                     ci_contains(text, "--install") ||
                     ci_contains(text, "--add-drivers") ||
                     ci_contains(text, "--kernel-image"))) ||
                   (ci_contains(text, "realm") &&
                    (ci_contains(text, " join") ||
                     ci_contains(text, " leave"))) ||
                   (ci_contains(text, "adcli") &&
                    (ci_contains(text, " join") ||
                     ci_contains(text, " delete") ||
                     ci_contains(text, " create"))) ||
                   (ci_contains(text, "authselect") &&
                    (ci_contains(text, " select") ||
                     ci_contains(text, " apply") ||
                     ci_contains(text, " enable") ||
                     ci_contains(text, " disable"))) ||
                   (ci_contains(text, "authconfig") &&
                    (ci_contains(text, "--update") ||
                     ci_contains(text, "--enable") ||
                     ci_contains(text, "--disable"))) ||
                   (ci_contains(text, "cryptsetup") &&
                    (ci_contains(text, "luksremovekey") ||
                     ci_contains(text, "lukskillslot") ||
                     ci_contains(text, "reencrypt") ||
                     ci_contains(text, "luksheaderbackup") ||
                     ci_contains(text, " remove"))) ||
                   (ci_contains(text, "resolvectl") &&
                    (ci_contains(text, " dns ") ||
                     ci_contains(text, " nta")))) {
            what = "unix mount/selinux/audit/l2/session-record primitive";
        } else if ((ci_contains(text, "rndc") &&
                    (ci_contains(text, "flush") || ci_contains(text, "reload") ||
                     ci_contains(text, "addzone") || ci_contains(text, "delzone") ||
                     ci_contains(text, "modzone") || ci_contains(text, "signing") ||
                     ci_contains(text, "halt") || ci_contains(text, "stop"))) ||
                   (ci_contains(text, "unbound-control") &&
                    (ci_contains(text, "reload") || ci_contains(text, "load") ||
                     ci_contains(text, "flush") || ci_contains(text, "stub") ||
                     ci_contains(text, "forward"))) ||
                   ci_contains(text, "knotc") ||
                   ci_contains(text, "pdns_control") ||
                   (ci_contains(text, "terraform") &&
                    ci_contains(text, " destroy")) ||
                   (ci_contains(text, "pulumi") &&
                    ci_contains(text, " destroy")) ||
                   (ci_contains(text, "tofu") &&
                    ci_contains(text, " destroy")) ||
                   (ci_contains(text, "kubectl") &&
                    ci_contains(text, " delete") &&
                    ci_contains(text, "--all")) ||
                   (ci_contains(text, "vault") &&
                    (ci_contains(text, " kv") ||
                     ci_contains(text, " secrets") ||
                     ci_contains(text, " policy") ||
                     ci_contains(text, " token"))) ||
                   (ci_contains(text, "consul") &&
                    (ci_contains(text, " kv") ||
                     ci_contains(text, " exec"))) ||
                   (ci_contains(text, "etcdctl") &&
                    (ci_contains(text, " put") || ci_contains(text, " del") ||
                     ci_contains(text, " txn"))) ||
                   (ci_contains(text, "nomad") &&
                    (ci_contains(text, " exec") ||
                     ci_contains(text, " alloc") ||
                     ci_contains(text, " stop"))) ||
                   (ci_contains(text, "aws") &&
                    (ci_contains(text, "s3 rb") ||
                     ci_contains(text, "s3api delete"))) ||
                   (ci_contains(text, "gsutil") &&
                    (ci_contains(text, " rm") || ci_contains(text, " rb"))) ||
                   (ci_contains(text, "az storage") &&
                    (ci_contains(text, " delete") ||
                     ci_contains(text, " remove"))) ||
                   ci_contains(text, "aria2c") || ci_contains(text, "httpie") ||
                   (ci_contains(text, "transmission-remote") &&
                    ci_contains(text, " -a")) ||
                   (ci_contains(text, "nmcli") &&
                    (ci_contains(text, " mod") ||
                     ci_contains(text, " down") ||
                     ci_contains(text, " delete")))) {
            what = "dns-control/infra-destruct/cloud-wipe primitive";
        /* c242: Windows eventlog/defense/firewall/AD PS cmdlets +
         * boot/cert/sticky-keys/tunnel/exec primitives ── */
        } else if (ci_contains(text, "eventcreate") ||
                   ci_contains(text, "clear-eventlog") ||
                   ci_contains(text, "remove-eventlog") ||
                   ci_contains(text, "limit-eventlog") ||
                   ci_contains(text, "new-eventlog") ||
                   ci_contains(text, "write-eventlog") ||
                   ci_contains(text, "get-eventlog") ||
                   ci_contains(text, "get-winevent") ||
                   ci_contains(text, "new-netfirewallrule") ||
                   ci_contains(text, "set-netfirewallrule") ||
                   ci_contains(text, "disable-netfirewallrule") ||
                   ci_contains(text, "remove-netfirewallrule") ||
                   (ci_contains(text, "set-netfirewallprofile") &&
                    ci_contains(text, "false")) ||
                   ci_contains(text, "disable-netadapter") ||
                   ci_contains(text, "set-dnsclientserveraddress") ||
                   ci_contains(text, "set-dnsclientglobalsetting") ||
                   ci_contains(text, "new-netipaddress") ||
                   ci_contains(text, "remove-netipaddress") ||
                   ci_contains(text, "set-netipaddress") ||
                   ci_contains(text, "remove-netroute") ||
                   ci_contains(text, "new-netroute") ||
                   ci_contains(text, "new-netneighbor") ||
                   ci_contains(text, "set-netneighbor") ||
                   ci_contains(text, "remove-netneighbor") ||
                   (ci_contains(text, "remove-item") &&
                    ci_contains(text, "-recurse") &&
                    ci_contains(text, "-force")) ||
                   ci_contains(text, "add-computer") ||
                   ci_contains(text, "remove-computer") ||
                   ci_contains(text, "set-smbserverconfiguration") ||
                   ci_contains(text, "set-smbclientconfiguration") ||
                   ci_contains(text, "new-smbshare") ||
                   ci_contains(text, "remove-smbshare") ||
                   ci_contains(text, "set-smbshare") ||
                   ci_contains(text, "grant-smbshareaccess") ||
                   ci_contains(text, "block-smbshareaccess") ||
                   ci_contains(text, "invoke-dcsync") ||
                   ci_contains(text, "invoke-kerberoast") ||
                   ci_contains(text, "invoke-tokenman") ||
                   ci_contains(text, "invoke-reflective") ||
                   ci_contains(text, "invoke-dllinjection") ||
                   ci_contains(text, "invoke-shell") ||
                   ci_contains(text, "invoke-ninjacopy") ||
                   ci_contains(text, "invoke-credential") ||
                   ci_contains(text, "invoke-userhunter") ||
                   ci_contains(text, "invoke-stealthuserhunter") ||
                   ci_contains(text, "invoke-psexec") ||
                   ci_contains(text, "invoke-wmiexec") ||
                   ci_contains(text, "invoke-smbexec") ||
                   ci_contains(text, "invoke-dcomexec") ||
                   ci_contains(text, "invoke-bloodhound") ||
                   ci_contains(text, "invoke-powerview") ||
                   ci_contains(text, "invoke-assembledbinary") ||
                   ci_contains(text, "invoke-inveigh") ||
                   ci_contains(text, "invoke-empire") ||
                   ci_contains(text, "invoke-sharphound") ||
                   ci_contains(text, "invoke-recon") ||
                   ci_contains(text, "get-aduser") ||
                   ci_contains(text, "get-adcomputer") ||
                   ci_contains(text, "get-adgroupmember") ||
                   ci_contains(text, "get-addomain") ||
                   ci_contains(text, "get-forest") ||
                   ci_contains(text, "get-domaintrust") ||
                   ci_contains(text, "get-gpo") ||
                   ci_contains(text, "get-adobject") ||
                   ci_contains(text, "set-aduser") ||
                   ci_contains(text, "set-adobject") ||
                   ci_contains(text, "new-adobject") ||
                   ci_contains(text, "add-domainobjectacl") ||
                   ci_contains(text, "set-domainobject") ||
                   ci_contains(text, "get-adprincipal") ||
                   ci_contains(text, "get-adserviceaccount") ||
                   ci_contains(text, "remove-aduser") ||
                   ci_contains(text, "remove-adcomputer") ||
                   ci_contains(text, "remove-adgroupmember") ||
                   ci_contains(text, "get-adgroup") ||
                   ci_contains(text, "get-addomaincontroller") ||
                   ci_contains(text, "set-adaccountpassword") ||
                   ci_contains(text, "enable-adaccount") ||
                   ci_contains(text, "unlock-adaccount") ||
                   (ci_contains(text, "new-psdrive") &&
                    ci_contains(text, "\\\\")) ||
                   (ci_contains(text, "net computer") &&
                    (ci_contains(text, " /add") ||
                     ci_contains(text, " /del"))) ||
                   (ci_contains(text, "bash.exe") &&
                    ci_contains(text, " -c")) ||
                   (ci_contains(text, "regedit") &&
                    (ci_contains(text, " /e") ||
                     ci_contains(text, " /s"))) ||
                   ci_contains(text, "regini") ||
                   ci_contains(text, "hh.exe") ||
                   ci_contains(text, "hh ") ||
                   ci_contains(text, "sdbinst") ||
                   ((ci_contains(text, "vbc ") ||
                     ci_contains(text, "vbc.exe") ||
                     ci_contains(text, "csc ") ||
                     ci_contains(text, "csc.exe")) &&
                    (ci_contains(text, " /") || ci_contains(text, "-") ||
                     ci_contains(text, ".cs") || ci_contains(text, ".vb"))) ||
                   ((ci_contains(text, "jsc ") ||
                     ci_contains(text, "jsc.exe")) &&
                    (ci_contains(text, " /") || ci_contains(text, "-") ||
                     ci_contains(text, ".js"))) ||
                   (ci_contains(text, "caspol") &&
                    (ci_contains(text, " -s") || ci_contains(text, " -m") ||
                     ci_contains(text, " -a") || ci_contains(text, " -pp") ||
                     ci_contains(text, " -cg") || ci_contains(text, " -rs") ||
                     ci_contains(text, " -en"))) ||
                   (ci_contains(text, "infdefaultinstall") &&
                    (ci_contains(text, " /") || ci_contains(text, "-") ||
                     ci_contains(text, ".inf") || ci_contains(text, "http"))) ||
                   ci_contains(text, "settingcontent") ||
                   ci_contains(text, "dfshim") || ci_contains(text, "dfsvc") ||
                   ci_contains(text, "xbap") ||
                   (ci_contains(text, "winscp") &&
                    (ci_contains(text, " /command") ||
                     ci_contains(text, " /script") ||
                     ci_contains(text, " /console"))) ||
                   (ci_contains(text, "plink") &&
                    ci_contains(text, " -")) ||
                   (ci_contains(text, "pscp") &&
                    ci_contains(text, " -")) ||
                   ci_contains(text, "net1 ") ||
                   (ci_contains(text, "msra") &&
                    (ci_contains(text, "/offerra") ||
                     ci_contains(text, "/saveasfile") ||
                     ci_contains(text, "/novice") ||
                     ci_contains(text, "/expert"))) ||
                   ci_contains(text, "tsdiscon") ||
                   (ci_contains(text, "bcdedit") &&
                    (ci_contains(text, "/delete") ||
                     ci_contains(text, "/create") ||
                     ci_contains(text, "/set") ||
                     ci_contains(text, "/emssettings") ||
                     ci_contains(text, "/bootsequence") ||
                     ci_contains(text, "/default") ||
                     ci_contains(text, "/timeout") ||
                     ci_contains(text, "-set"))) ||
                   ci_contains(text, "bootsect") ||
                   (ci_contains(text, "bootrec") &&
                    (ci_contains(text, "/fix") ||
                     ci_contains(text, "/rebuild") ||
                     ci_contains(text, "/scanos"))) ||
                   ci_contains(text, "bcdboot") ||
                   (ci_contains(text, "certreq") &&
                    (ci_contains(text, "-submit") ||
                     ci_contains(text, "-retrieve") ||
                     ci_contains(text, "-new") ||
                     ci_contains(text, "-enroll") ||
                     ci_contains(text, "-config"))) ||
                   (ci_contains(text, "certutil") &&
                    (ci_contains(text, "-exportpfx") ||
                     ci_contains(text, "-importpfx") ||
                     ci_contains(text, "-addstore") ||
                     ci_contains(text, "-delstore") ||
                     ci_contains(text, "-key") ||
                     ci_contains(text, "-backup") ||
                     ci_contains(text, "-restorekey") ||
                     ci_contains(text, "-importcert") ||
                     ci_contains(text, "-delkey"))) ||
                   ci_contains(text, "pvk2pfx") ||
                   ci_contains(text, "pvkimprt") ||
                   (ci_contains(text, "signtool") &&
                    (ci_contains(text, " sign") ||
                     ci_contains(text, " timestamp"))) ||
                   (ci_contains(text, "nbtstat") &&
                    (ci_contains(text, " -a") || ci_contains(text, " -c") ||
                     ci_contains(text, " -s") || ci_contains(text, " -r"))) ||
                   (ci_contains(text, "ipconfig") &&
                    (ci_contains(text, "/displaydns") ||
                     ci_contains(text, "/flushdns"))) ||
                   ((ci_contains(text, "copy") ||
                     ci_contains(text, "move") ||
                     ci_contains(text, "replace") ||
                     ci_contains(text, "ren ")) &&
                    ci_contains(text, "system32") &&
                    (ci_contains(text, "utilman") ||
                     ci_contains(text, "sethc") ||
                     ci_contains(text, "osk") ||
                     ci_contains(text, "narrator") ||
                     ci_contains(text, "magnify") ||
                     ci_contains(text, "atbroker") ||
                     ci_contains(text, "displayswitch"))) ||
                   (ci_contains(text, "netsh") &&
                    (ci_contains(text, " trace") &&
                     (ci_contains(text, " start") ||
                      ci_contains(text, " stop")))) ||
                   (ci_contains(text, "netsh") &&
                    ci_contains(text, "http") &&
                    (ci_contains(text, "add urlacl") ||
                     ci_contains(text, "add sslcert") ||
                     ci_contains(text, "delete urlacl") ||
                     ci_contains(text, "delete sslcert"))) ||
                   (ci_contains(text, "netsh") &&
                    (ci_contains(text, "dnsclient") ||
                     ci_contains(text, "dnsserver")) &&
                    (ci_contains(text, " add") ||
                     ci_contains(text, " set"))) ||
                   (ci_contains(text, "wusa") &&
                    ci_contains(text, "/uninstall")) ||
                   (ci_contains(text, "dism") &&
                    (ci_contains(text, "/remove") ||
                     ci_contains(text, "/disable"))) ||
                   (ci_contains(text, "fltmc") &&
                    (ci_contains(text, "unload") ||
                     ci_contains(text, "detach"))) ||
                   ci_contains(text, "lodctr") ||
                   ci_contains(text, "unlodctr") ||
                   (ci_contains(text, "psr") &&
                    (ci_contains(text, " /") ||
                     ci_contains(text, " -"))) ||
                   (ci_contains(text, "sysprep") &&
                    (ci_contains(text, "/generalize") ||
                     ci_contains(text, "/oobe") ||
                     ci_contains(text, "/audit") ||
                     ci_contains(text, "/reboot"))) ||
                   (ci_contains(text, "netdom") &&
                    ci_contains(text, " "))) {
            what = "windows eventlog/defense/ad/boot/cert primitive";
        /* c242: unix net-config writes + audit/anti-forensics +
         * account file edits + selinux/dhcp/postfix + pkg removal ── */
        } else if ((ci_contains(text, "history") &&
                    (ci_contains(text, " -c") ||
                     ci_contains(text, " -w") ||
                     ci_contains(text, " -d"))) ||
                   ci_contains(text, "unset histfile") ||
                   (ci_contains(text, "histfile=") &&
                    ci_contains(text, "null")) ||
                   (ci_contains(text, "crontab") &&
                    ci_contains(text, " -r")) ||
                   ci_contains(text, "atrm") ||
                   (ci_contains(text, "apt") &&
                    (ci_contains(text, " remove") ||
                     ci_contains(text, " purge"))) ||
                   (ci_contains(text, "yum") &&
                    (ci_contains(text, " remove") ||
                     ci_contains(text, " erase"))) ||
                   (ci_contains(text, "dnf") &&
                    (ci_contains(text, " remove") ||
                     ci_contains(text, " erase"))) ||
                   (ci_contains(text, "zypper") &&
                    (ci_contains(text, " rm") ||
                     ci_contains(text, " remove"))) ||
                   (ci_contains(text, "pacman") &&
                    (ci_contains(text, " -r") ||
                     ci_contains(text, " -rs"))) ||
                   (ci_contains(text, "apk") &&
                    ci_contains(text, " del")) ||
                   (ci_contains(text, "dpkg") &&
                    (ci_contains(text, " -r") ||
                     ci_contains(text, "--remove") ||
                     ci_contains(text, "--purge"))) ||
                   ci_contains(text, "vipw") || ci_contains(text, "vigr") ||
                   ci_contains(text, "pwunconv") ||
                   ci_contains(text, "grpunconv") ||
                   ci_contains(text, "newusers") ||
                   ci_contains(text, "deluser") ||
                   ci_contains(text, "delgroup") ||
                   ci_contains(text, "pam-auth-update") ||
                   ci_contains(text, "chcon") ||
                   (ci_contains(text, "audit2allow") &&
                    (ci_contains(text, " -a") || ci_contains(text, " -m") ||
                     ci_contains(text, " -l") || ci_contains(text, " -r") ||
                     ci_contains(text, "--all") ||
                     ci_contains(text, "--module"))) ||
                   ci_contains(text, "load_policy") ||
                   ci_contains(text, "semodule_package") ||
                   ci_contains(text, "semodule_link") ||
                   ci_contains(text, "semodule_expand") ||
                   ci_contains(text, "semodule_deps") ||
                   ci_contains(text, "setfiles") ||
                   (ci_contains(text, "dhclient") &&
                    (ci_contains(text, " -sf") ||
                     ci_contains(text, " -cf") ||
                     ci_contains(text, " -lf") ||
                     ci_contains(text, " -pf"))) ||
                   (ci_contains(text, "postconf") &&
                    ci_contains(text, " -e")) ||
                   (ci_contains(text, "postfix") &&
                    (ci_contains(text, " stop") ||
                     ci_contains(text, " flush") ||
                     ci_contains(text, " abort"))) ||
                   (ci_contains(text, "ipsec") &&
                    (ci_contains(text, " stop") ||
                     ci_contains(text, " restart") ||
                     ci_contains(text, " down") ||
                     ci_contains(text, " reload") ||
                     ci_contains(text, " update") ||
                     ci_contains(text, " route") ||
                     ci_contains(text, " unroute"))) ||
                   (ci_contains(text, "strongswan") &&
                    (ci_contains(text, " stop") ||
                     ci_contains(text, " restart") ||
                     ci_contains(text, " down") ||
                     ci_contains(text, " purge"))) ||
                   (ci_contains(text, "conntrack") &&
                    (ci_contains(text, " -d") ||
                     ci_contains(text, " -f") ||
                     ci_contains(text, " -i"))) ||
                   ((ci_contains(text, "ip route") ||
                     ci_contains(text, "ip ro ")) &&
                    (ci_contains(text, " add") ||
                     ci_contains(text, " del") ||
                     ci_contains(text, " replace") ||
                     ci_contains(text, " flush") ||
                     ci_contains(text, " chang"))) ||
                   (ci_contains(text, "ip rule") &&
                    (ci_contains(text, " add") ||
                     ci_contains(text, " del") ||
                     ci_contains(text, " flush"))) ||
                   (ci_contains(text, "ip tunnel") &&
                    (ci_contains(text, " add") ||
                     ci_contains(text, " del") ||
                     ci_contains(text, " chang"))) ||
                   (ci_contains(text, "ip link") &&
                    ci_contains(text, " add ") &&
                    ci_contains(text, "type ") &&
                    (ci_contains(text, "bridge") ||
                     ci_contains(text, "veth") ||
                     ci_contains(text, "vxlan") ||
                     ci_contains(text, "macvlan") ||
                     ci_contains(text, "macvtap") ||
                     ci_contains(text, "macsec") ||
                     ci_contains(text, "dummy") ||
                     ci_contains(text, "ipip") ||
                     ci_contains(text, "gre") ||
                     ci_contains(text, "sit") ||
                     ci_contains(text, "vrf") ||
                     ci_contains(text, "vcan") ||
                     ci_contains(text, "vxcan") ||
                     ci_contains(text, "geneve") ||
                     ci_contains(text, "erspan") ||
                     ci_contains(text, "gretap") ||
                     ci_contains(text, "vti") ||
                     ci_contains(text, "nlmon") ||
                     ci_contains(text, "ipoib"))) ||
                   (ci_contains(text, "tc ") &&
                    (ci_contains(text, "mirred") ||
                     ci_contains(text, " ingress") ||
                     ci_contains(text, "redirect"))) ||
                   (ci_contains(text, "nft") &&
                    (ci_contains(text, "masquerade") ||
                     ci_contains(text, " redirect") ||
                     ci_contains(text, " dnat") ||
                     ci_contains(text, " snat") ||
                     ci_contains(text, " tproxy") ||
                     ci_contains(text, " add table") ||
                     ci_contains(text, " add chain"))) ||
                   (ci_contains(text, "firewall-cmd") &&
                    (ci_contains(text, "--permanent") ||
                     ci_contains(text, "--direct") ||
                     ci_contains(text, "--panic"))) ||
                   (ci_contains(text, "ufw") &&
                    (ci_contains(text, " disable") ||
                     ci_contains(text, " reset"))) ||
                   (ci_contains(text, "fail2ban-client") &&
                    (ci_contains(text, "unban") ||
                     ci_contains(text, " stop") ||
                     ci_contains(text, " set "))) ||
                   (ci_contains(text, "bridge") &&
                    (ci_contains(text, " fdb ") ||
                     ci_contains(text, " vlan ") ||
                     ci_contains(text, " link ")) &&
                    (ci_contains(text, " add") ||
                     ci_contains(text, " del") ||
                     ci_contains(text, " append") ||
                     ci_contains(text, " replace") ||
                     ci_contains(text, " set"))) ||
                   ci_contains(text, "ovs-vsctl") ||
                   (ci_contains(text, "ovs-ofctl") &&
                    (ci_contains(text, "add-flow") ||
                     ci_contains(text, "del-flow") ||
                     ci_contains(text, "mod-flow") ||
                     ci_contains(text, "bundle") ||
                     ci_contains(text, "replace"))) ||
                   (ci_contains(text, "ovs-dpctl") &&
                    (ci_contains(text, "add") ||
                     ci_contains(text, "del") ||
                     ci_contains(text, "flush"))) ||
                   (ci_contains(text, "ethtool") &&
                    ci_contains(text, " -s ")) ||
                   ci_contains(text, "hostapd") ||
                   ci_contains(text, "airbase-ng") ||
                   ci_contains(text, "aireplay-ng") ||
                   ci_contains(text, "aircrack-ng") ||
                   (ci_contains(text, "reaver") &&
                    ci_contains(text, " -")) ||
                   (ci_contains(text, "bully") &&
                    ci_contains(text, " -")) ||
                   ci_contains(text, "mdk3") || ci_contains(text, "mdk4") ||
                   ci_contains(text, "wifite") ||
                   ci_contains(text, "fluxion") ||
                   ci_contains(text, "eaphammer") ||
                   ci_contains(text, "kismet") ||
                   (ci_contains(text, "responder") &&
                    ci_contains(text, " -")) ||
                   ci_contains(text, "mitm6") ||
                   ci_contains(text, "ntlmrelayx") ||
                   ci_contains(text, "impacket-") ||
                   ci_contains(text, "secretsdump") ||
                   ci_contains(text, "psexec") ||
                   ci_contains(text, "wmiexec") ||
                   ci_contains(text, "smbexec") ||
                   ci_contains(text, "atexec") ||
                   ci_contains(text, "dcomexec") ||
                   ci_contains(text, "addcomputer") ||
                   ci_contains(text, "rbcd") ||
                   ci_contains(text, "dacledit") ||
                   ci_contains(text, "shadowcoerce") ||
                   ci_contains(text, "petitpotam") ||
                   ci_contains(text, "ticketer") ||
                   ci_contains(text, "raisechild") ||
                   ci_contains(text, "getst") ||
                   ci_contains(text, "getnpusers") ||
                   ci_contains(text, "getadusers") ||
                   ci_contains(text, "lookupsid") ||
                   ci_contains(text, "samrdump") ||
                   ci_contains(text, "rpcdump") ||
                   ci_contains(text, "netview") ||
                   ci_contains(text, "finddelegation") ||
                   ci_contains(text, "getpac") ||
                   ci_contains(text, "goldenpac") ||
                   ci_contains(text, "krbrelayx") ||
                   ci_contains(text, "whisker") ||
                   ci_contains(text, "adidnsdump") ||
                   ci_contains(text, "dnstool") ||
                   ci_contains(text, "coercer") ||
                   ci_contains(text, "dpapi") ||
                   ci_contains(text, "sharpdpapi") ||
                   ci_contains(text, "sharpsccm") ||
                   ci_contains(text, "sccmhunter") ||
                   ci_contains(text, "azurehound") ||
                   ci_contains(text, "roadrecon") ||
                   ci_contains(text, "stormspotter")) {
            what = "unix net-config/audit/account/package primitive";
        /* c242: offensive tool names — scan/brute/exploit/c2/webshell/
         * cred-dump/privesc/k8s-attack/fleet-exec/tunnel families ── */
        } else if ((ci_contains(text, "nmap") &&
                    ci_contains(text, " -")) ||
                   ci_contains(text, "masscan") ||
                   ci_contains(text, "zmap") || ci_contains(text, "zgrab") ||
                   ci_contains(text, "rustscan") ||
                   ci_contains(text, "naabu") ||
                   ci_contains(text, "hping") ||
                   ci_contains(text, "arping") ||
                   (ci_contains(text, "fping") &&
                    ci_contains(text, " -g")) ||
                   ci_contains(text, "unicornscan") ||
                   ci_contains(text, "dnsrecon") ||
                   ci_contains(text, "fierce") ||
                   ci_contains(text, "dnsenum") ||
                   ci_contains(text, "dnsmap") ||
                   ci_contains(text, "massdns") ||
                   ci_contains(text, "subbrute") ||
                   ci_contains(text, "sublist3r") ||
                   ci_contains(text, "amass") ||
                   ci_contains(text, "subfinder") ||
                   ci_contains(text, "assetfinder") ||
                   ci_contains(text, "findomain") ||
                   ci_contains(text, "httprobe") ||
                   ci_contains(text, "httpx") ||
                   (ci_contains(text, "gau") &&
                    ci_contains(text, " ")) ||
                   ci_contains(text, "waybackurls") ||
                   ci_contains(text, "katana") ||
                   ci_contains(text, "hakrawler") ||
                   ci_contains(text, "gospider") ||
                   ci_contains(text, "gobuster") ||
                   ci_contains(text, "ffuf") ||
                   ci_contains(text, "dirb") ||
                   ci_contains(text, "dirsearch") ||
                   ci_contains(text, "feroxbuster") ||
                   ci_contains(text, "wfuzz") ||
                   ci_contains(text, "nuclei") ||
                   (ci_contains(text, "nikto") &&
                    ci_contains(text, " -")) ||
                   ci_contains(text, "wpscan") ||
                   ci_contains(text, "joomscan") ||
                   ci_contains(text, "droopescan") ||
                   ci_contains(text, "cmsmap") ||
                   ci_contains(text, "sqlmap") ||
                   ci_contains(text, "ghauri") ||
                   ci_contains(text, "commix") ||
                   ci_contains(text, "nosqlmap") ||
                   ci_contains(text, "xsstrike") ||
                   ci_contains(text, "dalfox") ||
                   ci_contains(text, "skipfish") ||
                   ci_contains(text, "w3af") ||
                   ci_contains(text, "arachni") ||
                   ci_contains(text, "wapiti") ||
                   ci_contains(text, "zaproxy") ||
                   ci_contains(text, "burpsuite") ||
                   ci_contains(text, "arjun") ||
                   ci_contains(text, "paramspider") ||
                   ci_contains(text, "kiterunner") ||
                   (ci_contains(text, "hydra") &&
                    ci_contains(text, " -")) ||
                   (ci_contains(text, "medusa") &&
                    ci_contains(text, " -")) ||
                   ci_contains(text, "ncrack") ||
                   ci_contains(text, "patator") ||
                   (ci_contains(text, "crowbar") &&
                    ci_contains(text, " -")) ||
                   ci_contains(text, "kerbrute") ||
                   ci_contains(text, "hashcat") ||
                   (ci_contains(text, "john") &&
                    ci_contains(text, " --")) ||
                   ci_contains(text, "chntpw") ||
                   ci_contains(text, "searchsploit") ||
                   ci_contains(text, "routersploit") ||
                   ci_contains(text, "getsploit") ||
                   ci_contains(text, "whatweb") ||
                   ci_contains(text, "p0f") ||
                   ci_contains(text, "amap") ||
                   ci_contains(text, "heartleech") ||
                   ci_contains(text, "swaks") ||
                   ci_contains(text, "sipvicious") ||
                   ci_contains(text, "svmap") ||
                   ci_contains(text, "svwar") ||
                   ci_contains(text, "svcrack") ||
                   ci_contains(text, "sngrep") ||
                   ci_contains(text, "tcpreplay") ||
                   ci_contains(text, "tcprewrite") ||
                   ci_contains(text, "bittwist") ||
                   ci_contains(text, "bittwiste") ||
                   ci_contains(text, "packeth") ||
                   ci_contains(text, "scapy") ||
                   ci_contains(text, "ysoserial") ||
                   ci_contains(text, "msfvenom") ||
                   ci_contains(text, "msfconsole") ||
                   ci_contains(text, "meterpreter") ||
                   ci_contains(text, "shellter") ||
                   (ci_contains(text, "veil") &&
                    ci_contains(text, " -")) ||
                   ci_contains(text, "powercat") ||
                   ci_contains(text, "teamserver") ||
                   ci_contains(text, "cobaltstrike") ||
                   ci_contains(text, "brute-ratel") ||
                   ci_contains(text, "brc4") ||
                   ci_contains(text, "koadic") ||
                   ci_contains(text, "starkiller") ||
                   ci_contains(text, "apfell") ||
                   ci_contains(text, "trevorc2") ||
                   ci_contains(text, "gcat") ||
                   ci_contains(text, "poshc2") ||
                   ci_contains(text, "shad0w") ||
                   (ci_contains(text, "deimos") &&
                    ci_contains(text, " -")) ||
                   ci_contains(text, "godzilla") ||
                   ci_contains(text, "behinder") ||
                   ci_contains(text, "antsword") ||
                   ci_contains(text, "weevely") ||
                   ci_contains(text, "b374k") ||
                   ci_contains(text, "p0wny") ||
                   ci_contains(text, "alfashell") ||
                   ci_contains(text, "c99shell") ||
                   ci_contains(text, "wso.php") ||
                   ci_contains(text, "r57") ||
                   ci_contains(text, "lazagne") ||
                   ci_contains(text, "mimipenguin") ||
                   ci_contains(text, "linikatz") ||
                   ci_contains(text, "pypykatz") ||
                   ci_contains(text, "lsassy") ||
                   ci_contains(text, "gsecdump") ||
                   ci_contains(text, "pwdump") ||
                   ci_contains(text, "fgdump") ||
                   ci_contains(text, "cachedump") ||
                   (ci_contains(text, "wce") &&
                    ci_contains(text, " -")) ||
                   ci_contains(text, "nanodump") ||
                   ci_contains(text, "handlekatz") ||
                   ci_contains(text, "mirrordump") ||
                   ci_contains(text, "sqldumper") ||
                   ci_contains(text, "createdump") ||
                   (ci_contains(text, "comsvcs") &&
                    ci_contains(text, "minidump")) ||
                   ci_contains(text, "linpeas") ||
                   (ci_contains(text, "linenum") &&
                    !ci_contains(text, "linenumber")) ||
                   ci_contains(text, "linux-exploit-suggester") ||
                   ci_contains(text, "unix-privesc-check") ||
                   ci_contains(text, "linuxprivchecker") ||
                   ci_contains(text, "pspy") ||
                   ci_contains(text, "winpeas") ||
                   ci_contains(text, "wesng") ||
                   (ci_contains(text, "powerup") &&
                    (ci_contains(text, " -") ||
                     ci_contains(text, ".ps1"))) ||
                   ci_contains(text, "sharpup") ||
                   ci_contains(text, "beroot") ||
                   ci_contains(text, "juicypotato") ||
                   ci_contains(text, "rottenpotato") ||
                   ci_contains(text, "godpotato") ||
                   ci_contains(text, "printspoofer") ||
                   ci_contains(text, "roguepotato") ||
                   ci_contains(text, "sweetpotato") ||
                   ci_contains(text, "efspotato") ||
                   ci_contains(text, "genericpotato") ||
                   ci_contains(text, "badpotato") ||
                   ci_contains(text, "hotpotato") ||
                   ci_contains(text, "sharpprintspoofer") ||
                   ci_contains(text, "juicypotatong") ||
                   ci_contains(text, "kube-hunter") ||
                   ci_contains(text, "peirates") ||
                   ci_contains(text, "kubesploit") ||
                   ci_contains(text, "kdigger") ||
                   ci_contains(text, "deepce") ||
                   ci_contains(text, "amicontained") ||
                   (ci_contains(text, "chisel") &&
                    (ci_contains(text, " client") ||
                     ci_contains(text, " server") || ci_contains(text, " -"))) ||
                   ci_contains(text, "ligolo") ||
                   (ci_contains(text, "gost") &&
                    ci_contains(text, " -")) ||
                   ci_contains(text, "frpc") || ci_contains(text, "frps") ||
                   (ci_contains(text, "rathole") &&
                    (ci_contains(text, " -") || ci_contains(text, ".toml"))) ||
                   ci_contains(text, "websocat") ||
                   (ci_contains(text, "iodine") &&
                    ci_contains(text, " -f")) ||
                   ci_contains(text, "dnscat") ||
                   ci_contains(text, "dns2tcp") ||
                   ci_contains(text, "icmpsh") ||
                   ci_contains(text, "ptunnel") ||
                   ci_contains(text, "pingtunnel") ||
                   ci_contains(text, "udp2raw") ||
                   ci_contains(text, "kcptun") ||
                   ci_contains(text, "v2ray") ||
                   (ci_contains(text, "xray") &&
                    (ci_contains(text, " run") ||
                     ci_contains(text, " -c"))) ||
                   (ci_contains(text, "trojan") &&
                    (ci_contains(text, " -c") ||
                     ci_contains(text, " -l"))) ||
                   ci_contains(text, "ss-server") ||
                   ci_contains(text, "ss-local") ||
                   ci_contains(text, "ssr-local") ||
                   ci_contains(text, "ss-manager") ||
                   (ci_contains(text, "hysteria") &&
                    (ci_contains(text, " server") ||
                     ci_contains(text, " client") ||
                     ci_contains(text, " -"))) ||
                   (ci_contains(text, "clash") &&
                    ci_contains(text, " -")) ||
                   ci_contains(text, "stunnel") ||
                   ci_contains(text, "sslh") ||
                   ci_contains(text, "proxytunnel") ||
                   ci_contains(text, "httptunnel") ||
                   ci_contains(text, "torsocks") ||
                   ci_contains(text, "torify") ||
                   ci_contains(text, "eggdrop") ||
                   ci_contains(text, "psybnc") ||
                   (ci_contains(text, "znc") &&
                    ci_contains(text, " -")) ||
                   ci_contains(text, "ezbounce") ||
                   ci_contains(text, "pssh") || ci_contains(text, "pdsh") ||
                   ci_contains(text, "clush") || ci_contains(text, "mussh") ||
                   ci_contains(text, "parallel-ssh") ||
                   ci_contains(text, "sshpass") ||
                   (ci_contains(text, "expect") &&
                    ci_contains(text, " -c")) ||
                   (ci_contains(text, "ansible") &&
                    (ci_contains(text, "-m command") ||
                     ci_contains(text, "-m shell") ||
                     ci_contains(text, "-m raw") ||
                     ci_contains(text, "-m script"))) ||
                   (ci_contains(text, "salt") &&
                    (ci_contains(text, "cmd.run") ||
                     ci_contains(text, "cmd.shell") ||
                     ci_contains(text, "state "))) ||
                   (ci_contains(text, "salt-call") &&
                    (ci_contains(text, "cmd.run") ||
                     ci_contains(text, "state"))) ||
                   ci_contains(text, "salt-ssh") ||
                   (ci_contains(text, "salt-key") &&
                    (ci_contains(text, " -a") ||
                     ci_contains(text, " -d"))) ||
                   (ci_contains(text, "chef") &&
                    (ci_contains(text, " exec") ||
                     ci_contains(text, " apply") ||
                     ci_contains(text, " -z"))) ||
                   (ci_contains(text, "puppet") &&
                    (ci_contains(text, " apply") ||
                     ci_contains(text, " agent"))) ||
                   (ci_contains(text, "bolt") &&
                    (ci_contains(text, " command") ||
                     ci_contains(text, " task") ||
                     ci_contains(text, " plan")))) {
            what = "offensive-tool/recon/c2/webshell/cred-dump name";
        /* c242: infra/cloud-writes + container/virt + ipmi/tpm +
         * cred-store + db-edit + mac ops + capture/clipboard +
         * forensics ── */
        } else if ((ci_contains(text, "kubectl") &&
                    (ci_contains(text, " exec") ||
                     ci_contains(text, " cp ") ||
                     ci_contains(text, " port-forward") ||
                     ci_contains(text, " debug") ||
                     ci_contains(text, " drain") ||
                     ci_contains(text, " cordon") ||
                     ci_contains(text, " attach") ||
                     ci_contains(text, " delete") ||
                     ci_contains(text, " taint") ||
                     ci_contains(text, " label") ||
                     ci_contains(text, " annotate"))) ||
                   (ci_contains(text, "kubeadm") &&
                    (ci_contains(text, " reset") ||
                     ci_contains(text, " token"))) ||
                   (ci_contains(text, "helm") &&
                    (ci_contains(text, " uninstall") ||
                     ci_contains(text, " delete") ||
                     ci_contains(text, " rollback"))) ||
                   (ci_contains(text, "oc ") &&
                    (ci_contains(text, " rsh") ||
                     ci_contains(text, " exec") ||
                     ci_contains(text, " debug") ||
                     ci_contains(text, " port-forward"))) ||
                   (ci_contains(text, "runc") &&
                    (ci_contains(text, " run") ||
                     ci_contains(text, " exec") ||
                     ci_contains(text, " create"))) ||
                   (ci_contains(text, "runsc ") &&
                    (ci_contains(text, " run") ||
                     ci_contains(text, " exec") ||
                     ci_contains(text, " create"))) ||
                   (ci_contains(text, "crictl") &&
                    (ci_contains(text, "exec") || ci_contains(text, "runp") ||
                     ci_contains(text, "stop") || ci_contains(text, "rmp") ||
                     ci_contains(text, " rm"))) ||
                   (ci_contains(text, "buildah") &&
                    (ci_contains(text, " run") ||
                     ci_contains(text, " from") ||
                     ci_contains(text, " mount") ||
                     ci_contains(text, " umount"))) ||
                   (ci_contains(text, "podman") &&
                    (ci_contains(text, "exec") ||
                     ci_contains(text, "--privileged") ||
                     ci_contains(text, "--pid=host") ||
                     ci_contains(text, "--net=host") ||
                     ci_contains(text, "--ipc=host") ||
                     ci_contains(text, " cp") ||
                     ci_contains(text, " volume"))) ||
                   (ci_contains(text, "nerdctl") &&
                    (ci_contains(text, " exec") ||
                     ci_contains(text, " run"))) ||
                   (ci_contains(text, "lxc") &&
                    (ci_contains(text, " exec") ||
                     ci_contains(text, " launch") ||
                     ci_contains(text, " config") ||
                     ci_contains(text, " copy") ||
                     ci_contains(text, " publish"))) ||
                   (ci_contains(text, "incus") &&
                    (ci_contains(text, " exec") ||
                     ci_contains(text, " launch") ||
                     ci_contains(text, " config"))) ||
                   (ci_contains(text, "virsh") &&
                    (ci_contains(text, " start") ||
                     ci_contains(text, " destroy") ||
                     ci_contains(text, " undefine") ||
                     ci_contains(text, " snapshot") ||
                     ci_contains(text, " dumpxml") ||
                     ci_contains(text, " edit") ||
                     ci_contains(text, " define") ||
                     ci_contains(text, " console") ||
                     ci_contains(text, " net-"))) ||
                   (ci_contains(text, "vboxmanage") &&
                    (ci_contains(text, "controlvm") ||
                     ci_contains(text, "modifyvm") ||
                     ci_contains(text, "unregistervm") ||
                     ci_contains(text, "startvm") ||
                     ci_contains(text, "snapshot") ||
                     ci_contains(text, "dhcpserver") ||
                     ci_contains(text, "sharedfolder"))) ||
                   ci_contains(text, "guestfish") ||
                   ci_contains(text, "guestmount") ||
                   ci_contains(text, "virt-edit") ||
                   ci_contains(text, "virt-customize") ||
                   ci_contains(text, "virt-rescue") ||
                   ci_contains(text, "virt-cat") ||
                   ci_contains(text, "virt-tar") ||
                   ci_contains(text, "virt-df") ||
                   ci_contains(text, "virt-inspector") ||
                   ci_contains(text, "virt-log") ||
                   ci_contains(text, "qemu-nbd") ||
                   ci_contains(text, "nbdkit") ||
                   ci_contains(text, "targetcli") ||
                   ci_contains(text, "tgtadm") ||
                   (ci_contains(text, "iscsiadm") &&
                    (ci_contains(text, " -l") ||
                     ci_contains(text, "--login") ||
                     ci_contains(text, "--logout") ||
                     ci_contains(text, " -m node"))) ||
                   (ci_contains(text, "drbdadm") &&
                    (ci_contains(text, "primary") ||
                     ci_contains(text, "disconnect") ||
                     ci_contains(text, "down") ||
                     ci_contains(text, "secondary") ||
                     ci_contains(text, "invalidate"))) ||
                   (ci_contains(text, "losetup") &&
                    (ci_contains(text, " -f") ||
                     ci_contains(text, " /dev/loop") ||
                     ci_contains(text, " -p") ||
                     ci_contains(text, " -o"))) ||
                   (ci_contains(text, "mknod") &&
                    ci_contains(text, "/dev/")) ||
                   ci_contains(text, "debugfs") ||
                   ci_contains(text, "xfsdump") ||
                   ci_contains(text, "xfsrestore") ||
                   ci_contains(text, "extundelete") ||
                   ci_contains(text, "ext4magic") ||
                   ci_contains(text, "ntfsundelete") ||
                   ci_contains(text, "testdisk") ||
                   ci_contains(text, "photorec") ||
                   ci_contains(text, "bulk_extractor") ||
                   (ci_contains(text, "volatility") &&
                    ci_contains(text, " -")) ||
                   ci_contains(text, "volatility3") ||
                   ci_contains(text, "rekall") ||
                   ci_contains(text, "avml") ||
                   ci_contains(text, "linpmem") ||
                   ci_contains(text, "winpmem") ||
                   ci_contains(text, "osxpmem") ||
                   (ci_contains(text, "srm") &&
                    ci_contains(text, " -")) ||
                   (ci_contains(text, "wipe ") &&
                    ci_contains(text, " -")) ||
                   (ci_contains(text, "bleachbit") &&
                    ci_contains(text, " -")) ||
                   ci_contains(text, "bcwipe") ||
                   (ci_contains(text, "exiftool") &&
                    ci_contains(text, "-all=")) ||
                   ci_contains(text, "steghide") ||
                   ci_contains(text, "binwalk") ||
                   ci_contains(text, "httrack") ||
                   ci_contains(text, "fswebcam") ||
                   ci_contains(text, "uvccapture") ||
                   (ci_contains(text, "streamer") &&
                    ci_contains(text, " -c")) ||
                   (ci_contains(text, "v4l2-ctl") &&
                    ci_contains(text, "--stream")) ||
                   (ci_contains(text, "gst-launch") &&
                    (ci_contains(text, "ximagesrc") ||
                     ci_contains(text, "pulsesrc") ||
                     ci_contains(text, "v4l2src") ||
                     ci_contains(text, "avfvideosrc") ||
                     ci_contains(text, "dshowvideosrc") ||
                     ci_contains(text, "alsasrc") ||
                     ci_contains(text, "osxvideosrc") ||
                     ci_contains(text, "autovideosrc") ||
                     ci_contains(text, "audiotestsrc"))) ||
                   ci_contains(text, "raspistill") ||
                   ci_contains(text, "raspivid") ||
                   ci_contains(text, "libcamera-still") ||
                   ci_contains(text, "libcamera-vid") ||
                   ci_contains(text, "imagesnap") ||
                   ci_contains(text, "videosnap") ||
                   ci_contains(text, "recordmydesktop") ||
                   (ci_contains(text, "xclip") &&
                    (ci_contains(text, " -o") || ci_contains(text, "-sel"))) ||
                   (ci_contains(text, "xsel") &&
                    ci_contains(text, " -")) ||
                   ci_contains(text, "wl-paste") ||
                   ci_contains(text, "wl-copy") ||
                   ci_contains(text, "pbcopy") ||
                   ci_contains(text, "conspy") ||
                   ci_contains(text, "sudoreplay") ||
                   ci_contains(text, "reptyr") ||
                   (ci_contains(text, "perf") &&
                    (ci_contains(text, " trace") ||
                     ci_contains(text, " record"))) ||
                   ci_contains(text, "lttng") ||
                   (ci_contains(text, "trace-cmd") &&
                    (ci_contains(text, " record") ||
                     ci_contains(text, " start"))) ||
                   (ci_contains(text, "dtrace") &&
                    (ci_contains(text, " -n") ||
                     ci_contains(text, " -s") ||
                     ci_contains(text, " -q") ||
                     ci_contains(text, " -c"))) ||
                   ci_contains(text, "dtruss") ||
                   ci_contains(text, "fs_usage") ||
                   ci_contains(text, "spindump") ||
                   ci_contains(text, "sysdiagnose") ||
                   ci_contains(text, "opensnoop") ||
                   ci_contains(text, "execsnoop") ||
                   ci_contains(text, "iosnoop") ||
                   ci_contains(text, "rwsnoop") ||
                   ci_contains(text, "tcpsnoop") ||
                   ci_contains(text, "killsnoop") ||
                   ci_contains(text, "bitesize") ||
                   (ci_contains(text, "log") &&
                    (ci_contains(text, " erase") ||
                     ci_contains(text, " collect"))) ||
                   (ci_contains(text, "plutil") &&
                    (ci_contains(text, " -insert") ||
                     ci_contains(text, " -replace") ||
                     ci_contains(text, " -remove") ||
                     ci_contains(text, " -extract"))) ||
                   (ci_contains(text, "mdutil") &&
                    (ci_contains(text, " -e") ||
                     ci_contains(text, " -i"))) ||
                   (ci_contains(text, "tmutil") &&
                    (ci_contains(text, "delete") ||
                     ci_contains(text, "disable") ||
                     ci_contains(text, "setdestination") ||
                     ci_contains(text, "removedestination") ||
                     ci_contains(text, "thinlocalsnapshots") ||
                     ci_contains(text, "deletelocalsnapshots") ||
                     ci_contains(text, "stopbackup") ||
                     ci_contains(text, "exclude"))) ||
                   (ci_contains(text, "softwareupdate") &&
                    (ci_contains(text, "--ignore") ||
                     ci_contains(text, "--schedule"))) ||
                   (ci_contains(text, "installer") &&
                    (ci_contains(text, " -pkg") ||
                     ci_contains(text, " -package"))) ||
                   (ci_contains(text, "jamf") &&
                    (ci_contains(text, " recon") ||
                     ci_contains(text, " policy") ||
                     ci_contains(text, " enroll") ||
                     ci_contains(text, "removeframework") ||
                     ci_contains(text, "resetpassword") ||
                     ci_contains(text, " manage") ||
                     ci_contains(text, " flush"))) ||
                   (ci_contains(text, "dseditgroup") &&
                    (ci_contains(text, " -o edit") ||
                     ci_contains(text, " -o create") ||
                     ci_contains(text, " -o delete") ||
                     ci_contains(text, " -a "))) ||
                   (ci_contains(text, "asr") &&
                    (ci_contains(text, " restore") ||
                     ci_contains(text, " erase"))) ||
                   (ci_contains(text, "bless") &&
                    (ci_contains(text, "--setboot") ||
                     ci_contains(text, " -folder") ||
                     ci_contains(text, " -mount") ||
                     ci_contains(text, " -device") ||
                     ci_contains(text, "--nextonly"))) ||
                   (ci_contains(text, "pmset") &&
                    (ci_contains(text, "disablesleep") ||
                     ci_contains(text, "autorestart") ||
                     ci_contains(text, "destroyfvkey"))) ||
                   (ci_contains(text, "lsregister") &&
                    (ci_contains(text, " -f") || ci_contains(text, " -r") ||
                     ci_contains(text, " -kill") ||
                     ci_contains(text, " -seed"))) ||
                   (ci_contains(text, "install_name_tool") &&
                    (ci_contains(text, " -id") ||
                     ci_contains(text, " -change") ||
                     ci_contains(text, " -rpath") ||
                     ci_contains(text, " -add_rpath") ||
                     ci_contains(text, " -delete_rpath"))) ||
                   ci_contains(text, "sandbox-exec") ||
                   (ci_contains(text, "ipmitool") &&
                    (ci_contains(text, " shell") ||
                     ci_contains(text, " sol") ||
                     ci_contains(text, " chassis") ||
                     ci_contains(text, " user") ||
                     ci_contains(text, " lan") ||
                     ci_contains(text, " sel") ||
                     ci_contains(text, " mc") ||
                     ci_contains(text, " bmc") ||
                     ci_contains(text, " raw") ||
                     ci_contains(text, " set"))) ||
                   ci_contains(text, "ipmiutil") ||
                   ci_contains(text, "ipmicfg") ||
                   ci_contains(text, "ipmi-config") ||
                   (ci_contains(text, "racadm") &&
                    (ci_contains(text, "racreset") ||
                     ci_contains(text, "serveraction") ||
                     ci_contains(text, " set") ||
                     ci_contains(text, " user") ||
                     ci_contains(text, "fwupdate") ||
                     ci_contains(text, " update") ||
                     ci_contains(text, "jobqueue"))) ||
                   ci_contains(text, "hponcfg") ||
                   ci_contains(text, "ilorest") ||
                   ci_contains(text, "tpm2_clear") ||
                   ci_contains(text, "tpm2_changeauth") ||
                   ci_contains(text, "tpm2_evictcontrol") ||
                   ci_contains(text, "tpm2_takeownership") ||
                   ci_contains(text, "tpm2_dictionarylockout") ||
                   ci_contains(text, "keepassxc-cli") ||
                   ci_contains(text, "kpcli") ||
                   ci_contains(text, "secret-tool") ||
                   ci_contains(text, "kwallet-query") ||
                   ci_contains(text, "lpass") ||
                   ci_contains(text, "gopass") ||
                   (ci_contains(text, "bw") &&
                    (ci_contains(text, " export") ||
                     ci_contains(text, " unlock") ||
                     ci_contains(text, " list"))) ||
                   (ci_contains(text, "keyring") &&
                    (ci_contains(text, " get") ||
                     ci_contains(text, " set"))) ||
                   (ci_contains(text, "nmcli") &&
                    ci_contains(text, " -s")) ||
                   ci_contains(text, "ssh-import-id") ||
                   (ci_contains(text, "redis-cli") &&
                    (ci_contains(text, " eval") ||
                     ci_contains(text, "flushall") ||
                     ci_contains(text, " config") ||
                     ci_contains(text, " debug") ||
                     ci_contains(text, " module") ||
                     ci_contains(text, "shutdown") ||
                     ci_contains(text, "slaveof") ||
                     ci_contains(text, "replicaof"))) ||
                   (ci_contains(text, "mongo") &&
                    ci_contains(text, "--eval")) ||
                   (ci_contains(text, "mongosh") &&
                    ci_contains(text, "--eval")) ||
                   (ci_contains(text, "ldapsearch") &&
                    (ci_contains(text, " -x") ||
                     ci_contains(text, " -h"))) ||
                   ci_contains(text, "ldapadd") ||
                   ci_contains(text, "ldapmodify") ||
                   ci_contains(text, "ldapdelete") ||
                   ci_contains(text, "ldapmodrdn") ||
                   ci_contains(text, "ldappasswd") ||
                   (ci_contains(text, "smbclient") &&
                    (ci_contains(text, " -c") ||
                     ci_contains(text, " \\\\"))) ||
                   (ci_contains(text, "rpcclient") &&
                    (ci_contains(text, " -c") ||
                     ci_contains(text, " -u"))) ||
                   (ci_contains(text, "showmount") &&
                    ci_contains(text, " -")) ||
                   (ci_contains(text, "rpcinfo") &&
                    ci_contains(text, " -p")) ||
                   (ci_contains(text, "aws") &&
                    (ci_contains(text, " delete") ||
                     ci_contains(text, " terminate") ||
                     ci_contains(text, " disable") ||
                     ci_contains(text, " stop-logging") ||
                     ci_contains(text, " purge") ||
                     ci_contains(text, "secretsmanager") ||
                     ci_contains(text, " ssm") ||
                     ci_contains(text, "sts assume") ||
                     ci_contains(text, "iam attach") ||
                     ci_contains(text, "iam create-login") ||
                     ci_contains(text, "iam put-user") ||
                     ci_contains(text, "iam add-user") ||
                     ci_contains(text, "iam update") ||
                     ci_contains(text, "s3 presign") ||
                     ci_contains(text, " kms"))) ||
                   (ci_contains(text, "gcloud") &&
                    (ci_contains(text, "compute ssh") ||
                     ci_contains(text, "compute scp") ||
                     ci_contains(text, "secrets") ||
                     ci_contains(text, "service-accounts keys") ||
                     ci_contains(text, "logging sinks") ||
                     ci_contains(text, "instances delete") ||
                     ci_contains(text, "clusters delete") ||
                     ci_contains(text, "deployments delete") ||
                     ci_contains(text, " kms"))) ||
                   (ci_contains(text, "az ") &&
                    (ci_contains(text, "keyvault") ||
                     ci_contains(text, "run-command") ||
                     ci_contains(text, "monitor"))) ||
                   (ci_contains(text, "ceph") &&
                    (ci_contains(text, " rm") ||
                     ci_contains(text, " destroy") ||
                     ci_contains(text, " purge") ||
                     ci_contains(text, " osd out") ||
                     ci_contains(text, " mds"))) ||
                   (ci_contains(text, "hdfs") &&
                    ci_contains(text, "dfs") &&
                    (ci_contains(text, "-rm") ||
                     ci_contains(text, "-expunge") ||
                     ci_contains(text, "-chmod") ||
                     ci_contains(text, "-chown") ||
                     ci_contains(text, "-setfacl"))) ||
                   (ci_contains(text, "rclone") &&
                    (ci_contains(text, " copy") ||
                     ci_contains(text, " move") ||
                     ci_contains(text, " sync") ||
                     ci_contains(text, " serve") ||
                     ci_contains(text, " lsd"))) ||
                   (ci_contains(text, "sshfs") &&
                    ci_contains(text, ":")) ||
                   ci_contains(text, "curlftpfs") ||
                   ci_contains(text, "davfs") ||
                   ci_contains(text, "nbd-client") ||
                   (ci_contains(text, "nmap") &&
                    ci_contains(text, " -"))) {
            what = "infra/cloud/container/cred-store/mac/forensic primitive";
        /* c243: mobile device control + RE/OSINT names + SCADA/
         * telephony/queue + DB destructive + supply publish + CI/
         * deploy + supervisor/journald + hardware/radio/input snoop +
         * fake infra + phish/C2 extras ── */
        } else if ((ci_contains(text, "adb") &&
                    (ci_contains(text, " shell") ||
                     ci_contains(text, " install") ||
                     ci_contains(text, " push") ||
                     ci_contains(text, " root") ||
                     ci_contains(text, " reboot") ||
                     ci_contains(text, " sideload") ||
                     ci_contains(text, " remount") ||
                     ci_contains(text, " disable-verity") ||
                     ci_contains(text, " unroot"))) ||
                   (ci_contains(text, "fastboot") &&
                    (ci_contains(text, " flash") ||
                     ci_contains(text, " oem") ||
                     ci_contains(text, " erase") ||
                     ci_contains(text, " reboot") ||
                     ci_contains(text, " unlock") ||
                     ci_contains(text, " format") ||
                     ci_contains(text, " set_active"))) ||
                   (ci_contains(text, "heimdall") &&
                    ci_contains(text, " flash")) ||
                   ci_contains(text, "mtkclient") ||
                   (ci_contains(text, "edl") &&
                    (ci_contains(text, "flash") ||
                     ci_contains(text, "qfil"))) ||
                   ci_contains(text, "scrcpy") ||
                   ci_contains(text, "sndcpy") ||
                   ci_contains(text, "ideviceinstaller") ||
                   ci_contains(text, "idevicebackup") ||
                   ci_contains(text, "idevicediagnostics") ||
                   ci_contains(text, "ideviceinfo") ||
                   ci_contains(text, "idevicerestore") ||
                   ci_contains(text, "idevicepair") ||
                   ci_contains(text, "idevicerestore") ||
                   ci_contains(text, "ios-deploy") ||
                   ci_contains(text, "ifuse") ||
                   ci_contains(text, "iproxy") ||
                   ci_contains(text, "idevicedebug") ||
                   ci_contains(text, "checkra1n") ||
                   ci_contains(text, "palera1n") ||
                   ci_contains(text, "magisk") ||
                   (ci_contains(text, "frida") &&
                    ci_contains(text, " -")) ||
                   ci_contains(text, "frida-trace") ||
                   ci_contains(text, "frida-ps") ||
                   ci_contains(text, "objection") ||
                   ci_contains(text, "apktool") ||
                   ci_contains(text, "jadx") ||
                   (ci_contains(text, "apksigner") &&
                    (ci_contains(text, "sign") ||
                     ci_contains(text, "rotate"))) ||
                   ci_contains(text, "d2j-dex2jar") ||
                   ci_contains(text, "baksmali") ||
                   ci_contains(text, "quark-engine") ||
                   ci_contains(text, "drozer") ||
                   ci_contains(text, "mobsf") ||
                   ci_contains(text, "radare2") ||
                   ci_contains(text, "rabin2") ||
                   ci_contains(text, "rasm2") ||
                   ci_contains(text, "radiff2") ||
                   ci_contains(text, "rizin") ||
                   ci_contains(text, "idat64") ||
                   ci_contains(text, "idat32") ||
                   ci_contains(text, "ghidra") ||
                   ci_contains(text, "analyzeheadless") ||
                   ci_contains(text, "retdec") ||
                   (ci_contains(text, "cutter") &&
                    ci_contains(text, " -")) ||
                   (ci_contains(text, "binaryninja") ||
                    ci_contains(text, "bndb")) ||
                   (ci_contains(text, "hopper") &&
                    ci_contains(text, " -")) ||
                   (ci_contains(text, "edb") &&
                    ci_contains(text, " -")) ||
                   ci_contains(text, "x64dbg") ||
                   ci_contains(text, "x32dbg") ||
                   (ci_contains(text, "windbg") &&
                    ci_contains(text, " -")) ||
                   ci_contains(text, "immunitydebugger") ||
                   ci_contains(text, "pwndbg") ||
                   ci_contains(text, "gef") ||
                   ci_contains(text, "peda") ||
                   (ci_contains(text, "capa") &&
                    ci_contains(text, " -")) ||
                   (ci_contains(text, "floss") &&
                    ci_contains(text, " -")) ||
                   ci_contains(text, "binlex") ||
                   (ci_contains(text, "yara") &&
                    (ci_contains(text, ".yar") ||
                     ci_contains(text, " -r") ||
                     ci_contains(text, " -f") ||
                     ci_contains(text, " -p") ||
                     ci_contains(text, " -s") ||
                     ci_contains(text, " -w") ||
                     ci_contains(text, " -n") ||
                     ci_contains(text, " -m"))) ||
                   ci_contains(text, "theharvester") ||
                   ci_contains(text, "recon-ng") ||
                   ci_contains(text, "spiderfoot") ||
                   (ci_contains(text, "sherlock") &&
                    ci_contains(text, " -")) ||
                   ci_contains(text, "holehe") ||
                   ci_contains(text, "ghunt") ||
                   ci_contains(text, "phoneinfoga") ||
                   ci_contains(text, "metagoofil") ||
                   (ci_contains(text, "shodan") &&
                    (ci_contains(text, " search") ||
                     ci_contains(text, " host") ||
                     ci_contains(text, " count") ||
                     ci_contains(text, " download") ||
                     ci_contains(text, " scan") ||
                     ci_contains(text, " parse") ||
                     ci_contains(text, " alert") ||
                     ci_contains(text, " domain") ||
                     ci_contains(text, " honeyscore") ||
                     ci_contains(text, " init") ||
                     ci_contains(text, " org"))) ||
                   (ci_contains(text, "censys") &&
                    ci_contains(text, " -")) ||
                   ci_contains(text, "dnstwist") ||
                   ci_contains(text, "trufflehog") ||
                   ci_contains(text, "gitleaks") ||
                   ci_contains(text, "shhgit") ||
                   ci_contains(text, "gitrob") ||
                   ci_contains(text, "detect-secrets") ||
                   ci_contains(text, "mbpoll") ||
                   ci_contains(text, "modpoll") ||
                   ci_contains(text, "snap7") ||
                   ci_contains(text, "pymodbus") ||
                   (ci_contains(text, "asterisk") &&
                    (ci_contains(text, " -r") ||
                     ci_contains(text, " -x"))) ||
                   (ci_contains(text, "fs_cli") &&
                    ci_contains(text, " -")) ||
                   ci_contains(text, "kamcmd") ||
                   ci_contains(text, "kamctl") ||
                   ci_contains(text, "opensips-cli") ||
                   (ci_contains(text, "mmcli") &&
                    (ci_contains(text, " -m") ||
                     ci_contains(text, " --"))) ||
                   (ci_contains(text, "qmicli") &&
                    ci_contains(text, " -")) ||
                   (ci_contains(text, "mbimcli") &&
                    (ci_contains(text, " -d") ||
                     ci_contains(text, " -p") ||
                     ci_contains(text, "--query") ||
                     ci_contains(text, "--set") ||
                     ci_contains(text, "--connect") ||
                     ci_contains(text, "--disconnect"))) ||
                   ci_contains(text, "mosquitto_pub") ||
                   ci_contains(text, "mosquitto_sub") ||
                   (ci_contains(text, "emqx") &&
                    (ci_contains(text, " ctl") ||
                     ci_contains(text, " eval") ||
                     ci_contains(text, " stop") ||
                     ci_contains(text, " kill"))) ||
                   ci_contains(text, "rabbitmqctl") ||
                   ci_contains(text, "rabbitmqadmin") ||
                   ci_contains(text, "kafka-topics") ||
                   ci_contains(text, "kafka-console-") ||
                   ci_contains(text, "kafka-acls") ||
                   ci_contains(text, "kafka-configs") ||
                   ci_contains(text, "kafka-producer") ||
                   ci_contains(text, "kafka-consumer-") ||
                   ci_contains(text, "kafka-delete-records") ||
                   ci_contains(text, "pulsar-admin") ||
                   ci_contains(text, "pulsar-client") ||
                   (ci_contains(text, "nats-") &&
                    ci_contains(text, " -")) ||
                   ci_contains(text, "zkcli") ||
                   ci_contains(text, "flush_all") ||
                   (ci_contains(text, "psql") &&
                    (ci_contains(text, " drop ") ||
                     ci_contains(text, " truncate") ||
                     ci_contains(text, " delete "))) ||
                   (ci_contains(text, "mysql") &&
                    (ci_contains(text, " drop ") ||
                     ci_contains(text, " truncate") ||
                     ci_contains(text, " delete "))) ||
                   (ci_contains(text, "sqlcmd") &&
                    (ci_contains(text, "drop table") ||
                     ci_contains(text, "drop database") ||
                     ci_contains(text, "truncate table") ||
                     ci_contains(text, "delete from"))) ||
                   (ci_contains(text, "cqlsh") &&
                    (ci_contains(text, "drop table") ||
                     ci_contains(text, "drop keyspace") ||
                     ci_contains(text, "truncate"))) ||
                   (ci_contains(text, "beeline") &&
                    (ci_contains(text, "drop table") ||
                     ci_contains(text, "drop database") ||
                     ci_contains(text, "truncate table") ||
                     ci_contains(text, "delete from"))) ||
                   (ci_contains(text, "clickhouse-client") &&
                    (ci_contains(text, "drop table") ||
                     ci_contains(text, "drop database") ||
                     ci_contains(text, "truncate table") ||
                     ci_contains(text, "delete from") ||
                     ci_contains(text, "detach"))) ||
                   (ci_contains(text, "influx") &&
                    (ci_contains(text, " delete") ||
                     ci_contains(text, " drop"))) ||
                   (ci_contains(text, "bq ") &&
                    (ci_contains(text, " rm") ||
                     ci_contains(text, " delete") ||
                     ci_contains(text, " rm -rf"))) ||
                   (ci_contains(text, "snowsql") &&
                    (ci_contains(text, "drop ") ||
                     ci_contains(text, "delete "))) ||
                   (ci_contains(text, "arangosh") &&
                    ci_contains(text, " -")) ||
                   (ci_contains(text, "cypher-shell") &&
                    ci_contains(text, " -")) ||
                   (ci_contains(text, "db2") &&
                    (ci_contains(text, " drop ") ||
                     ci_contains(text, " deactivate"))) ||
                   (ci_contains(text, "impala-shell") &&
                    (ci_contains(text, " drop ") ||
                     ci_contains(text, " -q") ||
                     ci_contains(text, " -f") ||
                     ci_contains(text, " --impalad"))) ||
                   (ci_contains(text, "presto") &&
                    (ci_contains(text, " drop ") ||
                     ci_contains(text, " --execute"))) ||
                   (ci_contains(text, "trino") &&
                    (ci_contains(text, " drop ") ||
                     ci_contains(text, " delete") ||
                     ci_contains(text, " --execute"))) ||
                   (ci_contains(text, "npm") &&
                    (ci_contains(text, " publish") ||
                     ci_contains(text, " unpublish") ||
                     ci_contains(text, " deprecate") ||
                     ci_contains(text, " unstar") ||
                     ci_contains(text, " access"))) ||
                   (ci_contains(text, "yarn") &&
                    (ci_contains(text, " publish") ||
                     ci_contains(text, " unpublish") ||
                     ci_contains(text, " application -kill") ||
                     ci_contains(text, " -kill"))) ||
                   (ci_contains(text, "twine") &&
                    ci_contains(text, " upload")) ||
                   (ci_contains(text, "cargo") &&
                    (ci_contains(text, " publish") ||
                     ci_contains(text, " yank"))) ||
                   (ci_contains(text, "gem") &&
                    ci_contains(text, " push")) ||
                   (ci_contains(text, "conan") &&
                    (ci_contains(text, " upload") ||
                     ci_contains(text, " remove"))) ||
                   (ci_contains(text, "nuget") &&
                    (ci_contains(text, " push") ||
                     ci_contains(text, " delete"))) ||
                   (ci_contains(text, "dotnet nuget") &&
                    (ci_contains(text, " push") ||
                     ci_contains(text, " delete"))) ||
                   (ci_contains(text, "oras") &&
                    ci_contains(text, " push")) ||
                   (ci_contains(text, "jfrog") &&
                    (ci_contains(text, " rt u") ||
                     ci_contains(text, " rt upload") ||
                     ci_contains(text, " rt del") ||
                     ci_contains(text, " rt delete"))) ||
                   (ci_contains(text, "mvn") &&
                    (ci_contains(text, " deploy") ||
                     ci_contains(text, " release"))) ||
                   (ci_contains(text, "gradle") &&
                    ci_contains(text, " publish")) ||
                   (ci_contains(text, "poetry") &&
                    ci_contains(text, " publish")) ||
                   (ci_contains(text, "pnpm") &&
                    ci_contains(text, " publish")) ||
                   (ci_contains(text, "gh ") &&
                    (ci_contains(text, "workflow run") ||
                     ci_contains(text, "secret ") ||
                     ci_contains(text, "variable ") ||
                     ci_contains(text, " api") ||
                     ci_contains(text, " release delete") ||
                     ci_contains(text, " release upload") ||
                     ci_contains(text, " repo delete") ||
                     ci_contains(text, " auth ") ||
                     ci_contains(text, " gpg-key") ||
                     ci_contains(text, " ssh-key") ||
                     ci_contains(text, " run watch") ||
                     ci_contains(text, " workflow disable") ||
                     ci_contains(text, " workflow enable"))) ||
                   (ci_contains(text, "glab") &&
                    (ci_contains(text, " ci ") ||
                     ci_contains(text, " variable") ||
                     ci_contains(text, " release") ||
                     ci_contains(text, " auth") ||
                     ci_contains(text, " repo delete"))) ||
                   (ci_contains(text, "fly ") &&
                    (ci_contains(text, "set-pipeline") ||
                     ci_contains(text, "destroy-pipeline") ||
                     ci_contains(text, " hijack") ||
                     ci_contains(text, " unpause") ||
                     ci_contains(text, "pause") ||
                     ci_contains(text, "trigger-job") ||
                     ci_contains(text, "validate-pipeline"))) ||
                   (ci_contains(text, "flyctl") &&
                    (ci_contains(text, " destroy") ||
                     ci_contains(text, " deploy") ||
                     ci_contains(text, " scale") ||
                     ci_contains(text, " secrets") ||
                     ci_contains(text, " ssh"))) ||
                   (ci_contains(text, "jenkins-cli") ||
                    ci_contains(text, "jenkins-cli.jar")) ||
                   (ci_contains(text, "gitlab-runner") &&
                    (ci_contains(text, " register") ||
                     ci_contains(text, " unregister") ||
                     ci_contains(text, " exec"))) ||
                   (ci_contains(text, "circleci") &&
                    (ci_contains(text, " run") ||
                     ci_contains(text, " build") ||
                     ci_contains(text, " orb") ||
                     ci_contains(text, " setup") ||
                     ci_contains(text, " execute") ||
                     ci_contains(text, " process") ||
                     ci_contains(text, " follow"))) ||
                   (ci_contains(text, "travis") &&
                    (ci_contains(text, " init") ||
                     ci_contains(text, " encrypt") ||
                     ci_contains(text, " ssh") ||
                     ci_contains(text, " token") ||
                     ci_contains(text, " env") ||
                     ci_contains(text, " enable") ||
                     ci_contains(text, " disable") ||
                     ci_contains(text, " sync") ||
                     ci_contains(text, " run"))) ||
                   (ci_contains(text, "drone") &&
                    (ci_contains(text, " build") ||
                     ci_contains(text, " exec") ||
                     ci_contains(text, " secret") ||
                     ci_contains(text, " sign") ||
                     ci_contains(text, " server") ||
                     ci_contains(text, " agent") ||
                     ci_contains(text, " promote") ||
                     ci_contains(text, " deploy") ||
                     ci_contains(text, " rollback") ||
                     ci_contains(text, " repo"))) ||
                   (ci_contains(text, "buildkite-agent") &&
                    (ci_contains(text, " -") ||
                     ci_contains(text, " start") ||
                     ci_contains(text, " agent"))) ||
                   (ci_contains(text, "sls") &&
                    (ci_contains(text, " deploy") ||
                     ci_contains(text, " remove") ||
                     ci_contains(text, " rollback") ||
                     ci_contains(text, " invoke"))) ||
                   (ci_contains(text, "serverless") &&
                    (ci_contains(text, " deploy") ||
                     ci_contains(text, " remove") ||
                     ci_contains(text, " invoke"))) ||
                   (ci_contains(text, "sam") &&
                    (ci_contains(text, " deploy") ||
                     ci_contains(text, " delete"))) ||
                   (ci_contains(text, "railway") &&
                    (ci_contains(text, " delete") ||
                     ci_contains(text, " up") ||
                     ci_contains(text, " down") ||
                     ci_contains(text, " run"))) ||
                   (ci_contains(text, "vercel") &&
                    (ci_contains(text, " rm") ||
                     ci_contains(text, " env") ||
                     ci_contains(text, " delete") ||
                     ci_contains(text, " redeploy"))) ||
                   (ci_contains(text, "netlify") &&
                    (ci_contains(text, " unlink") ||
                     ci_contains(text, " delete") ||
                     ci_contains(text, " deploy") ||
                     ci_contains(text, " env"))) ||
                   (ci_contains(text, "heroku") &&
                    (ci_contains(text, "apps:destroy") ||
                     ci_contains(text, "addons:destroy") ||
                     ci_contains(text, "config:set") ||
                     ci_contains(text, "config:unset") ||
                     ci_contains(text, "ps:scale") ||
                     ci_contains(text, "maintenance:") ||
                     ci_contains(text, "releases") ||
                     ci_contains(text, "drains") ||
                     ci_contains(text, "access:") ||
                     ci_contains(text, "certs") ||
                     ci_contains(text, "pg:kill") ||
                     ci_contains(text, "pg:reset") ||
                     ci_contains(text, "pg:backups"))) ||
                   (ci_contains(text, "vagrant") &&
                    (ci_contains(text, " destroy") ||
                     ci_contains(text, " package"))) ||
                   (ci_contains(text, "pm2") &&
                    (ci_contains(text, " delete") ||
                     ci_contains(text, " kill") ||
                     ci_contains(text, " stop") ||
                     ci_contains(text, " startup") ||
                     ci_contains(text, " save") ||
                     ci_contains(text, " resurrect") ||
                     ci_contains(text, " reload") ||
                     ci_contains(text, " restart") ||
                     ci_contains(text, " unstartup"))) ||
                   (ci_contains(text, "supervisorctl") &&
                    (ci_contains(text, " stop") ||
                     ci_contains(text, " shutdown") ||
                     ci_contains(text, " update") ||
                     ci_contains(text, " restart") ||
                     ci_contains(text, " signal") ||
                     ci_contains(text, " remove") ||
                     ci_contains(text, " add"))) ||
                   (ci_contains(text, "monit ") &&
                    (ci_contains(text, " unmonitor") ||
                     ci_contains(text, " stop") ||
                     ci_contains(text, " quit") ||
                     ci_contains(text, " reload") ||
                     ci_contains(text, " restart") ||
                     ci_contains(text, " monitor") ||
                     ci_contains(text, " start"))) ||
                   (ci_contains(text, "god") &&
                    (ci_contains(text, " stop") ||
                     ci_contains(text, " terminate") ||
                     ci_contains(text, " restart") ||
                     ci_contains(text, " unmonitor"))) ||
                   (ci_contains(text, "bluepill") &&
                    (ci_contains(text, " stop") ||
                     ci_contains(text, " quit") ||
                     ci_contains(text, " restart") ||
                     ci_contains(text, " load"))) ||
                   (ci_contains(text, "svcadm") &&
                    (ci_contains(text, " disable") ||
                     ci_contains(text, " delete") ||
                     ci_contains(text, " clear") ||
                     ci_contains(text, " mark") ||
                     ci_contains(text, " restart") ||
                     ci_contains(text, " refresh") ||
                     ci_contains(text, " enable"))) ||
                   (ci_contains(text, "journalctl") &&
                    (ci_contains(text, "--vacuum") ||
                     ci_contains(text, " --rotate") ||
                     ci_contains(text, " --flush") ||
                     ci_contains(text, " --sync") ||
                     ci_contains(text, " --relinquish") ||
                     ci_contains(text, " --header"))) ||
                   (ci_contains(text, "sysrq-trigger") &&
                    ci_contains(text, " >")) ||
                   (ci_contains(text, "flashrom") &&
                    (ci_contains(text, " -w") ||
                     ci_contains(text, " -e") ||
                     ci_contains(text, "--erase") ||
                     ci_contains(text, "-programmer") ||
                     ci_contains(text, " -p"))) ||
                   (ci_contains(text, "dfu-util") &&
                    (ci_contains(text, " -d") ||
                     ci_contains(text, " -a") ||
                     ci_contains(text, " -e") ||
                     ci_contains(text, " -w"))) ||
                   (ci_contains(text, "avrdude") &&
                    (ci_contains(text, " -u") ||
                     ci_contains(text, " -e") ||
                     ci_contains(text, " -c"))) ||
                   (ci_contains(text, "esptool") &&
                    (ci_contains(text, "write_flash") ||
                     ci_contains(text, "erase_flash") ||
                     ci_contains(text, "flash_id") ||
                     ci_contains(text, "read_flash") ||
                     ci_contains(text, "verify_flash") ||
                     ci_contains(text, "dump_mem") ||
                     ci_contains(text, "load_ram") ||
                     ci_contains(text, "write_mem") ||
                     ci_contains(text, "merge_bin") ||
                     ci_contains(text, "elf2image") ||
                     ci_contains(text, "run"))) ||
                   (ci_contains(text, "usbreset") &&
                    ci_contains(text, " /dev")) ||
                   (ci_contains(text, "usb_modeswitch") &&
                    ci_contains(text, " -")) ||
                   (ci_contains(text, "openocd") &&
                    (ci_contains(text, " -f") ||
                     ci_contains(text, " -c"))) ||
                   ci_contains(text, "gpioset") ||
                   ci_contains(text, "i2cset") ||
                   ci_contains(text, "spidev") ||
                   ci_contains(text, "nandwrite") ||
                   ci_contains(text, "nandtest") ||
                   ci_contains(text, "ubiformat") ||
                   ci_contains(text, "mtd_debug") ||
                   (ci_contains(text, "nanddump") &&
                    ci_contains(text, " -")) ||
                   ci_contains(text, "hackrf_transfer") ||
                   ci_contains(text, "hackrf_sweep") ||
                   ci_contains(text, "hackrf_specan") ||
                   ci_contains(text, "rtl_sdr") ||
                   ci_contains(text, "rtl_fm") ||
                   ci_contains(text, "airprobe") ||
                   ci_contains(text, "kalibrate") ||
                   ci_contains(text, "ubertooth") ||
                   ci_contains(text, "btmon") ||
                   ci_contains(text, "btproxy") ||
                   ci_contains(text, "bleah") ||
                   (ci_contains(text, "crackle") &&
                    ci_contains(text, " -")) ||
                   (ci_contains(text, "hcitool") &&
                    (ci_contains(text, " -") ||
                     ci_contains(text, "scan") ||
                     ci_contains(text, " le"))) ||
                   (ci_contains(text, "gatttool") &&
                    ci_contains(text, " -")) ||
                   (ci_contains(text, "bluetoothctl") &&
                    (ci_contains(text, " pair") ||
                     ci_contains(text, " connect") ||
                     ci_contains(text, "connectable") ||
                     ci_contains(text, "discoverable") ||
                     ci_contains(text, " agent") ||
                     ci_contains(text, " power"))) ||
                   ci_contains(text, "proxmark3") ||
                   ci_contains(text, "pm3") ||
                   ci_contains(text, "mfoc") ||
                   ci_contains(text, "mfcuk") ||
                   ci_contains(text, "nfc-list") ||
                   ci_contains(text, "killerbee") ||
                   ci_contains(text, "zbwd") ||
                   ci_contains(text, "zbgoodfind") ||
                   ci_contains(text, "zbreplay") ||
                   ci_contains(text, "zbstumbler") ||
                   ci_contains(text, "zbdump") ||
                   ci_contains(text, "zbsniff") ||
                   ci_contains(text, "zbassocflood") ||
                   ci_contains(text, "gps-sdr-sim") ||
                   ci_contains(text, "gpsfaker") ||
                   ci_contains(text, "fakegps") ||
                   ci_contains(text, "gnss-sdr") ||
                   ci_contains(text, "evtest") ||
                   (ci_contains(text, "libinput") &&
                    (ci_contains(text, " debug") ||
                     ci_contains(text, " record"))) ||
                   ci_contains(text, "showkey") ||
                   ci_contains(text, "dumpkeys") ||
                   (ci_contains(text, "wev") &&
                    !ci_contains(text, "wevtutil")) ||
                   ci_contains(text, "wshowkeys") ||
                   (ci_contains(text, "xinput") &&
                    (ci_contains(text, " test") ||
                     ci_contains(text, " set") ||
                     ci_contains(text, " map") ||
                     ci_contains(text, " float") ||
                     ci_contains(text, " reattach") ||
                     ci_contains(text, " disable") ||
                     ci_contains(text, " enable"))) ||
                   (ci_contains(text, "hyprctl") &&
                    (ci_contains(text, " dispatch") ||
                     ci_contains(text, " keyword") ||
                     ci_contains(text, " reload") ||
                     ci_contains(text, " exec"))) ||
                   (ci_contains(text, "swaymsg") &&
                    (ci_contains(text, " exec") ||
                     ci_contains(text, " -m"))) ||
                   (ci_contains(text, "i3-msg") &&
                    (ci_contains(text, " exec") ||
                     ci_contains(text, " -m"))) ||
                   ci_contains(text, "fakedns") ||
                   ci_contains(text, "fakenet") ||
                   ci_contains(text, "inetsim") ||
                   ci_contains(text, "apatedns") ||
                   ci_contains(text, "remnux") ||
                   ci_contains(text, "hiddeneye") ||
                   ci_contains(text, "hidden-eye") ||
                   (ci_contains(text, "seeker") &&
                    ci_contains(text, " -")) ||
                   ci_contains(text, "socialfish") ||
                   ci_contains(text, "social-phish") ||
                   ci_contains(text, "nexphisher") ||
                   ci_contains(text, "camphish") ||
                   ci_contains(text, "sayhello") ||
                   ci_contains(text, "stormbreaker") ||
                   ci_contains(text, "pyphisher") ||
                   ci_contains(text, "madphish") ||
                   ci_contains(text, "mrphish") ||
                   ci_contains(text, "evilurl") ||
                   ci_contains(text, "evil-winrm") ||
                   (ci_contains(text, "villain") &&
                    ci_contains(text, " -")) ||
                   (ci_contains(text, "mythic") &&
                    ci_contains(text, " -")) ||
                   (ci_contains(text, "covenant") &&
                    ci_contains(text, " -")) ||
                   (ci_contains(text, "havoc") &&
                    ci_contains(text, " -")) ||
                   ci_contains(text, "darkcomet") ||
                   ci_contains(text, "poisonivy") ||
                   ci_contains(text, "poison-ivy") ||
                   ci_contains(text, "gh0st") ||
                   ci_contains(text, "backdoor-factory") ||
                   ci_contains(text, "bdfproxy") ||
                   (ci_contains(text, "unicorn") &&
                    (ci_contains(text, ".py") ||
                     ci_contains(text, " -"))) ||
                   (ci_contains(text, "scarecrow") &&
                    ci_contains(text, " -")) ||
                   ci_contains(text, "nimcrypt") ||
                   ci_contains(text, "nimplant") ||
                   (ci_contains(text, "upx") &&
                    ci_contains(text, " -")) ||
                   (ci_contains(text, "printui") &&
                    (ci_contains(text, "/ga") ||
                     ci_contains(text, "/gd") ||
                     ci_contains(text, "/ge") ||
                     ci_contains(text, "/dd") ||
                     ci_contains(text, "printuientry"))) ||
                   (ci_contains(text, "verifier") &&
                    (ci_contains(text, " /standard") ||
                     ci_contains(text, " /all") ||
                     ci_contains(text, " /volatile") ||
                     ci_contains(text, " /boot") ||
                     ci_contains(text, " /faults"))) ||
                   (ci_contains(text, "lpadmin") &&
                    (ci_contains(text, " -x") ||
                     ci_contains(text, " -p") ||
                     ci_contains(text, " -v") ||
                     ci_contains(text, " -e"))) ||
                   (ci_contains(text, "cancel") &&
                    ci_contains(text, " -a")) ||
                   (ci_contains(text, "lpmove") &&
                    ci_contains(text, " ")) ||
                   ci_contains(text, "cupsdisable") ||
                   ci_contains(text, "cupsreject") ||
                   (ci_contains(text, "update-initramfs") &&
                    (ci_contains(text, " -u") ||
                     ci_contains(text, " -c") ||
                     ci_contains(text, " -d"))) ||
                   (ci_contains(text, "mkinitrd") &&
                    (ci_contains(text, " -o") ||
                     ci_contains(text, " -f"))) ||
                   ci_contains(text, "update-grub") ||
                   (ci_contains(text, "grub2-mkconfig") ||
                    ci_contains(text, "grub-mkconfig")) ||
                   (ci_contains(text, "grub-install") &&
                    (ci_contains(text, " /") ||
                     ci_contains(text, " --"))) ||
                   (ci_contains(text, "ssh-keygen") &&
                    (ci_contains(text, " -s ") ||
                     ci_contains(text, " -z ") ||
                     ci_contains(text, " -i "))) ||
                   (ci_contains(text, "mutt") &&
                    (ci_contains(text, " -a") ||
                     ci_contains(text, " -s") ||
                     ci_contains(text, " @"))) ||
                   (ci_contains(text, "mailx") &&
                    (ci_contains(text, " -a") ||
                     ci_contains(text, " @"))) ||
                   (ci_contains(text, "sendmail") &&
                    (ci_contains(text, " <") ||
                     ci_contains(text, " -t") ||
                     ci_contains(text, " -f"))) ||
                   (ci_contains(text, "s-nail") &&
                    ci_contains(text, " -")) ||
                   (ci_contains(text, "mpack") &&
                    ci_contains(text, " ")) ||
                   ((ci_contains(text, "curl") ||
                     ci_contains(text, "wget") ||
                     ci_contains(text, "httpie") ||
                     ci_contains(text, "xh ")) &&
                    (ci_contains(text, " -d") ||
                     ci_contains(text, " -f") ||
                     ci_contains(text, " -t ") ||
                     ci_contains(text, "--data") ||
                     ci_contains(text, "--form") ||
                     ci_contains(text, "--upload") ||
                     ci_contains(text, "-post")) &&
                    (ci_contains(text, "api.telegram.org") ||
                     ci_contains(text, "/api/webhooks") ||
                     ci_contains(text, "hooks.slack.com") ||
                     ci_contains(text, "outlook.office.com/webhook") ||
                     ci_contains(text, "webhook.site") ||
                     ci_contains(text, "pipedream") ||
                     ci_contains(text, "requestbin") ||
                     ci_contains(text, "hookbin") ||
                     ci_contains(text, "beeceptor") ||
                     ci_contains(text, "smee.io"))) ||
                   (ci_contains(text, "systemd-cryptenroll") &&
                    ci_contains(text, " --")) ||
                   (ci_contains(text, "homectl") &&
                    (ci_contains(text, " create") ||
                     ci_contains(text, " remove") ||
                     ci_contains(text, " passwd") ||
                     ci_contains(text, " update") ||
                     ci_contains(text, " rename") ||
                     ci_contains(text, " deactivate"))) ||
                   (ci_contains(text, "bootctl") &&
                    (ci_contains(text, " install") ||
                     ci_contains(text, " remove") ||
                     ci_contains(text, " update") ||
                     ci_contains(text, " set-") ||
                     ci_contains(text, " write"))) ||
                   (ci_contains(text, "udevadm") &&
                    (ci_contains(text, " trigger") ||
                     ci_contains(text, " test") ||
                     ci_contains(text, " control") ||
                     ci_contains(text, " --"))) ||
                   (ci_contains(text, "clevis") &&
                    ci_contains(text, " ")) ||
                   (ci_contains(text, "fscrypt") &&
                    (ci_contains(text, " encrypt") ||
                     ci_contains(text, " purge") ||
                     ci_contains(text, " destroy") ||
                     ci_contains(text, " lock") ||
                     ci_contains(text, " unlock"))) ||
                   (ci_contains(text, "tomb") &&
                    (ci_contains(text, " -") ||
                     ci_contains(text, " dig"))) ||
                   (ci_contains(text, "gocryptfs") &&
                    ci_contains(text, " ")) ||
                   (ci_contains(text, "encfs") &&
                    ci_contains(text, " -")) ||
                   (ci_contains(text, "cryfs") &&
                    ci_contains(text, " ")) ||
                   (ci_contains(text, "veracrypt") &&
                    (ci_contains(text, " -") ||
                     ci_contains(text, " /"))) ||
                   ci_contains(text, "ecryptfs") ||
                   (ci_contains(text, "htpasswd") &&
                    (ci_contains(text, " -c") ||
                     ci_contains(text, " -b") ||
                     ci_contains(text, " -b") ||
                     ci_contains(text, " -d") ||
                     ci_contains(text, " -v"))) ||
                   (ci_contains(text, "amtool") &&
                    (ci_contains(text, " silence") ||
                     ci_contains(text, " alert") ||
                     ci_contains(text, " expire"))) ||
                   ci_contains(text, "mimirtool") ||
                   (ci_contains(text, "grafana-cli") &&
                    (ci_contains(text, " admin") ||
                     ci_contains(text, " plugins") ||
                     ci_contains(text, " --"))) ||
                   (ci_contains(text, "onevm") &&
                    ci_contains(text, " ")) ||
                   (ci_contains(text, "onehost") &&
                    ci_contains(text, " ")) ||
                   (ci_contains(text, "pvesh") &&
                    (ci_contains(text, " delete") ||
                     ci_contains(text, " set") ||
                     ci_contains(text, " create"))) ||
                   (ci_contains(text, "qm ") &&
                    (ci_contains(text, " destroy") ||
                     ci_contains(text, " del") ||
                     ci_contains(text, " stop") ||
                     ci_contains(text, " shutdown") ||
                     ci_contains(text, " migrate") ||
                     ci_contains(text, " template") ||
                     ci_contains(text, " clone") ||
                     ci_contains(text, " set"))) ||
                   (ci_contains(text, "pct ") &&
                    (ci_contains(text, " destroy") ||
                     ci_contains(text, " del") ||
                     ci_contains(text, " stop") ||
                     ci_contains(text, " shutdown") ||
                     ci_contains(text, " exec"))) ||
                   (ci_contains(text, "openstack") &&
                    (ci_contains(text, " delete") ||
                     ci_contains(text, " remove") ||
                     ci_contains(text, " stop") ||
                     ci_contains(text, " shutoff") ||
                     ci_contains(text, " hard"))) ||
                   (ci_contains(text, "nova ") &&
                    (ci_contains(text, " delete") ||
                     ci_contains(text, " stop") ||
                     ci_contains(text, " force"))) ||
                   (ci_contains(text, "doctl") &&
                    ci_contains(text, " delete")) ||
                   (ci_contains(text, "hcloud") &&
                    (ci_contains(text, " delete") ||
                     ci_contains(text, " poweroff") ||
                     ci_contains(text, " rebuild") ||
                     ci_contains(text, " shutdown"))) ||
                   (ci_contains(text, "scw") &&
                    (ci_contains(text, " delete") ||
                     ci_contains(text, " stop"))) ||
                   (ci_contains(text, "oci") &&
                    (ci_contains(text, " terminate") ||
                     ci_contains(text, " delete"))) ||
                   (ci_contains(text, "govc") &&
                    (ci_contains(text, "vm.destroy") ||
                     ci_contains(text, "vm.power") ||
                     ci_contains(text, "vm.delete") ||
                     ci_contains(text, "datastore") ||
                     ci_contains(text, "host."))) ||
                   (ci_contains(text, "vim-cmd") &&
                    (ci_contains(text, "power.") ||
                     ci_contains(text, "destroy") ||
                     ci_contains(text, "unreg"))) ||
                   (ci_contains(text, "esxcli") &&
                    (ci_contains(text, " kill") ||
                     ci_contains(text, " set") ||
                     ci_contains(text, " unload") ||
                     ci_contains(text, " network") ||
                     ci_contains(text, " firewall") ||
                     ci_contains(text, " storage") ||
                     ci_contains(text, " system"))) ||
                   (ci_contains(text, "virtctl") &&
                    (ci_contains(text, " stop") ||
                     ci_contains(text, " delete") ||
                     ci_contains(text, " pause") ||
                     ci_contains(text, " migrate") ||
                     ci_contains(text, " start") ||
                     ci_contains(text, " console"))) ||
                   (ci_contains(text, "rancher") &&
                    (ci_contains(text, " app") ||
                     ci_contains(text, " login") ||
                     ci_contains(text, " cluster") ||
                     ci_contains(text, " server") ||
                     ci_contains(text, " delete") ||
                     ci_contains(text, " context"))) ||
                   (ci_contains(text, "rke ") &&
                    (ci_contains(text, " remove") ||
                     ci_contains(text, " up") ||
                     ci_contains(text, " etcd"))) ||
                   (ci_contains(text, "k3d") &&
                    (ci_contains(text, " delete") ||
                     ci_contains(text, " create"))) ||
                   (ci_contains(text, "kind") &&
                    (ci_contains(text, " delete") ||
                     ci_contains(text, " create") ||
                     ci_contains(text, " load"))) ||
                   (ci_contains(text, "minikube") &&
                    (ci_contains(text, " delete") ||
                     ci_contains(text, " stop"))) ||
                   (ci_contains(text, "colima") &&
                    (ci_contains(text, " delete") ||
                     ci_contains(text, " stop") ||
                     ci_contains(text, " start"))) ||
                   (ci_contains(text, "docker swarm") &&
                    (ci_contains(text, " leave") ||
                     ci_contains(text, " join") ||
                     ci_contains(text, " update") ||
                     ci_contains(text, " init"))) ||
                   (ci_contains(text, "ctr ") &&
                    (ci_contains(text, " exec") ||
                     ci_contains(text, " rm") ||
                     ci_contains(text, " kill"))) ||
                   (ci_contains(text, "umoci") &&
                    ci_contains(text, " ")) ||
                   (ci_contains(text, "skopeo") &&
                    ci_contains(text, " ")) ||
                   (ci_contains(text, "cosign") &&
                    (ci_contains(text, " sign") ||
                     ci_contains(text, " attest") ||
                     ci_contains(text, " upload"))) ||
                   (ci_contains(text, "helmfile") &&
                    (ci_contains(text, " apply") ||
                     ci_contains(text, " sync") ||
                     ci_contains(text, " destroy") ||
                     ci_contains(text, " delete"))) ||
                   (ci_contains(text, "argocd") &&
                    (ci_contains(text, " app delete") ||
                     ci_contains(text, " app sync") ||
                     ci_contains(text, " cluster") ||
                     ci_contains(text, " repo") ||
                     ci_contains(text, " app set"))) ||
                   (ci_contains(text, "flux") &&
                    (ci_contains(text, " delete") ||
                     ci_contains(text, " suspend") ||
                     ci_contains(text, " uninstall") ||
                     ci_contains(text, " reconcile"))) ||
                   (ci_contains(text, "certbot") &&
                    (ci_contains(text, " delete") ||
                     ci_contains(text, " revoke") ||
                     ci_contains(text, " unregister") ||
                     ci_contains(text, " --cert-name"))) ||
                   (ci_contains(text, "kubeseal") &&
                    ci_contains(text, " ")) ||
                   (ci_contains(text, "sops") &&
                    (ci_contains(text, " -d") ||
                     ci_contains(text, "--decrypt") ||
                     ci_contains(text, " updatekeys") ||
                     ci_contains(text, " rotate"))) ||
                   (ci_contains(text, "spark-submit") &&
                    ci_contains(text, " ")) ||
                   (ci_contains(text, "flink") &&
                    (ci_contains(text, " run") ||
                     ci_contains(text, " cancel") ||
                     ci_contains(text, " stop") ||
                     ci_contains(text, " savepoint"))) ||
                   (ci_contains(text, "oozie") &&
                    (ci_contains(text, " job") ||
                     ci_contains(text, " -oozie") ||
                     ci_contains(text, " -dryrun") ||
                     ci_contains(text, " sla") ||
                     ci_contains(text, " bundle") ||
                     ci_contains(text, " validate") ||
                     ci_contains(text, " submit"))) ||
                   (ci_contains(text, "airflow") &&
                    (ci_contains(text, " dags") ||
                     ci_contains(text, " db") ||
                     ci_contains(text, " scheduler") ||
                     ci_contains(text, " webserver") ||
                     ci_contains(text, " celery") ||
                     ci_contains(text, " users") ||
                     ci_contains(text, " connections") ||
                     ci_contains(text, " variables") ||
                     ci_contains(text, " delete") ||
                     ci_contains(text, " reset"))) ||
                   ci_contains(text, "sqoop") ||
                   ci_contains(text, "distcp") ||
                   (ci_contains(text, "huggingface-cli") &&
                    (ci_contains(text, " upload") ||
                     ci_contains(text, " delete"))) ||
                   ci_contains(text, "driftnet") ||
                   ci_contains(text, "xplico") ||
                   ci_contains(text, "text2pcap") ||
                   ci_contains(text, "mergecap") ||
                   ci_contains(text, "editcap") ||
                   ci_contains(text, "trafgen") ||
                   ci_contains(text, "mausezahn") ||
                   ci_contains(text, "mz -") ||
                   ci_contains(text, "nemesis") ||
                   ci_contains(text, "parprouted") ||
                   ci_contains(text, "zarp") ||
                   (ci_contains(text, "lftp") &&
                    (ci_contains(text, " -c") ||
                     ci_contains(text, " mirror"))) ||
                   (ci_contains(text, "ncftpput") ||
                    ci_contains(text, "ncftpget")) ||
                   ci_contains(text, "autorunsc") ||
                   ci_contains(text, "handle64") ||
                   ci_contains(text, "logonsessions") ||

                   ci_contains(text, "chromium --remote-debugging") ||
                   ci_contains(text, "chrome --remote-debugging") ||
                   ci_contains(text, "firefox --remote-debugging") ||
                   ci_contains(text, "msedge --remote-debugging") ||
                   ci_contains(text, "brave --remote-debugging") ||
                   ci_contains(text, "--remote-debugging-port") ||
                   ci_contains(text, "--remote-debugging-pipe")) {
            what = "mobile/re/osint/infra-ctl/destructive primitive";
        /* c244: k8s/mesh/registry/IaC helpers + secret CLIs + UAC/
         * LOLBin extras + backup destruct + exec-context/interp
         * primitives + dialog spoof + VPN/proxy/NAT ── */
        } else if (ci_contains(text, "kubectx") ||
                   ci_contains(text, "kubens") ||
                   (ci_contains(text, "k9s") &&
                    ci_contains(text, " ")) ||
                   (ci_contains(text, "stern") &&
                    ci_contains(text, " -")) ||
                   (ci_contains(text, "kail") &&
                    ci_contains(text, " -")) ||
                   ci_contains(text, "kubecm") ||
                   ci_contains(text, "krew ") ||
                   ci_contains(text, "telepresence") ||
                   ci_contains(text, "mirrord") ||
                   (ci_contains(text, "kapp") &&
                    (ci_contains(text, " deploy") ||
                     ci_contains(text, " delete"))) ||
                   (ci_contains(text, "kbld") &&
                    ci_contains(text, " -")) ||
                   (ci_contains(text, "ytt") &&
                    (ci_contains(text, " -f") ||
                     ci_contains(text, " --"))) ||
                   ci_contains(text, "vendir") ||
                   (ci_contains(text, "skaffold") &&
                    (ci_contains(text, " deploy") ||
                     ci_contains(text, " run") ||
                     ci_contains(text, " delete"))) ||
                   (ci_contains(text, "tilt") &&
                    (ci_contains(text, " up") ||
                     ci_contains(text, " down") ||
                     ci_contains(text, " ci"))) ||
                   (ci_contains(text, "garden") &&
                    (ci_contains(text, " deploy") ||
                     ci_contains(text, " delete") ||
                     ci_contains(text, " plugins"))) ||
                   (ci_contains(text, "draft") &&
                    (ci_contains(text, " up") ||
                     ci_contains(text, " create") ||
                     ci_contains(text, " -"))) ||
                   ci_contains(text, "istioctl") ||
                   ci_contains(text, "linkerd ") ||
                   (ci_contains(text, "consul") &&
                    (ci_contains(text, " connect") ||
                     ci_contains(text, " kv") ||
                     ci_contains(text, " acl") ||
                     ci_contains(text, " reload") ||
                     ci_contains(text, " leave"))) ||
                   ci_contains(text, "cilium") ||
                   ci_contains(text, "calicoctl") ||
                   ci_contains(text, "crane ") ||
                   ci_contains(text, "regctl") ||
                   (ci_contains(text, "notation") &&
                    (ci_contains(text, " sign") ||
                     ci_contains(text, " -"))) ||
                   ci_contains(text, "docker-credential-") ||
                   (ci_contains(text, "terragrunt") &&
                    (ci_contains(text, " destroy") ||
                     ci_contains(text, " apply") ||
                     ci_contains(text, " run-all"))) ||
                   (ci_contains(text, "atlantis") &&
                    (ci_contains(text, " plan") ||
                     ci_contains(text, " apply") ||
                     ci_contains(text, " unlock"))) ||
                   (ci_contains(text, "terramate") &&
                    ci_contains(text, " ")) ||
                   ci_contains(text, "crossplane") ||
                   (ci_contains(text, "checkov") &&
                    ci_contains(text, " -")) ||
                   (ci_contains(text, "tfsec") &&
                    ci_contains(text, " ")) ||
                   (ci_contains(text, "terrascan") &&
                    ci_contains(text, " ")) ||
                   ci_contains(text, "kics ") ||
                   (ci_contains(text, "conftest") &&
                    ci_contains(text, " ")) ||
                   (ci_contains(text, "opa") &&
                    (ci_contains(text, " eval") ||
                     ci_contains(text, " exec") ||
                     ci_contains(text, " run"))) ||
                   (ci_contains(text, "trivy") &&
                    ci_contains(text, " ")) ||
                   (ci_contains(text, "grype") &&
                    ci_contains(text, " ")) ||
                   (ci_contains(text, "syft") &&
                    ci_contains(text, " ")) ||
                   (ci_contains(text, "op ") &&
                    (ci_contains(text, "get") ||
                     ci_contains(text, "inject") ||
                     ci_contains(text, "signin") ||
                     ci_contains(text, "read") ||
                     ci_contains(text, "document") ||
                     ci_contains(text, "item") ||
                     ci_contains(text, "vault"))) ||
                   (ci_contains(text, "doppler") &&
                    (ci_contains(text, " secrets") ||
                     ci_contains(text, " run"))) ||
                   (ci_contains(text, "infisical") &&
                    ci_contains(text, " ")) ||
                   ci_contains(text, "pslist") ||
                   ci_contains(text, "pskill") ||
                   ci_contains(text, "psinfo") ||
                   ci_contains(text, "accesschk") ||
                   ci_contains(text, "autoruns") ||
                   ci_contains(text, "pipelist") ||
                   (ci_contains(text, "sigcheck") &&
                    ci_contains(text, " -")) ||
                   ci_contains(text, "streams -d") ||
                   ci_contains(text, "sdelete") ||
                   ci_contains(text, "fodhelper") ||
                   ci_contains(text, "computerdefaults") ||
                   ci_contains(text, "sdclt") ||
                   ci_contains(text, "slui") ||
                   ci_contains(text, "eventvwr") ||
                   ci_contains(text, "wsreset") ||
                   ci_contains(text, "wt.exe") ||
                   ci_contains(text, "te.exe") ||
                   (ci_contains(text, "tracker") &&
                    ci_contains(text, " -")) ||
                   ci_contains(text, "vsiisexelauncher") ||
                   ci_contains(text, "wmpsetup") ||
                   ci_contains(text, "workfolders") ||
                   ci_contains(text, "cmlutil") ||
                   (ci_contains(text, "slmgr") &&
                    (ci_contains(text, "/") ||
                     ci_contains(text, " -"))) ||
                   ci_contains(text, "rasautou") ||
                   ci_contains(text, "rdpsign") ||
                   (ci_contains(text, "sftp") &&
                    ci_contains(text, " -b")) ||
                   (ci_contains(text, "restic") &&
                    (ci_contains(text, " forget") ||
                     ci_contains(text, " backup") ||
                     ci_contains(text, " check") ||
                     ci_contains(text, " prune"))) ||
                   (ci_contains(text, "borg") &&
                    (ci_contains(text, " prune") ||
                     ci_contains(text, " delete") ||
                     ci_contains(text, " create"))) ||
                   (ci_contains(text, "rsync") &&
                    ci_contains(text, "--delete")) ||
                   ci_contains(text, "rdiff-backup") ||
                   (ci_contains(text, "duplicity") &&
                    (ci_contains(text, " remove") ||
                     ci_contains(text, " cleanup") ||
                     ci_contains(text, " full"))) ||
                   (ci_contains(text, "kopia") &&
                    (ci_contains(text, " snapshot delete") ||
                     ci_contains(text, " delete") ||
                     ci_contains(text, " maintenance"))) ||
                   ci_contains(text, "bconsole") ||
                   ci_contains(text, "setsid ") ||
                   (ci_contains(text, "nohup") &&
                    ci_contains(text, " ")) ||
                   (ci_contains(text, "disown") &&
                    (ci_contains(text, " -") ||
                     ci_contains(text, " %"))) ||
                   ci_contains(text, "daemonize ") ||
                   (ci_contains(text, "start-stop-daemon") &&
                    ci_contains(text, " -b")) ||
                   (ci_contains(text, "sg ") &&
                    ci_contains(text, " -c")) ||
                   (ci_contains(text, "newgrp") &&
                    ci_contains(text, " ")) ||
                   (ci_contains(text, "getcap") &&
                    (ci_contains(text, " /") ||
                     ci_contains(text, " -"))) ||
                   ci_contains(text, "ktutil") ||
                   ci_contains(text, "kadmin") ||
                   ci_contains(text, "msktutil") ||
                   (ci_contains(text, "systemd-run") &&
                    (ci_contains(text, "--pty") ||
                     ci_contains(text, "--uid") ||
                     ci_contains(text, "--collect") ||
                     ci_contains(text, "--property") ||
                     ci_contains(text, "--on-") ||
                     ci_contains(text, "--unit") ||
                     ci_contains(text, "--description") ||
                     ci_contains(text, "--timer") ||
                     ci_contains(text, "--path") ||
                     ci_contains(text, "--socket") ||
                     ci_contains(text, "--mount") ||
                     ci_contains(text, "--nice") ||
                     ci_contains(text, "--setenv") ||
                     ci_contains(text, "--working-directory"))) ||
                   ci_contains(text, "systemd-cat") ||
                   (ci_contains(text, "systemd-tmpfiles") &&
                    (ci_contains(text, " --create") ||
                     ci_contains(text, " --remove") ||
                     ci_contains(text, " --clean"))) ||
                   ci_contains(text, "systemd-inhibit") ||
                   (ci_contains(text, "busctl") &&
                    (ci_contains(text, " set-property") ||
                     ci_contains(text, " call") ||
                     ci_contains(text, " get-property"))) ||
                   (ci_contains(text, "logger") &&
                    (ci_contains(text, " -n") ||
                     ci_contains(text, " -r") ||
                     ci_contains(text, "--server") ||
                     ci_contains(text, " -t"))) ||
                   (ci_contains(text, "hwclock") &&
                    (ci_contains(text, "--systohc") ||
                     ci_contains(text, "--hctosys") ||
                     ci_contains(text, "--set") ||
                     ci_contains(text, "--adjust") ||
                     ci_contains(text, "--epoch="))) ||
                   ci_contains(text, "ntpdate") ||
                   (ci_contains(text, "chronyc") &&
                    (ci_contains(text, " offline") ||
                     ci_contains(text, " online") ||
                     ci_contains(text, " settime") ||
                     ci_contains(text, " makestep") ||
                     ci_contains(text, " sources"))) ||
                   (ci_contains(text, "tmux") &&
                    (ci_contains(text, " new-session -d") ||
                     ci_contains(text, " new -d") ||
                     ci_contains(text, " load-buffer") ||
                     ci_contains(text, " source-file"))) ||
                   (ci_contains(text, "screen") &&
                    (ci_contains(text, " -dm") ||
                     ci_contains(text, " -dms") ||
                     ci_contains(text, " -d -m"))) ||
                   (ci_contains(text, "inotifywait") &&
                    (ci_contains(text, " -m") ||
                     ci_contains(text, " -r") ||
                     ci_contains(text, " -e"))) ||
                   (ci_contains(text, "watch") &&
                    (ci_contains(text, " -n") ||
                     ci_contains(text, " -x"))) ||
                   ci_contains(text, "zenity") ||
                   ci_contains(text, "kdialog") ||
                   ci_contains(text, "whiptail") ||
                   (ci_contains(text, "newt") &&
                    ci_contains(text, " -")) ||
                   (ci_contains(text, "osascript") &&
                    (ci_contains(text, "display dialog") ||
                     ci_contains(text, "display alert"))) ||
                   (ci_contains(text, "notify-send") &&
                    (ci_contains(text, " -u") ||
                     ci_contains(text, " -i") ||
                     ci_contains(text, " --"))) ||
                   ci_contains(text, "dnctl ") ||
                   ci_contains(text, "natd") ||
                   ci_contains(text, "portfwd") ||
                   (ci_contains(text, "redir") &&
                    (ci_contains(text, "--lport") ||
                     ci_contains(text, "--cport") ||
                     ci_contains(text, "--laddr") ||
                     ci_contains(text, "--caddr") ||
                     ci_contains(text, "--bport") ||
                     ci_contains(text, "--bind"))) ||
                   (ci_contains(text, "nginx") &&
                    (ci_contains(text, " -c") ||
                     ci_contains(text, " -g"))) ||
                   (ci_contains(text, "haproxy") &&
                    (ci_contains(text, " -f") ||
                     ci_contains(text, " -db"))) ||
                   (ci_contains(text, "caddy") &&
                    (ci_contains(text, " run") ||
                     ci_contains(text, " reload"))) ||
                   (ci_contains(text, "tinyproxy") &&
                    ci_contains(text, " -")) ||
                   (ci_contains(text, "squid") &&
                    (ci_contains(text, " -f") ||
                     ci_contains(text, " -z") ||
                     ci_contains(text, " -k"))) ||
                   (ci_contains(text, "polipo") &&
                    ci_contains(text, " -")) ||
                   ci_contains(text, "microsocks") ||
                   ci_contains(text, "3proxy") ||
                   (ci_contains(text, "openvpn") &&
                    (ci_contains(text, " --config") ||
                     ci_contains(text, " --daemon") ||
                     ci_contains(text, " --up") ||
                     ci_contains(text, " --down") ||
                     ci_contains(text, "--script-security") ||
                     ci_contains(text, "--mktun") ||
                     ci_contains(text, "--rmtun") ||
                     ci_contains(text, "--remote") ||
                     ci_contains(text, "--dev "))) ||
                   ci_contains(text, "wireguard") ||
                   ci_contains(text, "wg-quick") ||
                   ci_contains(text, "xl2tpd") ||
                   ci_contains(text, "pptpd") ||
                   ci_contains(text, "openconnect") ||
                   ci_contains(text, "mkfifo /") ||
                   ci_contains(text, "tclsh") ||
                   (ci_contains(text, "julia") &&
                    ci_contains(text, " -e")) ||
                   (ci_contains(text, "r -e") ||
                    ci_contains(text, "rscript -e")) ||
                   (ci_contains(text, "octave") &&
                    ci_contains(text, " --eval")) ||
                   (ci_contains(text, "maxima") &&
                    ci_contains(text, " --batch")) ||
                   (ci_contains(text, "ghci") &&
                    ci_contains(text, " -e")) ||
                   ci_contains(text, "runhaskell") ||
                   (ci_contains(text, "fish") &&
                    ci_contains(text, " -c")) ||
                   (ci_contains(text, "zsh") &&
                    ci_contains(text, " -c")) ||
                   (ci_contains(text, "ksh") &&
                    ci_contains(text, " -c")) ||
                   (ci_contains(text, "dash") &&
                    ci_contains(text, " -c")) ||
                   (ci_contains(text, "csh") &&
                    ci_contains(text, " -c")) ||
                   (ci_contains(text, "powershell") &&
                    (ci_contains(text, " -c") ||
                     ci_contains(text, " -ec") ||
                     ci_contains(text, " -ep bypass") ||
                     ci_contains(text, " -ep unrestricted") ||
                     ci_contains(text, " -executionpolicy bypass") ||
                     ci_contains(text, " -executionpolicy unrestricted") ||
                     ci_contains(text, " -sta") ||
                     ci_contains(text, " -mta") ||
                     ci_contains(text, " -w hidden") ||
                     ci_contains(text, " -windowstyle hidden"))) ||
                   (ci_contains(text, "pwsh") &&
                    (ci_contains(text, " -c") ||
                     ci_contains(text, " -ep bypass") ||
                     ci_contains(text, " -ep unrestricted") ||
                     ci_contains(text, " -executionpolicy bypass") ||
                     ci_contains(text, " -executionpolicy unrestricted") ||
                     ci_contains(text, " -sta") ||
                     ci_contains(text, " -w hidden") ||
                     ci_contains(text, " -windowstyle hidden"))) ||
                   (ci_contains(text, "deno") &&
                    (ci_contains(text, " run ") ||
                     ci_contains(text, " run -") ||
                     ci_contains(text, " eval ") ||
                     ci_contains(text, " task "))) ||
                   (ci_contains(text, "bun ") &&
                    (ci_contains(text, " run") ||
                     ci_contains(text, " x ") ||
                     ci_contains(text, " -e"))) ||
                   ci_contains(text, "bunx") ||
                   (ci_contains(text, "npx") &&
                    ci_contains(text, " ")) ||
                   (ci_contains(text, "pnpm") &&
                    (ci_contains(text, " dlx") ||
                     ci_contains(text, " exec"))) ||
                   (ci_contains(text, "yarn") &&
                    (ci_contains(text, " dlx") ||
                     ci_contains(text, " exec"))) ||
                   (ci_contains(text, "pipx") &&
                    ci_contains(text, " ")) ||
                   (ci_contains(text, "go ") &&
                    (ci_contains(text, " install") ||
                     ci_contains(text, " run"))) ||
                   (ci_contains(text, "composer") &&
                    (ci_contains(text, " require") ||
                     ci_contains(text, " global") ||
                     ci_contains(text, " exec") ||
                     ci_contains(text, " create-project") ||
                     ci_contains(text, " install"))) ||
                   (ci_contains(text, "nimble") &&
                    (ci_contains(text, " install") ||
                     ci_contains(text, " build") ||
                     ci_contains(text, " run") ||
                     ci_contains(text, " init") ||
                     ci_contains(text, " doc") ||
                     ci_contains(text, " refresh"))) ||
                   (ci_contains(text, "opam") &&
                    (ci_contains(text, " install") ||
                     ci_contains(text, " exec"))) ||
                   (ci_contains(text, "luarocks") &&
                    ci_contains(text, " ")) ||
                   (ci_contains(text, "julia") &&
                    ci_contains(text, " -e")) ||
                   (ci_contains(text, "at ") &&
                    (ci_contains(text, "now") ||
                     ci_contains(text, " -f"))) ||
                   (ci_contains(text, "batch") &&
                    (ci_contains(text, " <") ||
                     ci_contains(text, " -f"))) ||
                   ci_contains(text, "env -i") ||
                   (ci_contains(text, "env ") &&
                    (ci_contains(text, " -i") ||
                     (ci_contains(text, "=") &&
                      (ci_contains(text, " sh") ||
                       ci_contains(text, "bash") ||
                       ci_contains(text, "zsh") ||
                       ci_contains(text, "dash") ||
                       ci_contains(text, "ksh") ||
                       ci_contains(text, "csh") ||
                       ci_contains(text, "fish") ||
                       ci_contains(text, " cmd") ||
                       ci_contains(text, "powershell") ||
                       ci_contains(text, "pwsh") ||
                       ci_contains(text, "python") ||
                       ci_contains(text, "perl") ||
                       ci_contains(text, "ruby") ||
                       ci_contains(text, "node") ||
                       ci_contains(text, "php") ||
                       ci_contains(text, "curl") ||
                       ci_contains(text, "wget") ||
                       ci_contains(text, "nc ") ||
                       ci_contains(text, "socat") ||
                       ci_contains(text, " awk") ||
                       ci_contains(text, "base64")))))) {
            what = "k8s/mesh/registry/iac/sec-cli/uac/exec primitive";
        }
        /* ── cycle-245: db exfil/backup + rmm/remote access + modern
           proxy/tunnel transports + BYOVD/packers + cloud-attack +
           spray/phish kits + miners + bcc/forensics + wifi/bt/nfc/can/
           scada + remaining win/unix mgmt primitives ── */
        else if (
            /* db dump / exfil primitives */
            ci_contains(text, "pg_dump") ||
            ci_contains(text, "mysqldump") ||
            ci_contains(text, "mariadb-dump") ||
            ci_contains(text, "mariadb-backup") ||
            ci_contains(text, "mariabackup") ||
            ci_contains(text, "mongodump") ||
            ci_contains(text, "mongoexport") ||
            ci_contains(text, "elasticdump") ||
            (ci_contains(text, "sqlite3") &&
             ci_contains(text, ".dump")) ||
            (ci_contains(text, "redis-cli") &&
             ci_contains(text, "--rdb")) ||
            (ci_contains(text, "bcp") &&
             ci_contains(text, " out")) ||
            ci_contains(text, "expdp") ||
            ci_contains(text, "sqlldr") ||
            ci_contains(text, "wal-g") ||
            ci_contains(text, "pgbackrest") ||
            ci_contains(text, "xtrabackup") ||
            (ci_contains(text, "nodetool") &&
             (ci_contains(text, " drain") ||
              ci_contains(text, " cleanup") ||
              ci_contains(text, " decommission") ||
              ci_contains(text, " snapshot") ||
              ci_contains(text, " clearsnapshot") ||
              ci_contains(text, " disablebinary") ||
              ci_contains(text, " stopdaemon"))) ||
            (ci_contains(text, "gluster") &&
             (ci_contains(text, " delete") ||
              ci_contains(text, " stop") ||
              ci_contains(text, " rebalance"))) ||
            (ci_contains(text, "rbd") &&
             (ci_contains(text, " rm") ||
              ci_contains(text, " remove") ||
              ci_contains(text, " snap") ||
              ci_contains(text, " map") ||
              ci_contains(text, " bench-write"))) ||
            /* mail pull-down / sync = mailbox theft */
            (ci_contains(text, "fetchmail") &&
             (ci_contains(text, " -k") ||
              ci_contains(text, " -a") ||
              ci_contains(text, " -d") ||
              ci_contains(text, " -f"))) ||
            ci_contains(text, "offlineimap") ||
            ci_contains(text, "mbsync") ||
            /* object stores / ipfs publish */
            (ci_contains(text, "ipfs") &&
             (ci_contains(text, " add") ||
              ci_contains(text, " pin") ||
              ci_contains(text, " get") ||
              ci_contains(text, " swarm") ||
              ci_contains(text, " daemon") ||
              ci_contains(text, " block") ||
              ci_contains(text, " name"))) ||
            (ci_contains(text, "s3cmd") &&
             (ci_contains(text, " put") ||
              ci_contains(text, " get") ||
              ci_contains(text, " sync") ||
              ci_contains(text, " del") ||
              ci_contains(text, " rm") ||
              ci_contains(text, " mb") ||
              ci_contains(text, " rb"))) ||
            (ci_contains(text, "mc ") &&
             (ci_contains(text, " cp") ||
              ci_contains(text, " mv") ||
              ci_contains(text, " rm") ||
              ci_contains(text, " mirror") ||
              ci_contains(text, " share") ||
              ci_contains(text, " admin"))) ||
            (ci_contains(text, "velero") &&
             (ci_contains(text, " create") ||
              ci_contains(text, " delete") ||
              ci_contains(text, " restore") ||
              ci_contains(text, " download") ||
              ci_contains(text, " uninstall") ||
              ci_contains(text, " install"))) ||
            (ci_contains(text, "tkn") &&
             (ci_contains(text, " delete") ||
              ci_contains(text, " start") ||
              ci_contains(text, " cancel") ||
              ci_contains(text, " trigger") ||
              ci_contains(text, " pipelinerun") ||
              ci_contains(text, " taskrun"))) ||
            (ci_contains(text, "kn ") &&
             (ci_contains(text, " delete ") ||
              ci_contains(text, " apply ") ||
              ci_contains(text, " service ") ||
              ci_contains(text, " revision ") ||
              ci_contains(text, " route "))) ||
            (ci_contains(text, "argo ") &&
             (ci_contains(text, " submit ") ||
              ci_contains(text, " stop ") ||
              ci_contains(text, " delete ") ||
              ci_contains(text, " resubmit ") ||
              ci_contains(text, " retry ") ||
              ci_contains(text, " terminate ") ||
              ci_contains(text, " suspend "))) ||
            ci_contains(text, "buildctl") ||
            (ci_contains(text, "crun") &&
             (ci_contains(text, " exec") ||
              ci_contains(text, " run") ||
              ci_contains(text, " create") ||
              ci_contains(text, " delete") ||
              ci_contains(text, " kill"))) ||
            ci_contains(text, "jexec") ||
            (ci_contains(text, "toolbox") &&
             (ci_contains(text, " enter") ||
              ci_contains(text, " run") ||
              ci_contains(text, " create") ||
              ci_contains(text, " rm"))) ||
            (ci_contains(text, "distrobox") &&
             (ci_contains(text, " enter") ||
              ci_contains(text, " rm") ||
              ci_contains(text, " create") ||
              ci_contains(text, " ephemeral"))) ||
            /* rmm / remote-access tooling (legit tools, abused for
               persistence + lateral + exfil) */
            ci_contains(text, "teamviewer") ||
            ci_contains(text, "anydesk") ||
            ci_contains(text, "rustdesk") ||
            ci_contains(text, "screenconnect") ||
            ci_contains(text, "meshagent") ||
            ci_contains(text, "ninjarmm") ||
            ci_contains(text, "atera") ||
            ci_contains(text, "datto") ||
            ci_contains(text, "syncro") ||
            ci_contains(text, "splashtop") ||
            ci_contains(text, "realvnc") ||
            ci_contains(text, "tightvnc") ||
            ci_contains(text, "ultravnc") ||
            ci_contains(text, "nomachine") ||
            ci_contains(text, "dwagent") ||
            ci_contains(text, "dwservice") ||
            (ci_contains(text, "parsec") &&
             ci_contains(text, " -")) ||
            (ci_contains(text, "moonlight") &&
             ci_contains(text, " -")) ||
            ci_contains(text, "hamachi") ||
            ci_contains(text, "logmein") ||
            ci_contains(text, "tacticalrmm") ||
            ci_contains(text, "simplehelp") ||
            (ci_contains(text, "supremo") &&
             ci_contains(text, " -")) ||
            ci_contains(text, "aeroadmin") ||
            ci_contains(text, "ammyy") ||
            ci_contains(text, "impero") ||
            ci_contains(text, "sshx") ||
            ci_contains(text, "upterm") ||
            ci_contains(text, "xrdp") ||
            ci_contains(text, "remotepc") ||
            ci_contains(text, "litemanager") ||
            ci_contains(text, "mikogo") ||
            ci_contains(text, "goverlan") ||
            ci_contains(text, "optitune") ||
            ci_contains(text, "addigy") ||
            ci_contains(text, "quickassist") ||
            ci_contains(text, "islonline") ||
            ci_contains(text, "netop") ||
            ci_contains(text, "gocket") ||
            ci_contains(text, "beanywhere") ||
            ci_contains(text, "splashtop") ||
            /* modern proxy / tunnel / c2 transports */
            ci_contains(text, "sing-box") ||
            ci_contains(text, "mihomo") ||
            ci_contains(text, "hiddify") ||
            ci_contains(text, "naiveproxy") ||
            (ci_contains(text, "brook") &&
             ci_contains(text, " -")) ||
            ci_contains(text, "tuic") ||
            ci_contains(text, "juicity") ||
            (ci_contains(text, "snell") &&
             ci_contains(text, " -")) ||
            ci_contains(text, "v2fly") ||
            ci_contains(text, "ocserv") ||
            ci_contains(text, "tincd") ||
            (ci_contains(text, "tailscale") &&
             (ci_contains(text, " up") ||
              ci_contains(text, " login") ||
              ci_contains(text, " serve") ||
              ci_contains(text, " funnel") ||
              ci_contains(text, " ssh") ||
              ci_contains(text, " logout"))) ||
            (ci_contains(text, "zerotier") &&
             (ci_contains(text, " join") ||
              ci_contains(text, " leave") ||
              ci_contains(text, " set") ||
              ci_contains(text, "cli"))) ||
            (ci_contains(text, "netbird") &&
             (ci_contains(text, " up") ||
              ci_contains(text, " login") ||
              ci_contains(text, " down"))) ||
            (ci_contains(text, "nebula") &&
             ci_contains(text, " -")) ||
            ci_contains(text, "headscale") ||
            ci_contains(text, "innernet") ||
            ci_contains(text, "netmaker") ||
            ci_contains(text, "nps") ||
            ci_contains(text, "npc") ||
            ci_contains(text, "suo5") ||
            (ci_contains(text, "venom") &&
             ci_contains(text, " -")) ||
            (ci_contains(text, "stowaway") &&
             ci_contains(text, " -")) ||
            ci_contains(text, "iox") ||
            ci_contains(text, "rakshasa") ||
            ci_contains(text, "regory") ||
            ci_contains(text, "ssf") ||
            ci_contains(text, "pystinger") ||
            (ci_contains(text, "lcx ") &&
             ci_contains(text, " -")) ||
            ci_contains(text, "htran") ||
            ci_contains(text, "rinetd") ||
            ci_contains(text, "redsocks") ||
            ci_contains(text, "tun2socks") ||
            ci_contains(text, "mosh-server") ||
            ci_contains(text, "localtunnel") ||
            (ci_contains(text, "expose") &&
             ci_contains(text, " -")) ||
            ci_contains(text, "pagekite") ||
            (ci_contains(text, "bore") &&
             ci_contains(text, " -")) ||
            (ci_contains(text, "inlets") &&
             ci_contains(text, " -")) ||
            ci_contains(text, "packetriot") ||
            ci_contains(text, "localxpose") ||
            ci_contains(text, "ztncui") ||
            (ci_contains(text, "tinc") &&
             (ci_contains(text, " init") ||
              ci_contains(text, " start") ||
              ci_contains(text, " join") ||
              ci_contains(text, " -c"))) ||
            /* BYOVD drivers + packers/protectors + shellcode */
            ci_contains(text, "kdmapper") ||
            ci_contains(text, "capcom.sys") ||
            ci_contains(text, "gdrv.sys") ||
            ci_contains(text, "dbutil") ||
            ci_contains(text, "rtcore64") ||
            ci_contains(text, "iqvw64e") ||
            ci_contains(text, "asrdrv") ||
            ci_contains(text, "vboxdrv") ||
            ci_contains(text, "hevd") ||
            ci_contains(text, "runpe") ||
            ci_contains(text, "themida") ||
            ci_contains(text, "vmprotect") ||
            ci_contains(text, "obsidium") ||
            ci_contains(text, "molebox") ||
            ci_contains(text, "mpress") ||
            ci_contains(text, "aspack") ||
            (ci_contains(text, "petite") &&
             ci_contains(text, " -")) ||
            ci_contains(text, "kkrunchy") ||
            (ci_contains(text, "sgn") &&
             ci_contains(text, " -")) ||
            ci_contains(text, "pe2sh") ||
            (ci_contains(text, "amber") &&
             ci_contains(text, " -")) ||
            ci_contains(text, "inceptor") ||
            ci_contains(text, "pecloak") ||
            /* cryptominer names */
            (ci_contains(text, "t-rex") &&
             ci_contains(text, " -")) ||
            (ci_contains(text, "claymore") &&
             ci_contains(text, " -")) ||
            ci_contains(text, "srbminer") ||
            ci_contains(text, "cryptotab") ||
            ci_contains(text, "ccminer") ||
            ci_contains(text, "wildrig") ||
            (ci_contains(text, "excavator") &&
             ci_contains(text, " -")) ||
            /* ad / recon / osint / cloud-attack names */
            (ci_contains(text, "cme ") &&
             ci_contains(text, " -")) ||
            ci_contains(text, "adfind") ||
            ci_contains(text, "admod") ||
            ci_contains(text, "kekeo") ||
            (ci_contains(text, "certify") &&
             ci_contains(text, " -")) ||
            ci_contains(text, "maigret") ||
            (ci_contains(text, "blackbird") &&
             ci_contains(text, " -")) ||
            (ci_contains(text, "snoop") &&
             ci_contains(text, " -")) ||
            ci_contains(text, "toutatis") ||
            ci_contains(text, "instaloader") ||
            ci_contains(text, "osintgram") ||
            ci_contains(text, "git-dumper") ||
            ci_contains(text, "gitgraber") ||
            ci_contains(text, "dvcs-ripper") ||
            ci_contains(text, "uro ") ||
            (ci_contains(text, "unfurl") &&
             ci_contains(text, " -")) ||
            ci_contains(text, "waymore") ||
            ci_contains(text, "linkfinder") ||
            ci_contains(text, "qsreplace") ||
            ci_contains(text, "cloudfox") ||
            (ci_contains(text, "pacu") &&
              (ci_contains(text, " -") || ci_contains(text, " --") ||
               ci_contains(text, " run ") || ci_contains(text, " module") ||
               ci_contains(text, " exec") || ci_contains(text, " session"))) ||
            ci_contains(text, "enumerate-iam") ||
            ci_contains(text, "prowler") ||
            ci_contains(text, "s3scanner") ||
            ci_contains(text, "s3enum") ||
            ci_contains(text, "bucketfinder") ||
            ci_contains(text, "awsbucketdump") ||
            ci_contains(text, "grayhatwarfare") ||
            ci_contains(text, "skyark") ||
            ci_contains(text, "weirdaal") ||
            ci_contains(text, "iamhound") ||
            ci_contains(text, "o365spray") ||
            ci_contains(text, "msolspray") ||
            ci_contains(text, "adfspray") ||
            ci_contains(text, "fireprox") ||
            ci_contains(text, "spray365") ||
            ci_contains(text, "trevorspray") ||
            ci_contains(text, "credmaster") ||
            ci_contains(text, "go365") ||
            (ci_contains(text, "ruler") &&
             ci_contains(text, " -")) ||
            /* phish kits + c2 extras + webshells */
            ci_contains(text, "evilnovnc") ||
            ci_contains(text, "cred-sniper") ||
            (ci_contains(text, "merlin") &&
             ci_contains(text, " -")) ||
            ci_contains(text, "pupy") ||
            (ci_contains(text, "chaos") &&
             ci_contains(text, " -")) ||
            ci_contains(text, "wsc2") ||
            ci_contains(text, "doctrack") ||
            (ci_contains(text, "chopper") &&
             ci_contains(text, " -")) ||
            ci_contains(text, "tinyshell") ||
            ci_contains(text, "webhandler") ||
            ci_contains(text, "kubestriker") ||
            ci_contains(text, "kubelite") ||
            /* bcc / ebpf snoopers */
            ci_contains(text, "sslsniff") ||
            ci_contains(text, "bashreadline") ||
            ci_contains(text, "tcpconnect") ||
            ci_contains(text, "tcpaccept") ||
            ci_contains(text, "statsnoop") ||
            ci_contains(text, "capable") ||
            ci_contains(text, "funclatency") ||
            ci_contains(text, "argdist") ||
            ci_contains(text, "funccount") ||
            /* forensic / memory acquisition tools */
            ci_contains(text, "tsk_") ||
            (ci_contains(text, "fls") &&
             ci_contains(text, " -")) ||
            ci_contains(text, "icat ") ||
            ci_contains(text, "mmls") ||
            (ci_contains(text, "autopsy") &&
             ci_contains(text, " -")) ||
            ci_contains(text, "sleuthkit") ||
            ci_contains(text, "dcfldd") ||
            ci_contains(text, "dc3dd") ||
            ci_contains(text, "ddrescue") ||
            ci_contains(text, "safecopy") ||
            (ci_contains(text, "foremost") &&
             ci_contains(text, " -")) ||
            (ci_contains(text, "scalpel") &&
             ci_contains(text, " -")) ||
            ci_contains(text, "magicrescue") ||
            (ci_contains(text, "lime") &&
             ci_contains(text, " -")) ||
            ci_contains(text, "fmem") ||
            ci_contains(text, "memdump") ||
            ci_contains(text, "mdd") ||
            ci_contains(text, "makedumpfile") ||
            ci_contains(text, "vmss2core") ||
            /* fim / edr / host-monitor names (recon or kill target) */
            ci_contains(text, "osqueryi") ||
            (ci_contains(text, "velociraptor") &&
             ci_contains(text, " -")) ||
            ci_contains(text, "ossec") ||
            (ci_contains(text, "samhain") &&
             ci_contains(text, " -")) ||
            (ci_contains(text, "aide") &&
             ci_contains(text, " --")) ||
            (ci_contains(text, "tripwire") &&
             ci_contains(text, " --")) ||
            ci_contains(text, "wazuh") ||
            ci_contains(text, "afick") ||
            ci_contains(text, "integrit") ||
            /* mitmproxy / dsniff suite / dos tools */
            ci_contains(text, "mitmdump") ||
            ci_contains(text, "urlsnarf") ||
            ci_contains(text, "filesnarf") ||
            ci_contains(text, "mailsnarf") ||
            ci_contains(text, "msgsnarf") ||
            ci_contains(text, "sshmitm") ||
            ci_contains(text, "webmitm") ||
            ci_contains(text, "webspy") ||
            ci_contains(text, "tcpkill") ||
            ci_contains(text, "tcpnice") ||
            ci_contains(text, "slowhttptest") ||
            (ci_contains(text, "goldeneye") &&
             ci_contains(text, " -")) ||
            (ci_contains(text, "hulk") &&
             ci_contains(text, " -")) ||
            (ci_contains(text, "rudy") &&
             ci_contains(text, " -")) ||
            ci_contains(text, "torshammer") ||
            ci_contains(text, "pyloris") ||
            ci_contains(text, "ufonet") ||
            ci_contains(text, "xerxes") ||
            /* thc-ipv6 suite */
            ci_contains(text, "thc-ipv6") ||
            ci_contains(text, "atk6-") ||
            ci_contains(text, "denial6") ||
            ci_contains(text, "dos-new-ip6") ||
            ci_contains(text, "flood_router6") ||
            ci_contains(text, "flood_mld") ||
            ci_contains(text, "flood_dhcpc6") ||
            ci_contains(text, "flood_rs6") ||
            ci_contains(text, "flood_advertise6") ||
            ci_contains(text, "flood_redir6") ||
            ci_contains(text, "flood_solicitate6") ||
            ci_contains(text, "flood_router26") ||
            ci_contains(text, "fake_router6") ||
            ci_contains(text, "fake_dns6d") ||
            ci_contains(text, "fake_dhcps6") ||
            ci_contains(text, "fake_mld6") ||
            ci_contains(text, "fake_mld26") ||
            ci_contains(text, "fake_solicitate6") ||
            ci_contains(text, "fake_advertise6") ||
            ci_contains(text, "kill_router6") ||
            ci_contains(text, "ndpexhaust") ||
            ci_contains(text, "thcping6") ||
            ci_contains(text, "thcsyn6") ||
            ci_contains(text, "smurf6") ||
            ci_contains(text, "rsmurf6") ||
            ci_contains(text, "toobig6") ||
            ci_contains(text, "trace6 ") ||
            ci_contains(text, "fuzz_ip6") ||
            ci_contains(text, "inject_alive6") ||
            ci_contains(text, "passive_discovery6") ||
            ci_contains(text, "dnsdict6") ||
            ci_contains(text, "dnsrevenum6") ||
            ci_contains(text, "dump_router6") ||
            ci_contains(text, "exploit6") ||
            ci_contains(text, "sendpees") ||
            ci_contains(text, "node_query6") ||
            ci_contains(text, "randicmp6") ||
            ci_contains(text, "redir6") ||
            /* snmp / ike / zip-pw crackers */
            ci_contains(text, "onesixtyone") ||
            ci_contains(text, "snmpwalk") ||
            ci_contains(text, "snmpget") ||
            ci_contains(text, "snmpset") ||
            ci_contains(text, "snmpcheck") ||
            ci_contains(text, "ike-scan") ||
            ci_contains(text, "psk-crack") ||
            ci_contains(text, "vpnc") ||
            ci_contains(text, "swanctl") ||
            ci_contains(text, "racoon") ||
            ci_contains(text, "fcrackzip") ||
            ci_contains(text, "pdfcrack") ||
            ci_contains(text, "rarcrack") ||
            ci_contains(text, "pkcrack") ||
            ci_contains(text, "bkcrack") ||
            ci_contains(text, "rcrack") ||
            ci_contains(text, "ophcrack") ||
            ci_contains(text, "cowpatty") ||
            ci_contains(text, "asleap") ||
            ci_contains(text, "pyrit") ||
            ci_contains(text, "eapeak") ||
            /* wifi attack extras */
            ci_contains(text, "hcxdumptool") ||
            ci_contains(text, "hcxpcapngtool") ||
            ci_contains(text, "besside-ng") ||
            ci_contains(text, "airdecap-ng") ||
            ci_contains(text, "tkiptun-ng") ||
            ci_contains(text, "wesside-ng") ||
            ci_contains(text, "packetforge-ng") ||
            ci_contains(text, "airolib-ng") ||
            ci_contains(text, "easside-ng") ||
            ci_contains(text, "airserv-ng") ||
            ci_contains(text, "ivstools") ||
            ci_contains(text, "makeivs-ng") ||
            ci_contains(text, "buddy-ng") ||
            ci_contains(text, "create_ap") ||
            ci_contains(text, "fern-wifi") ||
            ci_contains(text, "linset") ||
            ci_contains(text, "wpa_cli") ||
            /* bluetooth / nfc / can / scada extras */
            ci_contains(text, "spooftooph") ||
            ci_contains(text, "redfang") ||
            ci_contains(text, "bluesnarfer") ||
            ci_contains(text, "bluelog") ||
            ci_contains(text, "btscanner") ||
            ci_contains(text, "l2ping") ||
            ci_contains(text, "sdptool") ||
            ci_contains(text, "obexftp") ||
            ci_contains(text, "ussp-push") ||
            (ci_contains(text, "chameleon") &&
             (ci_contains(text, " mini") ||
              ci_contains(text, " -"))) ||
            ci_contains(text, "rfidiot") ||
            ci_contains(text, "ykman") ||
            ci_contains(text, "pkcs11-tool") ||
            ci_contains(text, "pkcs15") ||
            ci_contains(text, "opensc-tool") ||
            ci_contains(text, "pcsc_scan") ||
            ci_contains(text, "yubico-piv-tool") ||
            ci_contains(text, "cardpeek") ||
            ci_contains(text, "mifare") ||
            ci_contains(text, "cansend") ||
            ci_contains(text, "candump") ||
            ci_contains(text, "canplayer") ||
            ci_contains(text, "cansniffer") ||
            ci_contains(text, "isotpsend") ||
            ci_contains(text, "slcand") ||
            ci_contains(text, "plcscan") ||
            ci_contains(text, "s7scan") ||
            ci_contains(text, "mbtget") ||
            ci_contains(text, "diagslave") ||
            ci_contains(text, "opcua-client") ||
            ci_contains(text, "iec104") ||
            ci_contains(text, "dnp3") ||
            ci_contains(text, "enip") ||
            ci_contains(text, "s7comm") ||
            ci_contains(text, "plcinjector") ||
            ci_contains(text, "melsec") ||
            ci_contains(text, "codesys") ||
            /* remaining windows primitives */
            ci_contains(text, "mofcomp") ||
            ci_contains(text, "wbemtest") ||
            (ci_contains(text, "msdt") &&
             (ci_contains(text, " -path") ||
              ci_contains(text, " /id") ||
              ci_contains(text, " /path") ||
              ci_contains(text, ".diagcab"))) ||
            ci_contains(text, "sdiageng") ||
            (ci_contains(text, "mmc") &&
             (ci_contains(text, ".msc") ||
              ci_contains(text, " -a")) ) ||
            ci_contains(text, "winhelp") ||
            (ci_contains(text, "setx") &&
             ci_contains(text, " /m")) ||
            (ci_contains(text, "cipher") &&
             (ci_contains(text, " /e") ||
              ci_contains(text, " /d") ||
              ci_contains(text, " /w") ||
              ci_contains(text, " /x") ||
              ci_contains(text, " /k"))) ||
            (ci_contains(text, "fsutil") &&
             (ci_contains(text, " volume dismount") ||
              ci_contains(text, " hardlink") ||
              ci_contains(text, " reparsepoint") ||
              ci_contains(text, " resource") ||
              ci_contains(text, " quota") ||
              ci_contains(text, " objectid") ||
              ci_contains(text, " 8dot3name strip") ||
              ci_contains(text, " dirty set"))) ||
            (ci_contains(text, "mountvol") &&
             (ci_contains(text, " /p") ||
              ci_contains(text, " /d") ||
              ci_contains(text, " /r"))) ||
            (ci_contains(text, "subst") &&
             (ci_contains(text, " c:") ||
              ci_contains(text, " d:") ||
              ci_contains(text, " e:") ||
              ci_contains(text, " \\") ||
              ci_contains(text, ".exe") ||
              ci_contains(text, ".bat") ||
              ci_contains(text, ".ps1"))) ||
            ci_contains(text, "wecutil") ||
            ((ci_contains(text, "netsh wfp") &&
              ci_contains(text, " capture")) ||
             (ci_contains(text, "netsh winhttp") &&
              ci_contains(text, " set"))) ||
            (ci_contains(text, "wpr") &&
             (ci_contains(text, " -start") ||
              ci_contains(text, " -stop") ||
              ci_contains(text, " -cancel") ||
              ci_contains(text, " -status"))) ||
            (ci_contains(text, "xperf") &&
             (ci_contains(text, " -on") ||
              ci_contains(text, " -d") ||
              ci_contains(text, " -stop") ||
              ci_contains(text, " -start") ||
              ci_contains(text, " -end"))) ||
            ci_contains(text, "tracerpt") ||
            (ci_contains(text, "relog") &&
             ci_contains(text, " ")) ||
            ci_contains(text, "imagex") ||
            (ci_contains(text, "appcmd") &&
             (ci_contains(text, " add") ||
              ci_contains(text, " delete") ||
              ci_contains(text, " set") ||
              ci_contains(text, " install") ||
              ci_contains(text, " start") ||
              ci_contains(text, " stop") ||
              ci_contains(text, " recycle"))) ||
            (ci_contains(text, "aspnet_regiis") &&
             ci_contains(text, " -")) ||
            (ci_contains(text, "gacutil") &&
             (ci_contains(text, " /u") ||
              ci_contains(text, " /i") ||
              ci_contains(text, " /r"))) ||
            (ci_contains(text, "ngen") &&
             (ci_contains(text, " uninstall") ||
              ci_contains(text, " install") ||
              ci_contains(text, " executequeueditems") ||
              ci_contains(text, " update"))) ||
            (ci_contains(text, "devenv") &&
             (ci_contains(text, " /command") ||
              ci_contains(text, " /run") ||
              ci_contains(text, " /r "))) ||
            ci_contains(text, "csi ") ||
            ci_contains(text, "fsi ") ||
            ci_contains(text, "scriptcs") ||
            ci_contains(text, "dotnet-script") ||
            ci_contains(text, "usoclient") ||
            ci_contains(text, "wuauclt") ||
            /* remaining unix primitives */
            (ci_contains(text, "keyctl") &&
             (ci_contains(text, " dump") ||
              ci_contains(text, " print") ||
              ci_contains(text, " pipe") ||
              ci_contains(text, " search") ||
              ci_contains(text, " update") ||
              ci_contains(text, " revoke") ||
              ci_contains(text, " negate") ||
              ci_contains(text, " purge"))) ||
            (ci_contains(text, "sbctl") &&
             (ci_contains(text, " enroll") ||
              ci_contains(text, " sign") ||
              ci_contains(text, " create") ||
              ci_contains(text, " remove") ||
              ci_contains(text, " reset"))) ||
            ci_contains(text, "sbsign") ||
            (ci_contains(text, "fio") &&
             ci_contains(text, "/dev/")) ||
            ci_contains(text, "badblocks -w") ||
            ci_contains(text, "sg_persist") ||
            (ci_contains(text, "ndctl") &&
             (ci_contains(text, " destroy") ||
              ci_contains(text, " disable") ||
              ci_contains(text, " init-labels") ||
              ci_contains(text, " zero-labels") ||
              ci_contains(text, " sanitize") ||
              ci_contains(text, " create-namespace") ||
              ci_contains(text, " start-scrub"))) ||
            (ci_contains(text, "ipmctl") &&
             (ci_contains(text, " delete") ||
              ci_contains(text, " create") ||
              ci_contains(text, " format") ||
              ci_contains(text, " sanitize"))) ||
            ci_contains(text, "binfmt_misc/register") ||
            ci_contains(text, "systemd-sysusers") ||
            ci_contains(text, "systemd-firstboot") ||
            (ci_contains(text, "portablectl") &&
             (ci_contains(text, " attach") ||
              ci_contains(text, " detach") ||
              ci_contains(text, " reattach"))) ||
            ci_contains(text, "ld-linux") ||
            ci_contains(text, "ld-musl") ||
            ci_contains(text, "ld.so.2") ||
            (ci_contains(text, "flatpak-spawn") &&
             ci_contains(text, "--host")) ||
            (ci_contains(text, "gdbus") &&
             (ci_contains(text, " call ") ||
              ci_contains(text, " emit ") ||
              ci_contains(text, " monitor "))) ||
            ci_contains(text, "killall5") ||
            (ci_contains(text, "fuser") &&
             ci_contains(text, " -k")) ||
            (ci_contains(text, "accton") &&
             ci_contains(text, " off")) ||
            (ci_contains(text, "vconfig") &&
             (ci_contains(text, " add ") ||
              ci_contains(text, " rem "))) ||
            (ci_contains(text, "rfkill") &&
             (ci_contains(text, " block ") ||
              ci_contains(text, " unblock "))) ||
            (ci_contains(text, "update-rc.d") &&
             (ci_contains(text, " defaults") ||
              ci_contains(text, " remove") ||
              ci_contains(text, " enable") ||
              ci_contains(text, " disable"))) ||
            (ci_contains(text, "chkconfig") &&
             (ci_contains(text, " --add") ||
              ci_contains(text, " --del") ||
              ci_contains(text, " on") ||
              ci_contains(text, " off"))) ||
            (ci_contains(text, "opkg") &&
             (ci_contains(text, " install ") ||
              ci_contains(text, " remove ") ||
              ci_contains(text, " upgrade "))) ||
            (ci_contains(text, "emerge") &&
             (ci_contains(text, " --unmerge") ||
              ci_contains(text, " --depclean") ||
              ci_contains(text, " -c") ||
              ci_contains(text, " --sync"))) ||
            (ci_contains(text, "pkg ") &&
             (ci_contains(text, " install ") ||
              ci_contains(text, " delete ") ||
              ci_contains(text, " remove "))) ||
            (ci_contains(text, "snap") &&
             (ci_contains(text, " install ") ||
              ci_contains(text, " remove ") ||
              ci_contains(text, " refresh "))) ||
            (ci_contains(text, "flatpak") &&
             (ci_contains(text, " install ") ||
              ci_contains(text, " uninstall ") ||
              ci_contains(text, " override ") ||
              ci_contains(text, " kill ") ||
              ci_contains(text, " run "))) ||
            (ci_contains(text, "brew") &&
             (ci_contains(text, " install ") ||
              ci_contains(text, " uninstall ") ||
              ci_contains(text, " remove "))) ||
            (ci_contains(text, "port") &&
             (ci_contains(text, " install ") ||
              ci_contains(text, " uninstall "))) ||
            (ci_contains(text, "uv ") &&
             (ci_contains(text, " pip") ||
              ci_contains(text, " tool") ||
              ci_contains(text, " publish") ||
              ci_contains(text, "x"))) ||
            (ci_contains(text, "rye") &&
             (ci_contains(text, " add ") ||
              ci_contains(text, " remove ") ||
              ci_contains(text, " sync ") ||
              ci_contains(text, " install ") ||
              ci_contains(text, " publish "))) ||
            (ci_contains(text, "mamba") &&
             (ci_contains(text, " install ") ||
              ci_contains(text, " remove ") ||
              ci_contains(text, " uninstall "))) ||
            (ci_contains(text, "conda") &&
             (ci_contains(text, " install ") ||
              ci_contains(text, " remove ") ||
              ci_contains(text, " env remove"))) ||
            (ci_contains(text, "poetry") &&
             (ci_contains(text, " add ") ||
              ci_contains(text, " remove ") ||
              ci_contains(text, " publish ") ||
              ci_contains(text, " install "))) ||
            (ci_contains(text, "pdm") &&
             (ci_contains(text, " add ") ||
              ci_contains(text, " remove ") ||
              ci_contains(text, " publish ") ||
              ci_contains(text, " install "))) ||
            (ci_contains(text, "dotnet") &&
             (ci_contains(text, " tool ") ||
              ci_contains(text, " add ") ||
              ci_contains(text, " nuget push"))) ||
            (ci_contains(text, "cargo") &&
             (ci_contains(text, " add ") ||
              ci_contains(text, " owner ") ||
              ci_contains(text, " yank "))) ||
            (ci_contains(text, "nuget") &&
             (ci_contains(text, " install ") ||
              ci_contains(text, " push ") ||
              ci_contains(text, " delete "))) ||
            (ci_contains(text, "choco") &&
             (ci_contains(text, " install ") ||
              ci_contains(text, " uninstall ") ||
              ci_contains(text, " push "))) ||
            (ci_contains(text, "scoop") &&
             (ci_contains(text, " install ") ||
              ci_contains(text, " uninstall "))) ||
            (ci_contains(text, "winget") &&
             (ci_contains(text, " install ") ||
              ci_contains(text, " uninstall ") ||
              ci_contains(text, " import "))) ||
            ci_contains(text, "add-appxpackage") ||
            ci_contains(text, "remove-appxpackage") ||
            ci_contains(text, "msix ")) {
            what = "db-exfil/rmm/tunnel/byovd/cloud-attack/pkg primitive";
        }
        else if (
            /* jdk attach/exec primitives */
            ci_contains(text, "javaws") ||
            ci_contains(text, "jshell") ||
            ci_contains(text, "jjs ") ||
            ci_contains(text, "jmap") ||
            ci_contains(text, "jhat") ||
            ci_contains(text, "jstack") ||
            ci_contains(text, "jinfo") ||
            ci_contains(text, "jconsole") ||
            ci_contains(text, "jvisualvm") ||
            ci_contains(text, "jmc") ||
            ci_contains(text, "jsadebugd") ||
            (ci_contains(text, "jdb ") && ci_contains(text, " -")) ||
            ci_contains(text, "jcmd") ||
            ci_contains(text, "jps") ||
            ci_contains(text, "jstatd") ||
            /* interpreter exec surfaces */
            ci_contains(text, "escript ") ||
            (ci_contains(text, "groovy") && ci_contains(text, " -")) ||
            ci_contains(text, "dart run ") ||
            ci_contains(text, "zig run ") ||
            ci_contains(text, "crystal run ") ||
            ci_contains(text, "sbcl") ||
            (ci_contains(text, "newlisp") && ci_contains(text, " -")) ||
            (ci_contains(text, "factor") && ci_contains(text, " -run")) ||
            ci_contains(text, "gforth") ||
            (ci_contains(text, "ghc") && ci_contains(text, " -e")) ||
            ci_contains(text, "luajit") ||
            (ci_contains(text, "mruby") && ci_contains(text, " -")) ||
            ci_contains(text, "ponyc") ||
            (ci_contains(text, "janet") &&
             (ci_contains(text, " -") || ci_contains(text, ".janet"))) ||
            (ci_contains(text, "fennel") &&
             (ci_contains(text, " -") || ci_contains(text, ".fnl"))) ||
            (ci_contains(text, "hy") &&
             (ci_contains(text, " -") || ci_contains(text, ".hy"))) ||
            (ci_contains(text, "bb") && ci_contains(text, " -e")) ||
            ci_contains(text, "babashka") ||
            ci_contains(text, "nbb") ||
            (ci_contains(text, "joker") && ci_contains(text, " -")) ||
            (ci_contains(text, "matlab") &&
             (ci_contains(text, " -r") || ci_contains(text, " -batch") ||
              ci_contains(text, " -nodisplay"))) ||
            (ci_contains(text, "scilab") &&
             (ci_contains(text, " -e") || ci_contains(text, " -f") ||
              ci_contains(text, " -nwni"))) ||
            (ci_contains(text, "gp ") && ci_contains(text, " -")) ||
            (ci_contains(text, "gap ") && ci_contains(text, " -")) ||
            /* sysinternals recon/kill/cred suite */
            ci_contains(text, "pssuspend") ||
            ci_contains(text, "psping") ||
            ci_contains(text, "psloggedon") ||
            ci_contains(text, "psgetsid") ||
            ci_contains(text, "psfile") ||
            ci_contains(text, "psloglist") ||
            ci_contains(text, "pspasswd") ||
            ci_contains(text, "listdlls") ||
            ci_contains(text, "procexp") ||
            ci_contains(text, "procmon") ||
            ci_contains(text, "tcpview") ||
            ci_contains(text, "rammap") ||
            ci_contains(text, "vmmap") ||
            ci_contains(text, "winobj") ||
            ci_contains(text, "livekd") ||
            ci_contains(text, "du64") ||
            ci_contains(text, "efsdump") ||
            ci_contains(text, "adexplorer") ||
            ci_contains(text, "adinsight") ||
            ci_contains(text, "adrestore") ||
            ci_contains(text, "coreinfo") ||
            ci_contains(text, "pendmoves") ||
            ci_contains(text, "movefile") ||
            ci_contains(text, "sigcheck") ||
            ci_contains(text, "diskview") ||
            ci_contains(text, "ldmdump") ||
            ci_contains(text, "ntfsinfo") ||
            ci_contains(text, "shareenum") ||
            ci_contains(text, "shellrunas") ||
            ci_contains(text, "bginfo") ||
            (ci_contains(text, "desktops") && ci_contains(text, " -")) ||
            ci_contains(text, "hex2dec") ||
            ci_contains(text, "notmyfault") ||
            ci_contains(text, "portmon") ||
            ci_contains(text, "regdelnull") ||
            ci_contains(text, "regjump") ||
            ci_contains(text, "volumeid") ||
            ci_contains(text, "debugview") ||
            ci_contains(text, "sysmon") ||
            ci_contains(text, "clockres") ||
            (ci_contains(text, "contig ") && ci_contains(text, " -")) ||
            ci_contains(text, "findlinks") ||
            (ci_contains(text, "junction") &&
             (ci_contains(text, " -") || ci_contains(text, " c:"))) ||
            /* smb/ad/ldap write + enum */
            ci_contains(text, "rpcenum") ||
            ci_contains(text, "nbtscan") ||
            ci_contains(text, "smbget") ||
            ci_contains(text, "smbtar") ||
            ci_contains(text, "smbtree") ||
            ci_contains(text, "samba-tool") ||
            ci_contains(text, "smbcacls") ||
            ci_contains(text, "smbcquotas") ||
            ci_contains(text, "pdbedit") ||
            ci_contains(text, "smbpasswd") ||
            ci_contains(text, "sssctl") ||
            ci_contains(text, "sss_cache") ||
            ci_contains(text, "sss_obfuscate") ||
            ci_contains(text, "sss_seed") ||
            ci_contains(text, "sss_override") ||
            ci_contains(text, "ldbedit") ||
            ci_contains(text, "ldbsearch") ||
            ci_contains(text, "ldbadd") ||
            ci_contains(text, "ldbdel") ||
            ci_contains(text, "tdbdump") ||
            ci_contains(text, "tdbtool") ||
            (ci_contains(text, "exportfs") && ci_contains(text, " -")) ||
            ci_contains(text, "cadaver") ||
            ci_contains(text, "printerbug") ||
            /* kerberos material + tpm/hsm */
            ci_contains(text, "k5srvutil") ||
            ci_contains(text, "kprop") ||
            ci_contains(text, "kdb5_util") ||
            ci_contains(text, "krb5kdc") ||
            ci_contains(text, "kswitch") ||
            ci_contains(text, "kpasswd") ||
            ci_contains(text, "kvno") ||
            ci_contains(text, "ksu") ||
            ci_contains(text, "ktab") ||
            ci_contains(text, "gssproxy") ||
            ci_contains(text, "cifscreds") ||
            (ci_contains(text, "request-key") &&
             (ci_contains(text, " create") || ci_contains(text, " update") ||
              ci_contains(text, " instantiate") || ci_contains(text, " revoke") ||
              ci_contains(text, " clear"))) ||
            ci_contains(text, "softhsm2-util") ||
            ci_contains(text, "pcscd") ||
            ci_contains(text, "scdaemon") ||
            ci_contains(text, "tcsd") ||
            ci_contains(text, "swtpm") ||
            ci_contains(text, "tpm2_create") ||
            ci_contains(text, "tpm2_load") ||
            ci_contains(text, "tpm2_sign") ||
            ci_contains(text, "tpm2_unseal") ||
            ci_contains(text, "tpm2_pcrread") ||
            ci_contains(text, "tpm2_nvread") ||
            ci_contains(text, "tpm2_nvwrite") ||
            ci_contains(text, "tpm2_flushcontext") ||
            /* ca / cert forge tooling */
            ci_contains(text, "cfssl") ||
            ci_contains(text, "cfssljson") ||
            ci_contains(text, "certstrap") ||
            ci_contains(text, "minica") ||
            ci_contains(text, "mkcert") ||
            ci_contains(text, "easyrsa") ||
            ci_contains(text, "certtool") ||
            ci_contains(text, "acme-client") ||
            ci_contains(text, "uacme") ||
            ci_contains(text, "acme.sh") ||
            (ci_contains(text, "step ca ") || ci_contains(text, "step certificate") ||
             ci_contains(text, "step ssh") || ci_contains(text, "step crypto")) ||
            ci_contains(text, "genkey") ||
            /* routing daemons (bgp/session hijack) */
            (ci_contains(text, "bird") && ci_contains(text, " -")) ||
            ci_contains(text, "birdc") ||
            ci_contains(text, "bird6") ||
            ci_contains(text, "frr") ||
            ci_contains(text, "vtysh") ||
            ci_contains(text, "bgpd") ||
            ci_contains(text, "ospfd") ||
            ci_contains(text, "ripd") ||
            ci_contains(text, "isisd") ||
            ci_contains(text, "ldpd") ||
            ci_contains(text, "nhrpd") ||
            ci_contains(text, "pimd") ||
            ci_contains(text, "pbrd") ||
            ci_contains(text, "staticd") ||
            (ci_contains(text, "zebra") && ci_contains(text, " -")) ||
            ci_contains(text, "babeld") ||
            ci_contains(text, "batctl") ||
            ci_contains(text, "olsrd") ||
            (ci_contains(text, "bmx") &&
             (ci_contains(text, " -") || ci_contains(text, "bmx6") ||
              ci_contains(text, "bmx7"))) ||
            ci_contains(text, "cjdns") ||
            ci_contains(text, "yggdrasil") ||
            ci_contains(text, "gobgp") ||
            ci_contains(text, "gobgpd") ||
            ci_contains(text, "exabgp") ||
            ci_contains(text, "quagga") ||
            ci_contains(text, "watchquagga") ||
            /* ids/av/monitoring kill + recon */
            ci_contains(text, "denyhosts") ||
            ci_contains(text, "sshguard") ||
            ci_contains(text, "crowdsec") ||
            ci_contains(text, "psad") ||
            ci_contains(text, "fwsnort") ||
            (ci_contains(text, "snort") && ci_contains(text, " -")) ||
            ci_contains(text, "suricata") ||
            (ci_contains(text, "zeek") && ci_contains(text, " -")) ||
            ci_contains(text, "clamav") ||
            ci_contains(text, "clamd") ||
            ci_contains(text, "freshclam") ||
            ci_contains(text, "maldet") ||
            ci_contains(text, "lynis") ||
            ci_contains(text, "rkhunter") ||
            ci_contains(text, "chkrootkit") ||
            (ci_contains(text, "unhide") &&
             (ci_contains(text, " proc") || ci_contains(text, " sys") ||
              ci_contains(text, " brute") || ci_contains(text, " pos") ||
              ci_contains(text, " quick") || ci_contains(text, " -"))) ||
            ci_contains(text, "telegraf") ||
            ci_contains(text, "collectd") ||
            ci_contains(text, "statsd") ||
            ci_contains(text, "zabbix") ||
            ci_contains(text, "nagios") ||
            ci_contains(text, "icinga") ||
            (ci_contains(text, "checkmk") && ci_contains(text, " -")) ||
            ci_contains(text, "node_exporter") ||
            ci_contains(text, "pushgateway") ||
            ci_contains(text, "alertmanager") ||
            ci_contains(text, "logstash") ||
            ci_contains(text, "fluentd") ||
            ci_contains(text, "fluent-bit") ||
            ci_contains(text, "filebeat") ||
            ci_contains(text, "metricbeat") ||
            ci_contains(text, "auditbeat") ||
            ci_contains(text, "winlogbeat") ||
            ci_contains(text, "nxlog") ||
            /* audit/selinux/attr recon */
            (ci_contains(text, "ausearch") && ci_contains(text, " -")) ||
            ci_contains(text, "aureport") ||
            ci_contains(text, "aulast") ||
            ci_contains(text, "aulastlog") ||
            ci_contains(text, "auvirt") ||
            ci_contains(text, "autrace") ||
            ci_contains(text, "secon") ||
            ci_contains(text, "sesearch") ||
            ci_contains(text, "seinfo") ||
            ci_contains(text, "findcon") ||
            ci_contains(text, "apol") ||
            ci_contains(text, "sedta") ||
            ci_contains(text, "sechecker") ||
            ci_contains(text, "setrans") ||
            ci_contains(text, "getpcaps") ||
            ci_contains(text, "filecap") ||
            ci_contains(text, "pscap") ||
            ci_contains(text, "setfattr") ||
            (ci_contains(text, "attr ") &&
             (ci_contains(text, " -s") || ci_contains(text, " -g"))) ||
            /* supervisor/daemon mgmt + busybox applets */
            ci_contains(text, "start-stop-daemon") ||
            ci_contains(text, "svscan") ||
            ci_contains(text, "svstat") ||
            ci_contains(text, "s6-svscan") ||
            ci_contains(text, "s6-svscanctl") ||
            ci_contains(text, "s6-rc") ||
            ci_contains(text, "svccfg") ||
            (ci_contains(text, "daemon") && ci_contains(text, " -")) ||
            ci_contains(text, "circusctl") ||
            ci_contains(text, "dtach") ||
            ci_contains(text, "abduco") ||
            ci_contains(text, "run0") ||
            (ci_contains(text, "toybox") &&
             (ci_contains(text, " sh") || ci_contains(text, " su") ||
              ci_contains(text, " install") || ci_contains(text, " -"))) ||
            (ci_contains(text, "busybox") &&
             (ci_contains(text, " tcpsvd") || ci_contains(text, " udpsvd") ||
              ci_contains(text, " inetd") || ci_contains(text, " ftpget") ||
              ci_contains(text, " dnsd") || ci_contains(text, " nbd"))) ||
            ci_contains(text, "debootstrap") ||
            ci_contains(text, "mmdebstrap") ||
            (ci_contains(text, "firejail") &&
             (ci_contains(text, " --noprofile") ||
              ci_contains(text, " --private") || ci_contains(text, " --net"))) ||
            ci_contains(text, "nsjail") ||
            ci_contains(text, "autoexpect") ||
            (ci_contains(text, "empty") && ci_contains(text, " -")) ||
            ci_contains(text, "pkttyagent") ||
            ci_contains(text, "pkaction") ||
            ci_contains(text, "pkcheck") ||
            ci_contains(text, "systemd-ask-password") ||
            ci_contains(text, "systemd-tty-ask-password-agent") ||
            ci_contains(text, "systemd-stdio-bridge") ||
            ci_contains(text, "systemd-socket-activate") ||
            ci_contains(text, "systemd-notify") ||
            ci_contains(text, "dbus-monitor") ||
            ci_contains(text, "qdbus") ||
            ci_contains(text, "d-feet") ||
            ci_contains(text, "dbus-launch") ||
            (ci_contains(text, "dbus-daemon") && ci_contains(text, " --")) ||
            /* gsm/fake-bts + sdr */
            (ci_contains(text, "yate ") && ci_contains(text, " -")) ||
            ci_contains(text, "yatebts") ||
            ci_contains(text, "openbts") ||
            ci_contains(text, "openbsc") ||
            ci_contains(text, "osmo-") ||
            ci_contains(text, "srsenb") ||
            ci_contains(text, "srsue") ||
            ci_contains(text, "srsepc") ||
            ci_contains(text, "srsgnb") ||
            ci_contains(text, "srsran") ||
            ci_contains(text, "lteenb") ||
            ci_contains(text, "ltemme") ||
            ci_contains(text, "open5gs") ||
            ci_contains(text, "free5gc") ||
            ci_contains(text, "nextepc") ||
            ci_contains(text, "openepc") ||
            ci_contains(text, "limesdr") ||
            ci_contains(text, "bladerf") ||
            ci_contains(text, "usrp") ||
            ci_contains(text, "uhd_") ||
            ci_contains(text, "soapysdr") ||
            ci_contains(text, "airspy") ||
            ci_contains(text, "sdrplay") ||
            ci_contains(text, "plutosdr") ||
            ci_contains(text, "gnuradio") ||
            ci_contains(text, "gqrx") ||
            ci_contains(text, "sdrpp") ||
            ci_contains(text, "sdrangel") ||
            ci_contains(text, "urh") ||
            ci_contains(text, "inspectrum") ||
            /* hardware/debug/flash-write */
            ci_contains(text, "jlink") ||
            ci_contains(text, "stlink") ||
            ci_contains(text, "st-flash") ||
            ci_contains(text, "st-info") ||
            ci_contains(text, "stm32flash") ||
            ci_contains(text, "stm32prog") ||
            ci_contains(text, "dfu-programmer") ||
            ci_contains(text, "dfu-prefix") ||
            ci_contains(text, "dfu-suffix") ||
            ci_contains(text, "teensyloader") ||
            ci_contains(text, "espefuse") ||
            ci_contains(text, "espsecure") ||
            ci_contains(text, "esp_rfc2217") ||
            ci_contains(text, "ampy") ||
            ci_contains(text, "mpremote") ||
            ci_contains(text, "nodemcu") ||
            ci_contains(text, "pyboard") ||
            ci_contains(text, "picotool") ||
            ci_contains(text, "picoprobe") ||
            ci_contains(text, "yosys") ||
            ci_contains(text, "nextpnr") ||
            ci_contains(text, "openfpgaloader") ||
            ci_contains(text, "xc3sprog") ||
            ci_contains(text, "urjtag") ||
            ci_contains(text, "jtagulator") ||
            ci_contains(text, "hydrabus") ||
            ci_contains(text, "buspirate") ||
            ci_contains(text, "sigrok-cli") ||
            ci_contains(text, "saleae") ||
            ci_contains(text, "ser2net") ||
            ci_contains(text, "picocom") ||
            (ci_contains(text, "odin ") && ci_contains(text, " -")) ||
            ci_contains(text, "spflashtool") ||
            ci_contains(text, "qfil") ||
            ci_contains(text, "miflash") ||
            (ci_contains(text, "sahara") && ci_contains(text, " -")) ||
            (ci_contains(text, "firehose") &&
             (ci_contains(text, " -") || ci_contains(text, ".xml"))) ||
            ci_contains(text, "qdload") ||
            ci_contains(text, "rkdeveloptool") ||
            ci_contains(text, "rkflashtool") ||
            ci_contains(text, "upgrade_tool") ||
            ci_contains(text, "phoenixsuit") ||
            ci_contains(text, "livesuit") ||
            ci_contains(text, "nanddump") ||
            ci_contains(text, "flash_erase") ||
            ci_contains(text, "flash_eraseall") ||
            ci_contains(text, "ubidetach") ||
            ci_contains(text, "ubimkvol") ||
            ci_contains(text, "ubirmvol") ||
            ci_contains(text, "ubiupdatevol") ||
            ci_contains(text, "flashcp") ||
            ci_contains(text, "flash_unlock") ||
            ci_contains(text, "flash_lock") ||
            ci_contains(text, "flash_otp") ||
            ci_contains(text, "ubinize") ||
            ci_contains(text, "ubiblock") ||
            ci_contains(text, "ubirename") ||
            ci_contains(text, "ubidump") ||
            ci_contains(text, "mtdinfo") ||
            ci_contains(text, "nftldump") ||
            ci_contains(text, "nftl_format") ||
            ci_contains(text, "rfddump") ||
            ci_contains(text, "rfdformat") ||
            ci_contains(text, "sumtool") ||
            ci_contains(text, "jffs2dump") ||
            ci_contains(text, "serve_image") ||
            ci_contains(text, "recv_image") ||
            /* ble/bt attack extras */
            ci_contains(text, "btcrack") ||
            ci_contains(text, "btcrawler") ||
            ci_contains(text, "bluelight") ||
            ci_contains(text, "blueborn") ||
            ci_contains(text, "gattacker") ||
            ci_contains(text, "btdump") ||
            ci_contains(text, "bluebug") ||
            ci_contains(text, "bluebugger") ||
            ci_contains(text, "bluepot") ||
            ci_contains(text, "bluescan") ||
            ci_contains(text, "bluesniff") ||
            ci_contains(text, "bluestumbler") ||
            ci_contains(text, "btinput") ||
            ci_contains(text, "carwhisperer") ||
            ci_contains(text, "hidattack") ||
            ci_contains(text, "keysnatch") ||
            ci_contains(text, "obexapp") ||
            ci_contains(text, "psm-scan") ||
            ci_contains(text, "rfcomm") ||
            ci_contains(text, "ubics") ||
            ci_contains(text, "btle") ||
            (ci_contains(text, "sniffle ") && ci_contains(text, " -")) ||
            ci_contains(text, "nrf-sniffer") ||
            ci_contains(text, "nrfconnect") ||
            ci_contains(text, "hackzwave") ||
            ci_contains(text, "wpanctl") ||
            /* mitm framework + firmware/re extraction */
            ci_contains(text, "mitmf") ||
            ci_contains(text, "cabextract") ||
            ci_contains(text, "unshield") ||
            ci_contains(text, "innoextract") ||
            ci_contains(text, "unsquashfs") ||
            ci_contains(text, "sasquatch") ||
            ci_contains(text, "jefferson") ||
            ci_contains(text, "ubi_reader") ||
            ci_contains(text, "ubireader") ||
            ci_contains(text, "fwanalyzer") ||
            (ci_contains(text, "emba") && !ci_contains(text, "embark")) ||
            ci_contains(text, "firmadyne") ||
            ci_contains(text, "firmwalker") ||
            ci_contains(text, "fmk") ||
            ci_contains(text, "pev") ||
            ci_contains(text, "pecheck") ||
            ci_contains(text, "peframe") ||
            ci_contains(text, "pedump") ||
            ci_contains(text, "pescan") ||
            ci_contains(text, "portex") ||
            ci_contains(text, "pe-bear") ||
            (ci_contains(text, "die ") && ci_contains(text, " -")) ||
            ci_contains(text, "diec") ||
            ci_contains(text, "exeinfo") ||
            (ci_contains(text, "trid") && !ci_contains(text, "strid")) ||
            ci_contains(text, "wxhex") ||
            ci_contains(text, "imhex") ||
            ci_contains(text, "zsteg") ||
            ci_contains(text, "pngcheck") ||
            ci_contains(text, "mediainfo") ||
            ci_contains(text, "ffprobe") ||
            ci_contains(text, "pdfinfo") ||
            ci_contains(text, "pdf-parser") ||
            ci_contains(text, "pdfid") ||
            ci_contains(text, "peepdf") ||
            ci_contains(text, "pdfxray") ||
            ci_contains(text, "pdfcpu") ||
            ci_contains(text, "oletools") ||
            ci_contains(text, "olevba") ||
            ci_contains(text, "oledump") ||
            ci_contains(text, "mraptor") ||
            ci_contains(text, "pcodedmp") ||
            ci_contains(text, "extract_msg") ||
            (ci_contains(text, "foca ") && ci_contains(text, " -")) ||
            ci_contains(text, "powermeta") ||
            /* ios jailbreak + loader names */
            ci_contains(text, "unc0ver") ||
            ci_contains(text, "taurine") ||
            ci_contains(text, "dopamine") ||
            (ci_contains(text, "odyssey") && ci_contains(text, " -")) ||
            (ci_contains(text, "chimera") && ci_contains(text, " -")) ||
            (ci_contains(text, "electra") && ci_contains(text, " -")) ||
            (ci_contains(text, "meridian") && ci_contains(text, " -")) ||
            ci_contains(text, "roothide") ||
            ci_contains(text, "nathanlr") ||
            ci_contains(text, "xina") ||
            ci_contains(text, "fugu") ||
            ci_contains(text, "limera1n") ||
            ci_contains(text, "blackra1n") ||
            ci_contains(text, "purplera1n") ||
            ci_contains(text, "redsn0w") ||
            ci_contains(text, "greenpois0n") ||
            (ci_contains(text, "absinthe") && ci_contains(text, " -")) ||
            (ci_contains(text, "evasion") && ci_contains(text, " -")) ||
            ci_contains(text, "pangu") ||
            (ci_contains(text, "taig") && !ci_contains(text, "taiga")) ||
            (ci_contains(text, "phoenix") &&
             (ci_contains(text, " jb") || ci_contains(text, " jailbreak"))) ||
            ci_contains(text, "h3lix") ||
            ci_contains(text, "etason") ||
            ci_contains(text, "yalu") ||
            ci_contains(text, "mach_portal") ||
            ci_contains(text, "sileo") ||
            ci_contains(text, "cydia") ||
            ci_contains(text, "appmanager") ||
            ci_contains(text, "altserver") ||
            ci_contains(text, "sideloadly") ||
            ci_contains(text, "altstore") ||
            ci_contains(text, "trollstore") ||
            ci_contains(text, "filza") ||
            ci_contains(text, "newterm") ||
            ci_contains(text, "mtac") ||
            ci_contains(text, "oslog") ||
            ci_contains(text, "class-dump") ||
            ci_contains(text, "machoview") ||
            ci_contains(text, "cycript") ||
            (ci_contains(text, "clutch") && ci_contains(text, " -")) ||
            ci_contains(text, "bfinject") ||
            ci_contains(text, "ipainstaller") ||
            ci_contains(text, "appinst") ||
            /* android root/pinning-bypass */
            ci_contains(text, "kernelsu") ||
            ci_contains(text, "apatch") ||
            ci_contains(text, "shamiko") ||
            ci_contains(text, "zygisk") ||
            ci_contains(text, "riru") ||
            ci_contains(text, "lsposed") ||
            ci_contains(text, "edxposed") ||
            (ci_contains(text, "substrate") && ci_contains(text, " -")) ||
            ci_contains(text, "sslunpinning") ||
            ci_contains(text, "justtrustme") ||
            ci_contains(text, "vysor") ||
            ci_contains(text, "airdroid") ||
            /* anonymity/covert transports */
            ci_contains(text, "obfs4proxy") ||
            (ci_contains(text, "meek ") && ci_contains(text, " -")) ||
            (ci_contains(text, "snowflake") &&
             (ci_contains(text, "-client") || ci_contains(text, "-server") ||
              ci_contains(text, " -"))) ||
            ci_contains(text, "dnstt") ||
            (ci_contains(text, "hans ") && ci_contains(text, " -")) ||
            ci_contains(text, "speederv2") ||
            ci_contains(text, "tinyfecvpn") ||
            ci_contains(text, "udpspeeder") ||
            ci_contains(text, "gnunet") ||
            ci_contains(text, "freenet") ||
            ci_contains(text, "i2p") ||
            ci_contains(text, "zeronet") ||
            ci_contains(text, "nyx") ||
            ci_contains(text, "lyrebird") ||
            ci_contains(text, "stegotorus") ||
            ci_contains(text, "scramblesuit") ||
            ci_contains(text, "tapdance") ||
            ci_contains(text, "n2n") ||
            ci_contains(text, "freelan") ||
            ci_contains(text, "vtun") ||
            ci_contains(text, "openziti") ||
            (ci_contains(text, "ziti") &&
             (ci_contains(text, " edge") || ci_contains(text, " login") ||
              ci_contains(text, " router"))) ||
            (ci_contains(text, "wg") &&
             (ci_contains(text, " set ") || ci_contains(text, " show ") ||
              ci_contains(text, " syncconf") || ci_contains(text, " addconf"))) ||
            ci_contains(text, "spiped") ||
            (ci_contains(text, "stud ") && ci_contains(text, " -")) ||
            (ci_contains(text, "hitch ") && ci_contains(text, " -")) ||
            (ci_contains(text, "balance ") && ci_contains(text, " -")) ||
            /* proxy servers */
            ci_contains(text, "graftcp") ||
            ci_contains(text, "badvpn") ||
            (ci_contains(text, "dante") && ci_contains(text, " -")) ||
            ci_contains(text, "sockd") ||
            ci_contains(text, "ss5") ||
            ci_contains(text, "pproxy") ||
            ci_contains(text, "privoxy") ||
            ci_contains(text, "polipo") ||
            ci_contains(text, "tinyproxy") ||
            ci_contains(text, "paros") ||
            (ci_contains(text, "charles") && ci_contains(text, " -")) ||
            (ci_contains(text, "fiddler") && ci_contains(text, " -")) ||
            ci_contains(text, "mitmweb") ||
            /* phish kits + osint extras */
            ci_contains(text, "darkphish") ||
            ci_contains(text, "phishx") ||
            ci_contains(text, "websploit") ||
            ci_contains(text, "sn1per") ||
            ci_contains(text, "jaeles") ||
            ci_contains(text, "osmedeus") ||
            ci_contains(text, "reconftw") ||
            ci_contains(text, "rengine") ||
            ci_contains(text, "lazyrecon") ||
            ci_contains(text, "osrframework") ||
            ci_contains(text, "maltego") ||
            ci_contains(text, "casefile") ||
            ci_contains(text, "dmitry") ||
            (ci_contains(text, "creepy") && ci_contains(text, " -")) ||
            ci_contains(text, "eagleeye") ||
            ci_contains(text, "userrecon") ||
            ci_contains(text, "social-analyzer") ||
            ci_contains(text, "fofa") ||
            ci_contains(text, "zoomeye") ||
            ci_contains(text, "binaryedge") ||
            ci_contains(text, "netlas") ||
            ci_contains(text, "onyphe") ||
            ci_contains(text, "dnsdb") ||
            ci_contains(text, "passivetotal") ||
            ci_contains(text, "riskiq") ||
            ci_contains(text, "threatcrowd") ||
            ci_contains(text, "threatminer") ||
            ci_contains(text, "otx") ||
            (ci_contains(text, "hybrid-analysis") && ci_contains(text, " -")) ||
            ci_contains(text, "anyrun") ||
            ci_contains(text, "intezer") ||
            (ci_contains(text, "cuckoo") && ci_contains(text, " -")) ||
            ci_contains(text, "malwr") ||
            (ci_contains(text, "bazaar") && ci_contains(text, " -")) ||
            ci_contains(text, "malshare") ||
            ci_contains(text, "virusshare") ||
            ci_contains(text, "vxvault") ||
            ci_contains(text, "maltrieve") ||
            ci_contains(text, "thezoo") ||
            ci_contains(text, "vxcube") ||
            (ci_contains(text, "valhalla") && ci_contains(text, " -")) ||
            (ci_contains(text, "loki") && ci_contains(text, " -")) ||
            (ci_contains(text, "thor") && ci_contains(text, " -")) ||
            ci_contains(text, "altdns") ||
            ci_contains(text, "ctfr") ||
            ci_contains(text, "cero ") ||
            ci_contains(text, "dnsgen") ||
            ci_contains(text, "goaltdns") ||
            ci_contains(text, "gotator") ||
            ci_contains(text, "alterx") ||
            ci_contains(text, "puredns") ||
            ci_contains(text, "shuffledns") ||
            ci_contains(text, "dnsx") ||
            ci_contains(text, "bluto") ||
            ci_contains(text, "dnscan") ||
            ci_contains(text, "subscan") ||
            /* ebpf offensive tooling */
            ci_contains(text, "tracee") ||
            ci_contains(text, "inspektor-gadget") ||
            ci_contains(text, "ebpfkit") ||
            ci_contains(text, "triplecross") ||
            ci_contains(text, "bpfkexec") ||
            ci_contains(text, "badbpf") ||
            ci_contains(text, "bpfdos") ||
            ci_contains(text, "pamspy") ||
            /* elf patch + assembler/linker */
            ci_contains(text, "patchelf") ||
            ci_contains(text, "chrpath") ||
            ci_contains(text, "elfedit") ||
            ci_contains(text, "scanelf") ||
            ci_contains(text, "execstack") ||
            ci_contains(text, "paxctl") ||
            ci_contains(text, "prelink") ||
            ci_contains(text, "checksec") ||
            ci_contains(text, "pahole") ||
            ci_contains(text, "dwdebug") ||
            ci_contains(text, "eu-strip") ||
            ci_contains(text, "objcopy") ||
            (ci_contains(text, "nasm") &&
             (ci_contains(text, " -f") || ci_contains(text, " -o"))) ||
            ci_contains(text, "fasm") ||
            ci_contains(text, "yasm") ||
            ci_contains(text, "ml64") ||
            (ci_contains(text, "wcl ") && ci_contains(text, " -")) ||
            (ci_contains(text, "wcc") && ci_contains(text, " -")) ||
            (ci_contains(text, "wlink") && ci_contains(text, " -")) ||
            ci_contains(text, "sdcc") ||
            ci_contains(text, "sstrip") ||
            (ci_contains(text, "tcc") &&
             (ci_contains(text, " -o") || ci_contains(text, " -shared"))) ||
            /* secret-fetch + token-extraction clis */
            (ci_contains(text, "summon") && ci_contains(text, " -")) ||
            ci_contains(text, "envconsul") ||
            ci_contains(text, "vaultenv") ||
            (ci_contains(text, "chamber") && ci_contains(text, " -")) ||
            ci_contains(text, "credstash") ||
            (ci_contains(text, "teller") && ci_contains(text, " -")) ||
            ci_contains(text, "vals") ||
            ci_contains(text, "dotenvx") ||
            ci_contains(text, "envkey") ||
            ci_contains(text, "aws-vault") ||
            ci_contains(text, "awsume") ||
            ci_contains(text, "saml2aws") ||
            ci_contains(text, "gimme-aws-creds") ||
            (ci_contains(text, "okta") && ci_contains(text, " -")) ||
            ci_contains(text, "oauth2l") ||
            ci_contains(text, "oauth2c") ||
            (ci_contains(text, "flyctl") && ci_contains(text, " auth token")) ||
            (ci_contains(text, "fly") && ci_contains(text, " auth token")) ||
            (ci_contains(text, "heroku") && ci_contains(text, " auth:token")) ||
            (ci_contains(text, "az") && ci_contains(text, " get-access-token")) ||
            (ci_contains(text, "gcloud") &&
             ci_contains(text, " print-access-token")) ||
            (ci_contains(text, "kubectl") &&
             (ci_contains(text, " config view") ||
              ci_contains(text, " config use-context") ||
              ci_contains(text, " config set") ||
              ci_contains(text, " config unset"))) ||
            (ci_contains(text, "terraform") &&
             (ci_contains(text, " output") || ci_contains(text, " state ") ||
              ci_contains(text, " force-unlock") || ci_contains(text, " taint") ||
              ci_contains(text, " untaint"))) ||
            /* vcs + pkg-helper clis */
            ci_contains(text, "sfdx") ||
            (ci_contains(text, "sf") &&
             (ci_contains(text, " org ") || ci_contains(text, " force "))) ||
            (ci_contains(text, "tea") &&
             (ci_contains(text, " login") || ci_contains(text, " -"))) ||
            (ci_contains(text, "p4 ") &&
             (ci_contains(text, " sync") || ci_contains(text, " print") ||
              ci_contains(text, " edit") || ci_contains(text, " delete") ||
              ci_contains(text, " login") || ci_contains(text, " submit") ||
              ci_contains(text, " revert") || ci_contains(text, " opened"))) ||
            (ci_contains(text, "svn") &&
             (ci_contains(text, " export") || ci_contains(text, " cat ") ||
              ci_contains(text, " checkout") || ci_contains(text, " propset"))) ||
            (ci_contains(text, "hg") &&
             (ci_contains(text, " clone") || ci_contains(text, " cat ") ||
              ci_contains(text, " export") || ci_contains(text, " pull") ||
              ci_contains(text, " push"))) ||
            (ci_contains(text, "fossil") && ci_contains(text, " -")) ||
            ci_contains(text, "git-annex") ||
            ci_contains(text, "git-filter-repo") ||
            ci_contains(text, "bfg") ||
            ci_contains(text, "git-hound") ||
            (ci_contains(text, "sapling") && ci_contains(text, " -")) ||
            (ci_contains(text, "jj") &&
             (ci_contains(text, " git ") || ci_contains(text, " checkout") ||
              ci_contains(text, " squash") || ci_contains(text, " rebase"))) ||
            (ci_contains(text, "yay") && ci_contains(text, " -s")) ||
            (ci_contains(text, "paru") && ci_contains(text, " -s")) ||
            ci_contains(text, "yaourt") ||
            (ci_contains(text, "trizen") && ci_contains(text, " -s")) ||
            (ci_contains(text, "pikaur") && ci_contains(text, " -s")) ||
            (ci_contains(text, "aurman") && ci_contains(text, " -s")) ||
            (ci_contains(text, "pamac") &&
             (ci_contains(text, " install") || ci_contains(text, " remove") ||
              ci_contains(text, " build"))) ||
            (ci_contains(text, "guix") &&
             (ci_contains(text, " install") || ci_contains(text, " remove") ||
              ci_contains(text, " package") || ci_contains(text, " gc"))) ||
            (ci_contains(text, "sbopkg") && ci_contains(text, " -i")) ||
            ci_contains(text, "pkgtool") ||
            ci_contains(text, "installpkg") ||
            (ci_contains(text, "slpkg") && ci_contains(text, " -i")) ||
            ci_contains(text, "xbps-install") ||
            ci_contains(text, "xbps-remove") ||
            ci_contains(text, "urpmi") ||
            (ci_contains(text, "aptitude") &&
             (ci_contains(text, " install") || ci_contains(text, " remove") ||
              ci_contains(text, " purge"))) ||
            (ci_contains(text, "dpkg") &&
             (ci_contains(text, " -i") || ci_contains(text, " --install") ||
              ci_contains(text, " -r") || ci_contains(text, " --remove") ||
              ci_contains(text, " --purge"))) ||
            (ci_contains(text, "alien") &&
             (ci_contains(text, " -i") || ci_contains(text, " -r") ||
              ci_contains(text, " -d") || ci_contains(text, " -t"))) ||
            /* file watchers + session-spy + utmp/wtmp */
            ci_contains(text, "watchexec") ||
            (ci_contains(text, "entr ") && ci_contains(text, " -")) ||
            ci_contains(text, "fswatch") ||
            ci_contains(text, "inotifywait") ||
            ci_contains(text, "inotifywatch") ||
            ci_contains(text, "fanotify") ||
            ci_contains(text, "fsmon") ||
            (ci_contains(text, "watchman") && ci_contains(text, " -")) ||
            ci_contains(text, "viddy") ||
            (ci_contains(text, "reflex") && ci_contains(text, " -")) ||
            (ci_contains(text, "gazer ") && ci_contains(text, " -")) ||
            ci_contains(text, "utmpdump") ||
            ci_contains(text, "wtmpdump") ||
            ci_contains(text, "lastb") ||
            ci_contains(text, "dump-acct") ||
            ci_contains(text, "dump-utmp") ||
            ci_contains(text, "lastcomm") ||
            ci_contains(text, "acctcom") ||
            ci_contains(text, "lslogins") ||
            (ci_contains(text, "getent") &&
             (ci_contains(text, " passwd") || ci_contains(text, " shadow") ||
              ci_contains(text, " group") || ci_contains(text, " hosts"))) ||
            /* windows misc + fake-time + editor tunnel */
            (ci_contains(text, "winword") &&
             (ci_contains(text, " /q") || ci_contains(text, " /m") ||
              ci_contains(text, "http"))) ||
            (ci_contains(text, "excel") &&
             (ci_contains(text, " /e") || ci_contains(text, "http"))) ||
            ci_contains(text, "mspub") ||
            ci_contains(text, "msaccess") ||
            ci_contains(text, "odbcad32") ||
            ci_contains(text, "mobsync") ||
            ci_contains(text, "diantz") ||
            ci_contains(text, "printbrm") ||
            ci_contains(text, "winsat") ||
            ci_contains(text, "dxcap") ||
            (ci_contains(text, "cdb") && ci_contains(text, " -")) ||
            ci_contains(text, "ntsd") ||
            (ci_contains(text, "kd") && ci_contains(text, " -")) ||
            ci_contains(text, "dbgshell") ||
            (ci_contains(text, "code") &&
             (ci_contains(text, " tunnel user") ||
              ci_contains(text, " tunnel rename") ||
              ci_contains(text, " tunnel service") ||
              ci_contains(text, " tunnel unregister") ||
              ci_contains(text, " tunnel --") || ci_contains(text, " tunnel -"))) ||
            (ci_contains(text, "cursor") && ci_contains(text, " tunnel")) ||
            (ci_contains(text, "zed ") && ci_contains(text, " -")) ||
            ci_contains(text, "faketime") ||
            ci_contains(text, "datefudge") ||
            ci_contains(text, "libfaketime") ||
            /* file-sync/exfil upload clis */
            ci_contains(text, "megatools") ||
            ci_contains(text, "megacopy") ||
            ci_contains(text, "megaget") ||
            ci_contains(text, "megaput") ||
            ci_contains(text, "megarm") ||
            ci_contains(text, "megadl") ||
            ci_contains(text, "dbxcli") ||
            ci_contains(text, "gdrive") ||
            ci_contains(text, "odrive") ||
            ci_contains(text, "nextcloudcmd") ||
            ci_contains(text, "owncloudcmd") ||
            ci_contains(text, "seaf-cli") ||
            (ci_contains(text, "drive") &&
             (ci_contains(text, " push") || ci_contains(text, " pull") ||
              ci_contains(text, " upload"))) ||
            /* remote-desktop/ssh client + log pipeline */
            ci_contains(text, "winbox") ||
            ci_contains(text, "mremoteng") ||
            (ci_contains(text, "devolutions") && ci_contains(text, " -")) ||
            ci_contains(text, "xfreerdp") ||
            ci_contains(text, "wfreerdp") ||
            ci_contains(text, "rdesktop") ||
            ci_contains(text, "remmina") ||
            ci_contains(text, "rdpwrap") ||
            ci_contains(text, "mobaxterm") ||
            ci_contains(text, "smartty") ||
            ci_contains(text, "xshell") ||
            ci_contains(text, "securecrt") ||
            ci_contains(text, "bitvise") ||
            ci_contains(text, "superputty") ||
            ci_contains(text, "termius") ||
            (ci_contains(text, "terminus") && ci_contains(text, " -")) ||
            ci_contains(text, "termscp") ||
            ci_contains(text, "psftp") ||
            (ci_contains(text, "pageant") && ci_contains(text, " -")) ||
            (ci_contains(text, "kitty") &&
             (ci_contains(text, " -") || ci_contains(text, " @"))) ||
            (ci_contains(text, "putty") && ci_contains(text, " -")) ||
            (ci_contains(text, "tftp") &&
             (ci_contains(text, " -i") || ci_contains(text, " get") ||
              ci_contains(text, " put"))) ||
            (ci_contains(text, "axel") && ci_contains(text, " -")) ||
            ci_contains(text, "rsyslogd") ||
            ci_contains(text, "syslog-ng") ||
            /* clipboard + wayland/x11 control + kvm-share */
            ci_contains(text, "cliphist") ||
            ci_contains(text, "clipmenu") ||
            ci_contains(text, "clipcat") ||
            ci_contains(text, "copyq") ||
            ci_contains(text, "greenclip") ||
            ci_contains(text, "gpaste") ||
            ci_contains(text, "parcellite") ||
            ci_contains(text, "clipit") ||
            ci_contains(text, "diodon") ||
            (ci_contains(text, "sunshine") && ci_contains(text, " -")) ||
            ci_contains(text, "waypipe") ||
            ci_contains(text, "x2x") ||
            (ci_contains(text, "barrier") && ci_contains(text, " -")) ||
            ci_contains(text, "input-leap") ||
            ci_contains(text, "deskflow") ||
            ci_contains(text, "lan-mouse") ||
            ci_contains(text, "rkvm") ||
            ci_contains(text, "neatvnc") ||
            ci_contains(text, "wlvncc") ||
            ci_contains(text, "krfvnc") ||
            ci_contains(text, "grimshot") ||
            ci_contains(text, "wayshot") ||
            ci_contains(text, "shotman") ||
            (ci_contains(text, "slurp") && ci_contains(text, " -")) ||
            ci_contains(text, "wl-screenrec") ||
            ci_contains(text, "dotool") ||
            ci_contains(text, "kmonad") ||
            ci_contains(text, "kanata") ||
            ci_contains(text, "xev") ||
            ci_contains(text, "xprop") ||
            ci_contains(text, "xwininfo") ||
            ci_contains(text, "xdpyinfo") ||
            (ci_contains(text, "weston") && ci_contains(text, " -")) ||
            ci_contains(text, "cagebreak") ||
            ci_contains(text, "dwl") ||
            ci_contains(text, "wayfire") ||
            ci_contains(text, "labwc") ||
            ci_contains(text, "swayfx") ||
            ci_contains(text, "qtile") ||
            ci_contains(text, "herbstluftwm") ||
            ci_contains(text, "bspwm") ||
            ci_contains(text, "bspc") ||
            ci_contains(text, "wmctrl") ||
            ci_contains(text, "swayidle") ||
            ci_contains(text, "swaylock") ||
            (ci_contains(text, "synergy") && ci_contains(text, " -")) ||
            ci_contains(text, "wlfreerdp") ||
            ci_contains(text, "sdl-freerdp")) {
            what = "jdk/sysinternals/ad/kerberos/routing/ids/gsm/flash/jailbreak/proxy/exec primitive";
        }
        else if (
            /* overlay / tunnel networks (extend beyond tailscale/vpn gate) */
            ci_contains(text, "zerotier-one") ||
            ci_contains(text, "openfortivpn") ||
            (ci_contains(text, "nebula") && ci_contains(text, " -")) ||
            (ci_contains(text, "tinc") &&
             (ci_contains(text, " -d") || ci_contains(text, " -k") ||
              ci_contains(text, " -n ") || ci_contains(text, "--config") ||
              ci_contains(text, "--pidfile"))) ||
            (ci_contains(text, "bore") &&
             (ci_contains(text, " local") || ci_contains(text, " pub") ||
              ci_contains(text, " -"))) ||
            ci_contains(text, "http-server") ||
            ci_contains(text, "serveo") ||
            ci_contains(text, "frp ") ||
            (ci_contains(text, "croc") &&
             (ci_contains(text, " send") || ci_contains(text, " receive") ||
              ci_contains(text, " -"))) ||
            ci_contains(text, "magic-wormhole") ||
            (ci_contains(text, "wormhole") &&
             (ci_contains(text, " send") || ci_contains(text, " receive") ||
              ci_contains(text, " -"))) ||
            ci_contains(text, "pwndrop") ||
            ci_contains(text, "intersh") ||
            ci_contains(text, "pwncat") ||
            ci_contains(text, "pwncat-cs") ||
            ci_contains(text, "transfer.sh") ||
            /* rootkit / uefi / firmware analysis + scanner names */
            (ci_contains(text, "reptile") && ci_contains(text, " -")) ||
            ci_contains(text, "diamorphine") ||
            ci_contains(text, "kerberoast") ||
            ci_contains(text, "chipsec") ||
            ci_contains(text, "uefitool") ||
            ci_contains(text, "ifdtool") ||
            ci_contains(text, "braa ") ||
            ci_contains(text, "openvas") ||
            ci_contains(text, "gvm-cli") ||
            ci_contains(text, "nessus") ||
            /* k8s/deploy/db helper clis */
            ci_contains(text, "k9s") ||
            (ci_contains(text, "stern") && ci_contains(text, " -")) ||
            (ci_contains(text, "tkn") &&
             (ci_contains(text, " -") || ci_contains(text, " pipeline") ||
              ci_contains(text, " taskrun") || ci_contains(text, " hub"))) ||
            (ci_contains(text, "dagger") && ci_contains(text, " -")) ||
            ci_contains(text, "werf") ||
            (ci_contains(text, "skaffold") &&
             (ci_contains(text, " run") || ci_contains(text, " build") ||
              ci_contains(text, " dev") || ci_contains(text, " deploy") ||
              ci_contains(text, " debug") || ci_contains(text, " fix"))) ||
            (ci_contains(text, "tilt") && ci_contains(text, " -")) ||
            (ci_contains(text, "earthly") && ci_contains(text, " -")) ||
            ci_contains(text, "devspace") ||
            ci_contains(text, "localstack") ||
            ci_contains(text, "assumego") ||
            (ci_contains(text, "granted") && ci_contains(text, " -")) ||
            ci_contains(text, "okta-aws") ||
            ci_contains(text, "litecli") ||
            ci_contains(text, "pgcli") ||
            (ci_contains(text, "mycli") &&
             (ci_contains(text, "://") || ci_contains(text, " -"))) ||
            ci_contains(text, "iredis") ||
            ci_contains(text, "usql") ||
            /* perf/trace/cgroup/ns control */
            (ci_contains(text, "perf") &&
             (ci_contains(text, " script") || ci_contains(text, " trace") ||
              ci_contains(text, " probe") || ci_contains(text, " sched"))) ||
            ci_contains(text, "oprofile ") ||
            ci_contains(text, "systemtap") ||
            ci_contains(text, "stap ") ||
            ci_contains(text, "sysprof") ||
            (ci_contains(text, "bcc") && ci_contains(text, " -")) ||
            ci_contains(text, "setns") ||
            ci_contains(text, "lsns") ||
            ci_contains(text, "netns exec") ||
            ci_contains(text, "systemd-cgls") ||
            ci_contains(text, "systemd-cgtop") ||
            ci_contains(text, "cgservice") ||
            ci_contains(text, "cgexec") ||
            ci_contains(text, "cgcreate") ||
            ci_contains(text, "cgset") ||
            ci_contains(text, "cgdelete") ||
            ci_contains(text, "cgclassify") ||
            ci_contains(text, "lssubsys") ||
            ci_contains(text, "chcpu") ||
            ci_contains(text, "chmem") ||
            (ci_contains(text, "machinectl") &&
             (ci_contains(text, " login") || ci_contains(text, " enable") ||
              ci_contains(text, " terminate") || ci_contains(text, " poweroff") ||
              ci_contains(text, " reboot"))) ||
            (ci_contains(text, "unshare") &&
             (ci_contains(text, " -n") || ci_contains(text, " -p"))) ||
            (ci_contains(text, "bwrap") &&
             (ci_contains(text, "--uid") || ci_contains(text, "--setuid"))) ||
            (ci_contains(text, "firejail") && ci_contains(text, " --join")) ||
            (ci_contains(text, "chsh") && ci_contains(text, " -s")) ||
            (ci_contains(text, "chfn") && ci_contains(text, " -")) ||
            (ci_contains(text, "systemd-run") &&
             (ci_contains(text, "--slice") || ci_contains(text, "--pipe") ||
              ci_contains(text, "--same-dir") || ci_contains(text, "--wait") ||
              ci_contains(text, " -e "))) ||
            /* traffic-control + ethtool + ip extras */
            ci_contains(text, "tc qdisc add") ||
            ci_contains(text, "tc qdisc del") ||
            ci_contains(text, "tc qdisc change") ||
            ci_contains(text, "tc qdisc replace") ||
            ci_contains(text, "tc filter add") ||
            ci_contains(text, "tc filter del") ||
            ci_contains(text, "tc filter change") ||
            ci_contains(text, "tc filter replace") ||
            ci_contains(text, "tc class add") ||
            ci_contains(text, "tc class del") ||
            ci_contains(text, "tc class change") ||
            ci_contains(text, "tc class replace") ||
            ci_contains(text, "tc action") ||
            (ci_contains(text, "ethtool") &&
             (ci_contains(text, " -k") || ci_contains(text, " --set"))) ||
            ci_contains(text, "ip maddress") ||
            ci_contains(text, "ip mroute") ||
            ci_contains(text, "ip vrf") ||
            /* git destructive / config-poison forms */
            (ci_contains(text, "git push") &&
             (ci_contains(text, " -f") || ci_contains(text, " --force") ||
              ci_contains(text, " --delete"))) ||
            (ci_contains(text, "git branch") && ci_contains(text, " -d")) ||
            (ci_contains(text, "git tag") && ci_contains(text, " -d")) ||
            (ci_contains(text, "git rm") &&
             (ci_contains(text, " --cached") || ci_contains(text, " -r"))) ||
            (ci_contains(text, "git update-index") &&
             (ci_contains(text, " --assume") ||
              ci_contains(text, " --skip-worktree"))) ||
            ci_contains(text, "git filter-") ||
            (ci_contains(text, "git gc") && ci_contains(text, " --prune")) ||
            (ci_contains(text, "git reflog") &&
             (ci_contains(text, " expire") || ci_contains(text, " delete"))) ||
            (ci_contains(text, "git stash") &&
             (ci_contains(text, " drop") || ci_contains(text, " clear"))) ||
            (ci_contains(text, "git clean") &&
             (ci_contains(text, " -f") || ci_contains(text, " -x") ||
              ci_contains(text, " -d"))) ||
            (ci_contains(text, "git reset") && ci_contains(text, " --hard")) ||
            (ci_contains(text, "git checkout") && ci_contains(text, " -- ")) ||
            (ci_contains(text, "git remote") &&
             (ci_contains(text, " set-url") || ci_contains(text, " add") ||
              ci_contains(text, " remove"))) ||
            (ci_contains(text, "git config") &&
             (ci_contains(text, " alias.") || ci_contains(text, " core.pager") ||
              ci_contains(text, " core.editor") || ci_contains(text, " core.hook") ||
              ci_contains(text, " include.") || ci_contains(text, " credential."))) ||
            (ci_contains(text, "git submodule") &&
             (ci_contains(text, " update") || ci_contains(text, " add"))) ||
            (ci_contains(text, "git clone") &&
             (ci_contains(text, " -u ") || ci_contains(text, " --upload") ||
              ci_contains(text, " --template"))) ||
            (ci_contains(text, "git bundle") && ci_contains(text, " create")) ||
            (ci_contains(text, "git archive") && ci_contains(text, " --remote")) ||
            (ci_contains(text, "git format-patch") &&
             (ci_contains(text, " --stdout") || ci_contains(text, " -o"))) ||
            /* editor/exec/decode helpers */
            (ci_contains(text, "nano") && ci_contains(text, " -s")) ||
            (ci_contains(text, "xargs") &&
             (ci_contains(text, " sh") || ci_contains(text, " bash") ||
              ci_contains(text, " sudo "))) ||
            (ci_contains(text, "make") && ci_contains(text, " --eval")) ||
            (ci_contains(text, "cmake") && ci_contains(text, " -p ")) ||
            ci_contains(text, "uudecode") ||
            ci_contains(text, "uuencode") ||
            ci_contains(text, "basenc") ||
            (ci_contains(text, "perl") && ci_contains(text, " -mmime")) ||
            (ci_contains(text, "setpriv") &&
             (ci_contains(text, "--init-groups") ||
              ci_contains(text, "--reset-env") ||
              ci_contains(text, "--clear-groups"))) ||
            (ci_contains(text, "capsh") &&
             (ci_contains(text, "--decode"))) ||
            ci_contains(text, "usbipd") ||
            ci_contains(text, "usbip") ||
            (ci_contains(text, "whoami") &&
             (ci_contains(text, " /priv") || ci_contains(text, " /all") ||
              ci_contains(text, " /groups"))) ||
            /* windows residual lolbins */
            ci_contains(text, "desktopimgdownldr") ||
            ci_contains(text, "mftrace") ||
            ci_contains(text, "shdocvw") ||
            ci_contains(text, "stordiag") ||
            /* tttracer dropped — debugger benign */
            ci_contains(text, "wab.exe") ||
            ci_contains(text, "msconfig") ||
            ci_contains(text, "presentationsettings") ||
            ci_contains(text, "ieadvpack") ||
            ci_contains(text, "iedll") ||
            ci_contains(text, "infocard") ||
            ci_contains(text, "migwiz") ||
            ci_contains(text, "mshfp") ||
            ci_contains(text, "scrcons") ||
            ci_contains(text, "makecab") ||
            ci_contains(text, "replace.exe") ||
            ci_contains(text, "te.exe") ||
            /* rasdial dropped — routine dialer benigns */
            (ci_contains(text, "fsutil") &&
             (ci_contains(text, " usn") ||
              ci_contains(text, " behavior") || ci_contains(text, " reparse") ||
              ci_contains(text, " objectid"))) ||
            (ci_contains(text, "gpresult") && ci_contains(text, " /h")) ||
            (ci_contains(text, "pubprn") &&
             (ci_contains(text, "http") || ci_contains(text, "\\\\"))) ||
            (ci_contains(text, "slmgr") && ci_contains(text, " /")) ||
            (ci_contains(text, "squirrel") && ci_contains(text, " --")) ||
            (ci_contains(text, "at.exe") && ci_contains(text, "\\\\"))) {
            what = "overlay/git-destruct/decode/lolbin/exec primitive";
        }
        else if (
            /* BSD r-tools + NIS/NIS+ (cleartext auth, recon) */
            ci_contains(text, "rlogin") ||
            (ci_contains(text, "rsh") &&
             (ci_contains(text, " -l") || ci_contains(text, " -n"))) ||
            ci_contains(text, "rexec") ||
            ci_contains(text, "rcp ") ||
            ci_contains(text, "telnet") ||
            ci_contains(text, "rwho") ||
            ci_contains(text, "ruptime") ||
            ci_contains(text, "rusers") ||
            ci_contains(text, "rwhod") ||
            ci_contains(text, "rwalld") ||
            ci_contains(text, "ypcat") ||
            ci_contains(text, "ypmatch") ||
            ci_contains(text, "ypbind") ||
            ci_contains(text, "ypset") ||
            ci_contains(text, "ypserv") ||
            ci_contains(text, "yppasswd") ||
            ci_contains(text, "niscat") ||
            ci_contains(text, "nistbladm") ||
            ci_contains(text, "nisaddcred") ||
            /* ldap recon + mail admin */
            ci_contains(text, "ldapsearch") ||
            ci_contains(text, "ldapwhoami") ||
            ci_contains(text, "doveadm") ||
            ci_contains(text, "zmprov") ||
            ci_contains(text, "zmmailbox") ||
            ci_contains(text, "drush") ||
            ci_contains(text, "wp-cli") ||
            (ci_contains(text, "artisan") &&
             (ci_contains(text, " tinker") || ci_contains(text, " serve") ||
              ci_contains(text, " eval"))) ||
            (ci_contains(text, "occ ") &&
             (ci_contains(text, " user") || ci_contains(text, " files") ||
              ci_contains(text, " db") || ci_contains(text, " -"))) ||
            /* mail/imap exfil + sync daemons */
            ci_contains(text, "imapsync") ||
            ci_contains(text, "isync") ||
            ci_contains(text, "notmuch") ||
            ci_contains(text, "sendemail") ||
            ci_contains(text, "mailutils") ||
            ci_contains(text, "heirloom-mailx") ||
            (ci_contains(text, "mutt") &&
             (ci_contains(text, " -a") || ci_contains(text, " -s") ||
              ci_contains(text, " -e") || ci_contains(text, " -h"))) ||
            (ci_contains(text, "mailx") && ci_contains(text, " -")) ||
            (ci_contains(text, "s-nail") && ci_contains(text, " -")) ||
            (ci_contains(text, "rsync") &&
             (ci_contains(text, " -e") || ci_contains(text, "--rsh") ||
              ci_contains(text, "rsync://") || ci_contains(text, "::"))) ||
            ci_contains(text, "lsyncd") ||
            ci_contains(text, "syncthing") ||
            ci_contains(text, "rslsync") ||
            ci_contains(text, "resilio") ||
            /* ftp/smb/nfs/webdav share exposure daemons */
            ci_contains(text, "vsftpd") ||
            ci_contains(text, "pure-ftpd") ||
            ci_contains(text, "proftpd") ||
            ci_contains(text, "tftpd") ||
            ci_contains(text, "atftpd") ||
            ci_contains(text, "in.tftpd") ||
            ci_contains(text, "tftpd-hpa") ||
            (ci_contains(text, "smbd") &&
             (ci_contains(text, " -d") || ci_contains(text, " -i") ||
              ci_contains(text, " -f"))) ||
            (ci_contains(text, "nmbd") &&
             (ci_contains(text, " -d") || ci_contains(text, " -i"))) ||
            (ci_contains(text, "exportfs") && ci_contains(text, " -")) ||
            ci_contains(text, "unfs3") ||
            ci_contains(text, "nfs-ganesha") ||
            ci_contains(text, "fusedav") ||
            ci_contains(text, "sftpgo") ||
            ci_contains(text, "pyftpdlib") ||
            ci_contains(text, "filebrowser") ||
            (ci_contains(text, "webdav") &&
             (ci_contains(text, "://") || ci_contains(text, " mount") ||
              ci_contains(text, " -"))) ||
            (ci_contains(text, "mc") &&
             (ci_contains(text, " alias") || ci_contains(text, " admin") ||
              ci_contains(text, " mirror"))) ||
            /* overlay/proxy extras */
            ci_contains(text, "etserver") ||
            (ci_contains(text, "supernode") && ci_contains(text, " -")) ||
            ci_contains(text, "ssserver") ||
            ci_contains(text, "sslocal") ||
            ci_contains(text, "mieru") ||
            ci_contains(text, "wireproxy") ||
            /* non-git vcs destructive / admin */
            (ci_contains(text, "hg") &&
             (ci_contains(text, " strip") || ci_contains(text, " rollback") ||
              ci_contains(text, " purge") || ci_contains(text, " backout") ||
              ci_contains(text, " graft"))) ||
            (ci_contains(text, "svn") &&
             (ci_contains(text, " delete") || ci_contains(text, " import") ||
              ci_contains(text, " switch") || ci_contains(text, " merge") ||
              ci_contains(text, " revert") || ci_contains(text, " copy") ||
              ci_contains(text, " cp "))) ||
            (ci_contains(text, "svnadmin") &&
             (ci_contains(text, " dump") || ci_contains(text, " load") ||
              ci_contains(text, " setrevprop"))) ||
            (ci_contains(text, "fossil") &&
             (ci_contains(text, " ui") || ci_contains(text, " server") ||
              ci_contains(text, " clone") || ci_contains(text, " open") ||
              ci_contains(text, " -"))) ||
            (ci_contains(text, "jj") &&
             (ci_contains(text, " abandon") || ci_contains(text, " undo") ||
              ci_contains(text, " squash"))) ||
            (ci_contains(text, "pijul") && ci_contains(text, " -")) ||
            ci_contains(text, "darcs") ||
            ci_contains(text, "bzr") ||
            (ci_contains(text, "monotone") && ci_contains(text, " -")) ||
            (ci_contains(text, "cvs") &&
             (ci_contains(text, " admin") || ci_contains(text, " -d") ||
              ci_contains(text, " checkout") || ci_contains(text, " commit"))) ||
            /* snmp/zmap-suite extras */
            ci_contains(text, "oidwalk") ||
            ci_contains(text, "snmpbulkwalk") ||
            ci_contains(text, "snmpdf") ||
            ci_contains(text, "snmpstatus") ||
            ci_contains(text, "snmptest") ||
            ci_contains(text, "zdns") ||
            ci_contains(text, "ztee") ||
            ci_contains(text, "zannotate") ||
            ci_contains(text, "netsed") ||
            ci_contains(text, "termshark") ||
            ci_contains(text, "macchanger") ||
            ci_contains(text, "nxc") ||
            (ci_contains(text, "sparta") && ci_contains(text, " -")) ||
            (ci_contains(text, "legion") && ci_contains(text, " -")) ||
            (ci_contains(text, "caldera") && ci_contains(text, " -")) ||
            ci_contains(text, "safebreach") ||
            (ci_contains(text, "dnsmasq") && ci_contains(text, " -")) ||
            /* emulators + torrent/download clis */
            ci_contains(text, "waydroid") ||
            ci_contains(text, "genymotion") ||
            ci_contains(text, "anbox") ||
            (ci_contains(text, " age ") &&
             (ci_contains(text, " -r") || ci_contains(text, " -e") ||
              ci_contains(text, " --encrypt"))) ||
            (ci_contains(text, "rage") && ci_contains(text, " -")) ||
            ci_contains(text, "transmission-cli") ||
            ci_contains(text, "deluge-console") ||
            ci_contains(text, "qbittorrent-nox") ||
            ci_contains(text, "rtorrent") ||
            ci_contains(text, "mktorrent") ||
            ci_contains(text, "ctorrent") ||
            (ci_contains(text, "axel") &&
             (ci_contains(text, " -") || ci_contains(text, "http"))) ||
            ci_contains(text, "prozilla") ||
            ci_contains(text, "mget") ||
            ci_contains(text, "getx") ||
            (ci_contains(text, "snarf") && ci_contains(text, " -")) ||
            /* mail infra */
            ci_contains(text, "smtpd") ||
            (ci_contains(text, "exim") && ci_contains(text, " -")) ||
            (ci_contains(text, "exim4") && ci_contains(text, " -")) ||
            (ci_contains(text, "postqueue") && ci_contains(text, " -")) ||
            ci_contains(text, "postcat") ||
            ci_contains(text, "postsuper") ||
            ci_contains(text, "postsrsd") ||
            ci_contains(text, "opendkim") ||
            ci_contains(text, "dkimproxy") ||
            ci_contains(text, "spamc") ||
            ci_contains(text, "spamctl") ||
            ci_contains(text, "bogofilter") ||
            ci_contains(text, "razor-admin") ||
            ci_contains(text, "pyzor") ||
            ci_contains(text, "dccproc") ||
            ci_contains(text, "postmap") ||
            ci_contains(text, "postalias") ||
            ci_contains(text, "newaliases") ||
            ci_contains(text, "qmail")) {
            what = "rtools/mail/sync/vcs/share-daemon/exec primitive";
        } else if (
            /* interpreter / REPL inline-exec and editor escapes */
            ci_contains(text, "nodejs -e") || ci_contains(text, "nodejs --eval") ||
            (ci_contains(text, "irb") &&
             (ci_contains(text, " -e") || ci_contains(text, " -r"))) ||
            ci_contains(text, "php -a") || ci_contains(text, "groovysh") ||
            ci_contains(text, "nashorn") ||
            (ci_contains(text, "scala") && ci_contains(text, " -e")) ||
            (ci_contains(text, "clj") &&
             (ci_contains(text, " -e") || ci_contains(text, " -m"))) ||
            (ci_contains(text, "iex") &&
             (ci_contains(text, " -e") || ci_contains(text, " -r"))) ||
            (ci_contains(text, "erl") &&
             (ci_contains(text, " -eval") || ci_contains(text, " -noshell") ||
              ci_contains(text, " -run"))) ||
            (ci_contains(text, "pwsh") && ci_contains(text, " -e")) ||
            (ci_contains(text, "perl") &&
             (ci_contains(text, " -pi") || ci_contains(text, " -pe"))) ||
            ((ci_contains(text, "vim") || ci_contains(text, "nvim")) &&
             (ci_contains(text, " +!") || ci_contains(text, " +:"))) ||
            (ci_contains(text, "less") && ci_contains(text, " !")) ||
            (ci_contains(text, "more") && ci_contains(text, " !")) ||
            (ci_contains(text, "man") && ci_contains(text, " !")) ||
            (ci_contains(text, "zip") && ci_contains(text, " -tt")) ||
            (ci_contains(text, "bash") && ci_contains(text, " -c")) ||
            (ci_contains(text, " sh ") && ci_contains(text, " -c")) ||
            (ci_contains(text, "enable -f") &&
             (ci_contains(text, ".so") || ci_contains(text, " /"))) ||
            /* terminal multiplexer / emulator command exec */
            (ci_contains(text, "xterm") && ci_contains(text, " -e")) ||
            (ci_contains(text, "urxvt") && ci_contains(text, " -e")) ||
            (ci_contains(text, "rxvt") && ci_contains(text, " -e")) ||
            (ci_contains(text, "alacritty") && ci_contains(text, " -e")) ||
            (ci_contains(text, "kitty") &&
             (ci_contains(text, " -e") || ci_contains(text, " @"))) ||
            (ci_contains(text, " st ") && ci_contains(text, " -e")) ||
            (ci_contains(text, "konsole") && ci_contains(text, " -e")) ||
            (ci_contains(text, "gnome-terminal") &&
             (ci_contains(text, " --") || ci_contains(text, " -e"))) ||
            (ci_contains(text, "xfce4-terminal") && ci_contains(text, " -e")) ||
            (ci_contains(text, "lxterminal") && ci_contains(text, " -e")) ||
            (ci_contains(text, "mate-terminal") && ci_contains(text, " -e")) ||
            (ci_contains(text, "tilix") && ci_contains(text, " -e")) ||
            (ci_contains(text, "terminator") && ci_contains(text, " -e")) ||
            (ci_contains(text, "sakura") && ci_contains(text, " -e")) ||
            (ci_contains(text, "termite") && ci_contains(text, " -e")) ||
            (ci_contains(text, "foot") && ci_contains(text, " -e")) ||
            (ci_contains(text, "wezterm") &&
             (ci_contains(text, " -e") || ci_contains(text, " cli"))) ||
            (ci_contains(text, "xinit") &&
             (ci_contains(text, " /") || ci_contains(text, " sh"))) ||
            (ci_contains(text, "tmux") &&
             (ci_contains(text, " new ") || ci_contains(text, " send-keys") ||
              ci_contains(text, " run-shell") || ci_contains(text, " respawn") ||
              ci_contains(text, " source") || ci_contains(text, " bind") ||
              ci_contains(text, " set-hook"))) ||
            (ci_contains(text, "screen") &&
             (ci_contains(text, " -dm") || ci_contains(text, " -s /") ||
              ci_contains(text, " sh ") || ci_contains(text, " bash"))) ||
            /* exec-wrapper primitives (GTFOBins-style prog spawn) */
            ((ci_contains(text, "flock") || ci_contains(text, "nice") ||
              ci_contains(text, "timeout") || ci_contains(text, "stdbuf") ||
              ci_contains(text, "ionice") || ci_contains(text, "taskset") ||
              ci_contains(text, "chrt") || ci_contains(text, "schedtool") ||
              ci_contains(text, "env ") || ci_contains(text, "chroot") ||
              ci_contains(text, "unshare") || ci_contains(text, "setpriv") ||
              ci_contains(text, "ssh-agent")) &&
             (ci_contains(text, " sh") || ci_contains(text, " bash") ||
              ci_contains(text, " python") || ci_contains(text, " perl") ||
              ci_contains(text, " ruby") || ci_contains(text, " php") ||
              ci_contains(text, " lua") || ci_contains(text, " node") ||
              ci_contains(text, " dash") || ci_contains(text, " zsh") ||
              ci_contains(text, " csh") || ci_contains(text, " tcsh") ||
              ci_contains(text, " fish") || ci_contains(text, " exec") ||
              ci_contains(text, " /bin"))) ||
            (ci_contains(text, "capsh") &&
             (ci_contains(text, " -- ") || ci_contains(text, " --decode"))) ||
            (ci_contains(text, " su ") && ci_contains(text, " -")) ||
            (ci_contains(text, "gdb") && ci_contains(text, " -ex")) ||
            (ci_contains(text, "lldb") &&
             (ci_contains(text, " -o") || ci_contains(text, " -b") ||
              ci_contains(text, " -s"))) ||
            (ci_contains(text, "strace") &&
             (ci_contains(text, " -e ") || ci_contains(text, " -o "))) ||
            /* package-manager / toolchain exec hooks */
            (ci_contains(text, "npm") && ci_contains(text, " exec")) ||
            (ci_contains(text, "gem") && ci_contains(text, " exec")) ||
            (ci_contains(text, "bundle") && ci_contains(text, " exec")) ||
            (ci_contains(text, "cpan") && ci_contains(text, " -e")) ||
            (ci_contains(text, "go ") &&
             (ci_contains(text, " tool ") || ci_contains(text, " generate"))) ||
            (ci_contains(text, "dotnet") &&
             (ci_contains(text, " run") || ci_contains(text, " exec") ||
              ci_contains(text, " fsi") || ci_contains(text, " msbuild"))) ||
            ci_contains(text, "cargo-script") ||
            /* IRC clients and C2-capable chat bots */
            ci_contains(text, "ircd") || ci_contains(text, "ngircd") ||
            (ci_contains(text, "irssi") &&
             (ci_contains(text, " -c") || ci_contains(text, " -!") ||
              ci_contains(text, " --connect"))) ||
            (ci_contains(text, "weechat") &&
             (ci_contains(text, " -r") || ci_contains(text, " -a") ||
              ci_contains(text, " --run") || ci_contains(text, " --connect"))) ||
            (ci_contains(text, "hexchat") &&
             (ci_contains(text, " -a") || ci_contains(text, " -c") ||
              ci_contains(text, " --existing"))) ||
            (ci_contains(text, "ftp") &&
             (ci_contains(text, " -n") || ci_contains(text, " -i") ||
              ci_contains(text, " -g") || ci_contains(text, " -d") ||
              ci_contains(text, "ftp://"))) ||
            (ci_contains(text, "lftp") &&
             (ci_contains(text, " -e") || ci_contains(text, " -f") ||
              ci_contains(text, " -c") || ci_contains(text, " -u"))) ||
            ci_contains(text, "ncftp") ||
            /* RMM / remote-access fleet */
            ci_contains(text, "connectwise") || ci_contains(text, "gotomypc") ||
            ci_contains(text, "dameware") || ci_contains(text, "dwrcs") ||
            ci_contains(text, "bomgar") || ci_contains(text, "beyondtrust") ||
            ci_contains(text, "ninjaone") || ci_contains(text, "kaseya") ||
            ci_contains(text, "n-able") || ci_contains(text, "meshcommander") ||
            ci_contains(text, "uvnc") || ci_contains(text, "krdc") ||
            ci_contains(text, "ssvnc") || ci_contains(text, "vinagre") ||
            (ci_contains(text, "parsec") && ci_contains(text, " -")) ||
            (ci_contains(text, "moonlight") &&
             (ci_contains(text, " -") || ci_contains(text, " stream") ||
              ci_contains(text, " pair"))) ||
            (ci_contains(text, "sunshine") &&
             (ci_contains(text, " -") || ci_contains(text, " stream") ||
              ci_contains(text, " pair") || ci_contains(text, " appspot"))) ||
            (ci_contains(text, "supremo") &&
             (ci_contains(text, " -") || ci_contains(text, " /"))) ||
            (ci_contains(text, "tactical") &&
             (ci_contains(text, " rmm") || ci_contains(text, " -"))) ||
            ci_contains(text, "zoho assist") || ci_contains(text, "fixme.it") ||
            ci_contains(text, "showmypc") ||
            /* crypto miners and wallet CLI looting */
            (ci_contains(text, "claymore") && ci_contains(text, " -")) ||
            ci_contains(text, "t-rex") ||
            (ci_contains(text, "trex") && ci_contains(text, " -")) ||
            ci_contains(text, "monerod") || ci_contains(text, "monero-wallet-cli") ||
            ci_contains(text, "bitcoin-cli") || ci_contains(text, "bitcoin-qt") ||
            ci_contains(text, "bitcoind") || ci_contains(text, "litecoin-cli") ||
            ci_contains(text, "dogecoind") || ci_contains(text, "dash-cli") ||
            ci_contains(text, "zcash-cli") || ci_contains(text, "p2pool") ||
            ci_contains(text, "kinsing") || ci_contains(text, "kdevtmpfsi") ||
            (ci_contains(text, "electrum") &&
             (ci_contains(text, " daemon") || ci_contains(text, " getaddress") ||
              ci_contains(text, " payto") || ci_contains(text, " -o") ||
              ci_contains(text, " -w") || ci_contains(text, " listaddresses") ||
              ci_contains(text, " getbalance") || ci_contains(text, " getprivatekeys") ||
              ci_contains(text, " signmessage") || ci_contains(text, " broadcast"))) ||
            (ci_contains(text, "geth") &&
             (ci_contains(text, " attach") || ci_contains(text, " account") ||
              ci_contains(text, " console") || ci_contains(text, " init") ||
              ci_contains(text, " dump") || ci_contains(text, " export") ||
              ci_contains(text, " import") || ci_contains(text, " removedb") ||
              ci_contains(text, " db ") || ci_contains(text, " js ") ||
              ci_contains(text, " --exec") || ci_contains(text, " --jspath") ||
              ci_contains(text, " --preload") || ci_contains(text, " --unlock") ||
              ci_contains(text, " --password") || ci_contains(text, " --mine"))) ||
            (ci_contains(text, "parity") && ci_contains(text, " -")) ||
            /* backup tooling exfil / destroy */
            (ci_contains(text, "duplicity") &&
             (ci_contains(text, " remove") || ci_contains(text, " cleanup") ||
              ci_contains(text, " restore") || ci_contains(text, " collection"))) ||
            ci_contains(text, "rsnapshot") || ci_contains(text, "bacula") ||
            ci_contains(text, "bareos") ||
            (ci_contains(text, "amanda") &&
             (ci_contains(text, " am") || ci_contains(text, " -"))) ||
            (ci_contains(text, "bup") &&
             (ci_contains(text, " init") || ci_contains(text, " save") ||
              ci_contains(text, " restore") || ci_contains(text, " -"))) ||
            ci_contains(text, "kopia") ||
            (ci_contains(text, "tarsnap") && ci_contains(text, " -")) ||
            (ci_contains(text, "timeshift") &&
             (ci_contains(text, " --delete") || ci_contains(text, " --restore") ||
              ci_contains(text, " --create") || ci_contains(text, " --check"))) ||
            /* SQL / LDAP / IPA client extras */
            (ci_contains(text, "osql") && ci_contains(text, " -")) ||
            (ci_contains(text, "isql") && ci_contains(text, " -")) ||
            (ci_contains(text, "tsql") && ci_contains(text, " -")) ||
            (ci_contains(text, "sqsh") && ci_contains(text, " -")) ||
            (ci_contains(text, "dsql") && ci_contains(text, " -")) ||
            ci_contains(text, "slapcat") || ci_contains(text, "slapadd") ||
            ci_contains(text, "slapindex") ||
            (ci_contains(text, "ipa") &&
             (ci_contains(text, " user") || ci_contains(text, " group") ||
              ci_contains(text, " host") || ci_contains(text, " hbac") ||
              ci_contains(text, " sudo") || ci_contains(text, " vault") ||
              ci_contains(text, " priv"))) ||
            ci_contains(text, "ipa-client-install") || ci_contains(text, "realmd") ||
            /* AD / Windows infra recon and control */
            ci_contains(text, "ntdsutil") || ci_contains(text, "repadmin") ||
            ci_contains(text, "dnscmd") || ci_contains(text, "dfsutil") ||
            ci_contains(text, "dfsradmin") || ci_contains(text, "mountvol") ||
            (ci_contains(text, "wmic") && ci_contains(text, " ntdomain")) ||
            /* NVMe / storage teardown and SCSI control */
            (ci_contains(text, "nvme") &&
             (ci_contains(text, " reset") || ci_contains(text, " ns-delete") ||
              ci_contains(text, " delete-ns") || ci_contains(text, " subsystem-reset") ||
              ci_contains(text, " disconnect") || ci_contains(text, " attach-ns") ||
              ci_contains(text, " detach-ns") || ci_contains(text, " create-ns") ||
              ci_contains(text, " set-property"))) ||
            (ci_contains(text, "sgdisk") &&
             (ci_contains(text, " -z") || ci_contains(text, " --zap") ||
              ci_contains(text, " --clear") || ci_contains(text, " -o") ||
              ci_contains(text, " --new") || ci_contains(text, " -d") ||
              ci_contains(text, " -t") || ci_contains(text, " -c") ||
              ci_contains(text, " -a") || ci_contains(text, " -u") ||
              ci_contains(text, " -g") || ci_contains(text, " -r") ||
              ci_contains(text, " -m"))) ||
            (ci_contains(text, "parted") &&
             (ci_contains(text, " rm") || ci_contains(text, " mkpart") ||
              ci_contains(text, " resizepart") || ci_contains(text, " name") ||
              ci_contains(text, " set") || ci_contains(text, " toggle") ||
              ci_contains(text, " rescue") || ci_contains(text, " disk_"))) ||
            (ci_contains(text, "hdparm") &&
             (ci_contains(text, " -y") || ci_contains(text, " --sleep") ||
              ci_contains(text, " --standby") || ci_contains(text, " --read-sector") ||
              ci_contains(text, " --dco"))) ||
            (ci_contains(text, "sdparm") &&
             (ci_contains(text, " --command") || ci_contains(text, " --clear") ||
              ci_contains(text, " --set") || ci_contains(text, " --reset"))) ||
            (ci_contains(text, "sg_start") &&
             (ci_contains(text, " --stop") || ci_contains(text, " --eject"))) ||
            (ci_contains(text, "sg_prevent") &&
             (ci_contains(text, " -a") || ci_contains(text, " --allow"))) ||
            (ci_contains(text, "camcontrol") &&
             (ci_contains(text, " stop") || ci_contains(text, " eject") ||
              ci_contains(text, " format") || ci_contains(text, " sanitize") ||
              ci_contains(text, " security") || ci_contains(text, " fwdownload") ||
              ci_contains(text, " delete") || ci_contains(text, " idle") ||
              ci_contains(text, " standby") || ci_contains(text, " sleep") ||
              ci_contains(text, " cmd"))) ||
            (ci_contains(text, "zpool") &&
             (ci_contains(text, " export") || ci_contains(text, " offline") ||
              ci_contains(text, " detach") || ci_contains(text, " remove") ||
              ci_contains(text, " replace") || ci_contains(text, " attach") ||
              ci_contains(text, " split") || ci_contains(text, " reguid") ||
              ci_contains(text, " labelclear") || ci_contains(text, " checkpoint") ||
              ci_contains(text, " trim"))) ||
            (ci_contains(text, "zfs") &&
             (ci_contains(text, " unmount") || ci_contains(text, " umount") ||
              ci_contains(text, " rename") || ci_contains(text, " promote") ||
              ci_contains(text, " rollback") || ci_contains(text, " hold") ||
              ci_contains(text, " release") || ci_contains(text, " send") ||
              ci_contains(text, " receive") || ci_contains(text, " allow") ||
              ci_contains(text, " unallow") || ci_contains(text, " jail") ||
              ci_contains(text, " change-key") || ci_contains(text, " load-key") ||
              ci_contains(text, " unload-key") || ci_contains(text, " redact") ||
              ci_contains(text, " bookmark"))) ||
            (ci_contains(text, "cryptsetup") &&
             (ci_contains(text, " luksclose") || ci_contains(text, " lukssuspend") ||
              ci_contains(text, " remove") || ci_contains(text, " convert") ||
              ci_contains(text, " config") || ci_contains(text, " reencrypt") ||
              ci_contains(text, " token") || ci_contains(text, " luksaddkey") ||
              ci_contains(text, " luksremovekey") || ci_contains(text, " lukskill") ||
              ci_contains(text, " lukschange"))) ||
            (ci_contains(text, "vgchange") &&
             (ci_contains(text, " -an") || ci_contains(text, " -a n") ||
              ci_contains(text, " --deactivate"))) ||
            (ci_contains(text, "lvchange") &&
             (ci_contains(text, " -an") || ci_contains(text, " -a n") ||
              ci_contains(text, " --deactivate") || ci_contains(text, " --permission") ||
              ci_contains(text, " -p"))) ||
            ci_contains(text, "blkdiscard") ||
            (ci_contains(text, "blkzone") && ci_contains(text, " reset")) ||
            (ci_contains(text, "zramctl") && ci_contains(text, " --reset")) ||
            (ci_contains(text, "kpartx") &&
             (ci_contains(text, " -d") || ci_contains(text, " --delete"))) ||
            (ci_contains(text, "dmraid") &&
             (ci_contains(text, " -an") || ci_contains(text, " -r") ||
              ci_contains(text, " -e") || ci_contains(text, " -x"))) ||
            (ci_contains(text, "multipath") &&
             (ci_contains(text, " -f") || ci_contains(text, " --flush") ||
              ci_contains(text, " -w"))) ||
            (ci_contains(text, "multipathd") && ci_contains(text, " -k")) ||
            (ci_contains(text, "iscsiadm") &&
             (ci_contains(text, " --delete") || ci_contains(text, " -o delete"))) ||
            ci_contains(text, "modprobe") || ci_contains(text, "rmmod") ||
            ci_contains(text, "depmod") ||
            (ci_contains(text, " sv ") &&
             (ci_contains(text, " stop") || ci_contains(text, " down") ||
              ci_contains(text, " force-") || ci_contains(text, " exit") ||
              ci_contains(text, " kill") || ci_contains(text, " term") ||
              ci_contains(text, " interrupt") || ci_contains(text, " quit") ||
              ci_contains(text, " once") || ci_contains(text, " pause") ||
              ci_contains(text, " hup") || ci_contains(text, " alarm") ||
              ci_contains(text, " cont"))) ||
            /* SNMP / NSM / SCADA extras */
            ci_contains(text, "snmptable") || ci_contains(text, "snmpnetstat") ||
            ci_contains(text, "snmpusm") || ci_contains(text, "snmpvacm") ||
            ci_contains(text, "snmptranslate") || ci_contains(text, "snmpinform") ||
            ci_contains(text, "snmpd") || ci_contains(text, "snmptrapd") ||
            ci_contains(text, "zeekctl") || ci_contains(text, "broctl") ||
            ci_contains(text, "argus") || ci_contains(text, "ntopng") ||
            ci_contains(text, "ostinato") || ci_contains(text, "etterfilter") ||
            ci_contains(text, "sshow") ||
            (ci_contains(text, "ntop") &&
             (ci_contains(text, " -") || ci_contains(text, "ng"))) ||
            ci_contains(text, "opcua") || ci_contains(text, "bacnet") ||
            ci_contains(text, "mbusd") || ci_contains(text, "profinet") ||
            ci_contains(text, "s7comm") || ci_contains(text, "modbus") ||
            /* PowerShell remoting / WMI persistence / Defender tamper */
            ci_contains(text, "enter-pssession") || ci_contains(text, "new-pssession") ||
            ci_contains(text, "invoke-command") || ci_contains(text, "invoke-expression") ||
            ci_contains(text, "invoke-wmicommand") || ci_contains(text, "invoke-cimmethod") ||
            ci_contains(text, "commandlineeventconsumer") ||
            ci_contains(text, "__eventfilter") ||
            ci_contains(text, "activescripteventconsumer") ||
            ci_contains(text, "paexec") || ci_contains(text, "set-mpcomputerstatus") ||
            ci_contains(text, "remove-mppreference") ||
            (ci_contains(text, "mpcmdrun") &&
             (ci_contains(text, " -") || ci_contains(text, " /"))) ||
            (ci_contains(text, "iex") &&
             (ci_contains(text, " (") || ci_contains(text, " new-"))) ||
            /* headless capture / webshot / curl-wget extras */
            ((ci_contains(text, "chromium") || ci_contains(text, "chrome") ||
              ci_contains(text, "msedge") || ci_contains(text, "firefox")) &&
             ci_contains(text, " --headless")) ||
            ci_contains(text, "wkhtmltoimage") || ci_contains(text, "wkhtmltopdf") ||
            ci_contains(text, "cutycapt") || ci_contains(text, "phantomjs") ||
            ci_contains(text, "casperjs") || ci_contains(text, "slimerjs") ||
            ci_contains(text, "trurl") ||
            (ci_contains(text, "playwright") &&
             (ci_contains(text, " screenshot") || ci_contains(text, " pdf") ||
              ci_contains(text, " open") || ci_contains(text, " codegen"))) ||
            (ci_contains(text, "puppeteer") &&
             (ci_contains(text, " -") || ci_contains(text, " screenshot") ||
              ci_contains(text, " pdf"))) ||
            (ci_contains(text, "curl") &&
             (ci_contains(text, " --resolve") || ci_contains(text, " --connect-to") ||
              ci_contains(text, " --cert") || ci_contains(text, " --key") ||
              ci_contains(text, " --config") || ci_contains(text, " --crlfile") ||
              ci_contains(text, " --pinnedpubkey"))) ||
            (ci_contains(text, "wget") &&
             (ci_contains(text, " --method") || ci_contains(text, " --body-data") ||
              ci_contains(text, " --body-file") || ci_contains(text, " --header") ||
              ci_contains(text, " --user") || ci_contains(text, " --password") ||
              ci_contains(text, " --ftp-") || ci_contains(text, " --http-"))) ||
            (ci_contains(text, "chronyc") &&
             (ci_contains(text, " makestep") || ci_contains(text, " burst") ||
              ci_contains(text, " -a") || ci_contains(text, " add") ||
              ci_contains(text, " delete") || ci_contains(text, " online") ||
              ci_contains(text, " offline"))) ||
            (ci_contains(text, "rdate") && ci_contains(text, " -")) ||
            /* credential / history / log / enum recon */
            (ci_contains(text, "find") && ci_contains(text, " -name") &&
             (ci_contains(text, ".env") || ci_contains(text, "id_rsa") ||
              ci_contains(text, ".pem") || ci_contains(text, ".key") ||
              ci_contains(text, "credential") || ci_contains(text, "pgpass") ||
              ci_contains(text, "shadow") || ci_contains(text, "id_ed25519") ||
              ci_contains(text, ".pypirc") || ci_contains(text, ".npmrc") ||
              ci_contains(text, "known_hosts") || ci_contains(text, ".ssh") ||
              ci_contains(text, "id_dsa") || ci_contains(text, "id_ecdsa") ||
              ci_contains(text, "secret"))) ||
            (ci_contains(text, "grep") && ci_contains(text, " -r") &&
             (ci_contains(text, "private") || ci_contains(text, "password") ||
              ci_contains(text, "secret") || ci_contains(text, "begin ") ||
              ci_contains(text, "credential") || ci_contains(text, "passwd"))) ||
            (ci_contains(text, "getent") && ci_contains(text, " netgroup")) ||
            (ci_contains(text, "compgen") &&
             (ci_contains(text, " -u") || ci_contains(text, " -g") ||
              ci_contains(text, " -a") || ci_contains(text, " user") ||
              ci_contains(text, " group"))) ||
            (ci_contains(text, "history") &&
             (ci_contains(text, " -a") || ci_contains(text, " -r") ||
              ci_contains(text, " -p") || ci_contains(text, " -s"))) ||
            (ci_contains(text, "fc ") && ci_contains(text, " -l")) ||
            (ci_contains(text, " net ") &&
             (ci_contains(text, " view") || ci_contains(text, " share") ||
              ci_contains(text, " session") || ci_contains(text, " accounts") ||
              ci_contains(text, " statistics") || ci_contains(text, " config") ||
              ci_contains(text, " time") || ci_contains(text, " file") ||
              ci_contains(text, " print") || ci_contains(text, " send") ||
              ci_contains(text, " start") || ci_contains(text, " stop") ||
              ci_contains(text, " continue") || ci_contains(text, " pause") ||
              ci_contains(text, " use") || ci_contains(text, " user") ||
              ci_contains(text, " localgroup") || ci_contains(text, " group") ||
              ci_contains(text, " helpmsg") || ci_contains(text, " name"))) ||
            ci_contains(text, "mongoexport") || ci_contains(text, "mongodump") ||
            ci_contains(text, "mongorestore") ||
            (ci_contains(text, "mount") &&
             (ci_contains(text, " -t cifs") || ci_contains(text, " -t nfs") ||
              ci_contains(text, " -t smbfs") || ci_contains(text, " -t davfs") ||
              ci_contains(text, " -t sshfs"))) ||
            ci_contains(text, "mount_smbfs") || ci_contains(text, "mount_nfs")
        ) {
            what = "repl/escape/rmm/miner/storage/exec primitive";
        } else if (
            /* storage teardown extras + fs destruction */
            ci_contains(text, "fstrim") ||
            ci_contains(text, "mkswap") || ci_contains(text, "resize2fs") ||
            ci_contains(text, "e2label") ||
            (ci_contains(text, "tune2fs") &&
             (ci_contains(text, " -u") || ci_contains(text, " -c") ||
              ci_contains(text, " -i") || ci_contains(text, " -o") ||
              ci_contains(text, " -m") || ci_contains(text, " -j") ||
              ci_contains(text, " -e") || ci_contains(text, " -r") ||
              ci_contains(text, " -s"))) ||
            ci_contains(text, "xfs_admin") || ci_contains(text, "xfs_io") ||
            ci_contains(text, "xfs_bmap") || ci_contains(text, "xfs_estimate") ||
            ci_contains(text, "xfs_freeze") || ci_contains(text, "xfs_growfs") ||
            ci_contains(text, "xfs_metadump") || ci_contains(text, "xfs_repair") ||
            ci_contains(text, "btrfstune") || ci_contains(text, "bcache") ||
            (ci_contains(text, "btrfs") &&
             (ci_contains(text, " send") || ci_contains(text, " receive") ||
              ci_contains(text, " balance") || ci_contains(text, " rescue") ||
              ci_contains(text, " restore") || ci_contains(text, " scrub") ||
              ci_contains(text, " check") || ci_contains(text, " property") ||
              ci_contains(text, " quota") || ci_contains(text, " qgroup") ||
              ci_contains(text, " inspect") || ci_contains(text, " dump"))) ||
            (ci_contains(text, "mdadm") &&
             (ci_contains(text, " --create") || ci_contains(text, " --build") ||
              ci_contains(text, " --grow") || ci_contains(text, " --assemble") ||
              ci_contains(text, " --misc") || ci_contains(text, " --monitor") ||
              ci_contains(text, " --incremental"))) ||
            (ci_contains(text, "dmsetup") &&
             (ci_contains(text, " clear") || ci_contains(text, " wipe") ||
              ci_contains(text, " suspend") || ci_contains(text, " create") ||
              ci_contains(text, " reload") || ci_contains(text, " rename") ||
              ci_contains(text, " resume") || ci_contains(text, " table"))) ||
            ci_contains(text, "zdb") || ci_contains(text, "ztest") ||
            ci_contains(text, "zstreamdump") || ci_contains(text, "zinject") ||
            ci_contains(text, "zvol_wait") || ci_contains(text, "zfs_ids_to_path") ||
            (ci_contains(text, "zpool") &&
             (ci_contains(text, " create") || ci_contains(text, " scrub") ||
              ci_contains(text, " initialize") || ci_contains(text, " resilver") ||
              ci_contains(text, " import"))) ||
            (ci_contains(text, "zfs") &&
             (ci_contains(text, " snapshot") || ci_contains(text, " clone") ||
              ci_contains(text, " share") || ci_contains(text, " mount ") ||
              ci_contains(text, " upgrade") || ci_contains(text, " set ") ||
              ci_contains(text, " project"))) ||
            /* screenshot / audio / input-injection / keylogger */
            (ci_contains(text, "grim") &&
             (ci_contains(text, " -") || ci_contains(text, ".png") ||
              ci_contains(text, ".jpg") || ci_contains(text, " /"))) ||
            (ci_contains(text, "slurp") && ci_contains(text, " -")) ||
            (ci_contains(text, "maim") &&
             (ci_contains(text, " -") || ci_contains(text, ".png") ||
              ci_contains(text, ".jpg"))) ||
            ci_contains(text, "hyprshot") || ci_contains(text, "grimblast") ||
            ci_contains(text, "xfce4-screenshooter") ||
            ci_contains(text, "pw-record") || ci_contains(text, "avconv") ||
            (ci_contains(text, "sox") &&
             (ci_contains(text, " rec ") || ci_contains(text, " -d ") ||
              ci_contains(text, " -t "))) ||
            ci_contains(text, "motioneye") || ci_contains(text, "zoneminder") ||
            ci_contains(text, "zmeventnotification") ||
            (ci_contains(text, "motion") &&
             (ci_contains(text, " -c") || ci_contains(text, " -b") ||
              ci_contains(text, " -d") || ci_contains(text, " -n"))) ||
            ci_contains(text, "xte ") || ci_contains(text, "xvkbd") ||
            ci_contains(text, "xdo ") || ci_contains(text, "input-recorder") ||
            (ci_contains(text, "keyd") &&
             (ci_contains(text, " send-keys") || ci_contains(text, " monitor") ||
              ci_contains(text, " applymap") || ci_contains(text, " -m"))) ||
            ci_contains(text, "keysniffer") ||
            /* miner / C2 / RAT / stealer vocabulary extras */
            ci_contains(text, "tnn-miner") || ci_contains(text, "cryptonight") ||
            ci_contains(text, "randomx") || ci_contains(text, "silenttrinity") ||
            ci_contains(text, "dcrat") || ci_contains(text, "vidar") ||
            ci_contains(text, "meduza") ||
            (ci_contains(text, "sliver") &&
             (ci_contains(text, " beacon") || ci_contains(text, " mtls") ||
              ci_contains(text, " http") || ci_contains(text, " wg") ||
              ci_contains(text, " implant") || ci_contains(text, " c2"))) ||
            (ci_contains(text, "quasar") &&
             (ci_contains(text, " c2") || ci_contains(text, " rat"))) ||
            (ci_contains(text, "warzone") &&
             (ci_contains(text, " rat") || ci_contains(text, " c2"))) ||
            (ci_contains(text, "raccoon") &&
             (ci_contains(text, " stealer") || ci_contains(text, " c2"))) ||
            (ci_contains(text, "ares") && ci_contains(text, " c2")) ||
            (ci_contains(text, "orion") && ci_contains(text, " c2")) ||
            (ci_contains(text, "villager") && ci_contains(text, " c2")) ||
            (ci_contains(text, "merlin") &&
             (ci_contains(text, " c2") || ci_contains(text, " beacon"))) ||
            (ci_contains(text, "octopus") &&
             (ci_contains(text, " c2") || ci_contains(text, " agent"))) ||
            /* LOLBin / exec-helper residuals */
            (ci_contains(text, "esentutl") &&
             (ci_contains(text, " /p") || ci_contains(text, " /o") ||
              ci_contains(text, " /r") || ci_contains(text, " /g") ||
              ci_contains(text, " /m"))) ||
            (ci_contains(text, "forfiles") &&
             (ci_contains(text, " /c") || ci_contains(text, " /s") ||
              ci_contains(text, " /p"))) ||
            (ci_contains(text, "mmc") &&
             (ci_contains(text, " /") || ci_contains(text, "msc"))) ||
            (ci_contains(text, "wmic") &&
             (ci_contains(text, " /node") || ci_contains(text, " /namespace") ||
              ci_contains(text, " process list") ||
              ci_contains(text, " process get") ||
              ci_contains(text, " bios get") ||
              ci_contains(text, " computersystem get") ||
              ci_contains(text, " os get") || ci_contains(text, " baseboard get") ||
              ci_contains(text, " cpu get") || ci_contains(text, " diskdrive get") ||
              ci_contains(text, " nicconfig") || ci_contains(text, " startup list") ||
              ci_contains(text, " service list") || ci_contains(text, " qfe") ||
              ci_contains(text, " product get") || ci_contains(text, " share list") ||
              ci_contains(text, " sysaccount") || ci_contains(text, " group list") ||
              ci_contains(text, " useraccount") || ci_contains(text, " netlogin") ||
              ci_contains(text, " rdtoggle") || ci_contains(text, " recoveros"))) ||
            (ci_contains(text, "manage-bde") &&
             (ci_contains(text, " -protectors") ||
              ci_contains(text, " -backupkey") ||
              ci_contains(text, " -changepassword") ||
              ci_contains(text, " -changepin") ||
              ci_contains(text, " -changekey") ||
              ci_contains(text, " -forcerecovery") ||
              ci_contains(text, " -getpackage"))) ||
            (ci_contains(text, "ncat") && ci_contains(text, " --lua-exec")) ||
            (ci_contains(text, "socat") && ci_contains(text, " system:")) ||
            (ci_contains(text, "parallel") &&
             (ci_contains(text, " ::") || ci_contains(text, " --pipe"))) ||
            ((ci_contains(text, "gawk") || ci_contains(text, "mawk")) &&
             (ci_contains(text, "system(") || ci_contains(text, "begin") ||
              ci_contains(text, " getline"))) ||
            (ci_contains(text, "tar") && ci_contains(text, " --to-command")) ||
            /* DNS TXT/ANY exfil + tunnel helpers */
            (ci_contains(text, "dig") &&
             (ci_contains(text, " txt") ||
              ci_contains(text, " -t txt") || ci_contains(text, " -t any") ||
              ci_contains(text, " -x"))) ||
            (ci_contains(text, "nslookup") &&
             (ci_contains(text, " -type=txt") || ci_contains(text, " -qt=txt") ||
              ci_contains(text, " -type=any") || ci_contains(text, " -qt=any"))) ||
            (ci_contains(text, "host") &&
             (ci_contains(text, " -t txt") || ci_contains(text, " -t any") ||
              ci_contains(text, " -ax"))) ||
            (ci_contains(text, "drill") &&
             (ci_contains(text, " txt") || ci_contains(text, " any") ||
              ci_contains(text, " -x"))) ||
            ci_contains(text, "doggo") || ci_contains(text, "kdig") ||
            /* external-IP recon endpoints */
            ((ci_contains(text, "curl") || ci_contains(text, "wget")) &&
             (ci_contains(text, "ifconfig.me") || ci_contains(text, "ident.me") ||
              ci_contains(text, "icanhazip") || ci_contains(text, "ipify") ||
              ci_contains(text, "checkip") || ci_contains(text, "wtfismyip") ||
              ci_contains(text, "ipinfo") || ci_contains(text, "ipapi") ||
              ci_contains(text, "ipecho") || ci_contains(text, "ifconfig.co"))) ||
            /* xdg / desktop launcher with remote payload */
            ((ci_contains(text, "xdg-open") || ci_contains(text, "gio ") ||
              ci_contains(text, "kde-open") || ci_contains(text, "sensible-browser") ||
              ci_contains(text, "x-www-browser") || ci_contains(text, "gnome-open") ||
              ci_contains(text, "exo-open") || ci_contains(text, "open ")) &&
             ci_contains(text, " http")) ||
            /* systemd / package-manager / loader tamper */
            ci_contains(text, "systemd-dissect") ||
            ci_contains(text, "systemd-volatile-root") ||
            (ci_contains(text, "machinectl") &&
             (ci_contains(text, " bind") || ci_contains(text, " copy-") ||
              ci_contains(text, " import-") || ci_contains(text, " export-") ||
              ci_contains(text, " image-"))) ||
            (ci_contains(text, "alternatives") &&
             (ci_contains(text, " --set") || ci_contains(text, " --install") ||
              ci_contains(text, " --config") || ci_contains(text, " --remove") ||
              ci_contains(text, " --auto") || ci_contains(text, " --slave") ||
              ci_contains(text, " --master") || ci_contains(text, " --altdir") ||
              ci_contains(text, " --admindir"))) ||
            ci_contains(text, "dpkg-divert") ||
            ci_contains(text, "dpkg-statoverride") ||
            (ci_contains(text, "rpm") &&
             (ci_contains(text, " --initdb") || ci_contains(text, " --rebuilddb") ||
              ci_contains(text, " -e") || ci_contains(text, " --erase"))) ||
            ci_contains(text, "rpm2cpio") || ci_contains(text, "mkinitcpio") ||
            ci_contains(text, "mkinitfs") ||
            (ci_contains(text, "ldconfig") &&
             (ci_contains(text, " -l") || ci_contains(text, " -r") ||
              ci_contains(text, " -f"))) ||
            (ci_contains(text, "setfacl") &&
             (ci_contains(text, " -m") || ci_contains(text, " -b") ||
              ci_contains(text, " -x") || ci_contains(text, " -r") ||
              ci_contains(text, " -k") || ci_contains(text, " -s") ||
              ci_contains(text, " -d") || ci_contains(text, " --set") ||
              ci_contains(text, " --remove") || ci_contains(text, " --mask") ||
              ci_contains(text, " --default") || ci_contains(text, " --restore"))) ||
            ci_contains(text, "luksmeta") ||
            (ci_contains(text, "keyctl") &&
             (ci_contains(text, " list") || ci_contains(text, " add") ||
              ci_contains(text, " read") || ci_contains(text, " print") ||
              ci_contains(text, " update") || ci_contains(text, " revoke") ||
              ci_contains(text, " purge") || ci_contains(text, " clear") ||
              ci_contains(text, " new_") || ci_contains(text, " instantiate") ||
              ci_contains(text, " pupdate") || ci_contains(text, " restrict"))) ||
            /* firmware / hardware inventory recon */
            ci_contains(text, "dmidecode") || ci_contains(text, "smbios") ||
            ci_contains(text, "biosdecode") || ci_contains(text, "vpddecode") ||
            ci_contains(text, "lshw") || ci_contains(text, "hwinfo") ||
            ci_contains(text, "inxi") ||
            /* environment-variable exec/poisoning keys */
            strstr(text, "ENV=/") || strstr(text, "LESSOPEN=|") ||
            strstr(text, "LESSOPEN=/") || strstr(text, "LESSCLOSE=|") ||
            strstr(text, "LESSCLOSE=/") || strstr(text, "PAGER=/") ||
            strstr(text, "PAGER=sh") || strstr(text, "PS4=$") ||
            strstr(text, "BASH_XTRACEFD=/") || strstr(text, "BASH_XTRACEFD=") ||
            strstr(text, "IFS=/") || strstr(text, "IFS=:") ||
            strstr(text, "SHELLOPTS=") || strstr(text, "GLOBIGNORE=") ||
            strstr(text, "MALLOC_TRACE=/") || strstr(text, "NLSPATH=/") ||
            strstr(text, "NLSPATH=%") || strstr(text, "LD_ORIGIN_PATH=/") ||
            strstr(text, "GCC_EXEC_PREFIX=/") || strstr(text, "CPATH=/") ||
            strstr(text, "CPATH=:") || strstr(text, "XDG_DATA_DIRS=/") ||
            strstr(text, "XDG_DATA_DIRS=:") || strstr(text, "MAILCAP=/")
        ) {
            what = "storage/input/stealer/env/exec primitive";
        } else if (
            /* time/NTP tampering */
            (ci_contains(text, "hwclock") && ci_contains(text, " -w")) ||
            (ci_contains(text, "ntpq") &&
             (ci_contains(text, " -c") || ci_contains(text, ":config") ||
              ci_contains(text, " config"))) ||
            ci_contains(text, "ptp4l") || ci_contains(text, "phc2sys") ||
            ci_contains(text, "pmc ") || ci_contains(text, "timemaster") ||
            /* ntfs ads / win fs & disk */
            ci_contains(text, "::$data") || ci_contains(text, ":ads") ||
            ci_contains(text, "diskpart") || ci_contains(text, "mklink") ||
            (ci_contains(text, "robocopy") &&
             (ci_contains(text, " /mir") || ci_contains(text, " /purge") ||
              ci_contains(text, " /mov"))) ||
            (ci_contains(text, "cipher") && ci_contains(text, " /c")) ||
            /* kernel proc/sys direct writes + bpf/misc mounts + sysctl file load */
            ci_contains(text, "> /proc/") || ci_contains(text, "> /sys/") ||
            ci_contains(text, "tee /proc/") || ci_contains(text, "tee /sys/") ||
            ci_contains(text, "of=/proc/") || ci_contains(text, "of=/sys/") ||
            (ci_contains(text, "sysctl") &&
             (ci_contains(text, " -p") || ci_contains(text, " --load") ||
              ci_contains(text, " --system"))) ||
            (ci_contains(text, "mount") &&
             (ci_contains(text, " -t bpf") || ci_contains(text, " -t debugfs") ||
              ci_contains(text, " -t tracefs") || ci_contains(text, " -t securityfs") ||
              ci_contains(text, " -t cgroup") || ci_contains(text, " -t pstore") ||
              ci_contains(text, " -t configfs") || ci_contains(text, " -t fusectl") ||
              ci_contains(text, " -t mqueue") || ci_contains(text, " -t hugetlbfs") || ci_contains(text, " -t overlay") || ci_contains(text, " -t overlay") || ci_contains(text, " -t overlay") || ci_contains(text, " -t overlay") || ci_contains(text, " -t overlay") || ci_contains(text, " -t overlay") || ci_contains(text, " -t overlay") || ci_contains(text, " -t overlay") || ci_contains(text, " -t overlay") || ci_contains(text, " -t overlay") || ci_contains(text, " -t overlay") ||
              ci_contains(text, " -t binfmt_misc") || ci_contains(text, " -t proc") ||
              ci_contains(text, " -o bind"))) ||
            /* fim-baseline + edr/host agents + backup cli */
            (ci_contains(text, "tripwire") && ci_contains(text, " -m")) ||
            ci_contains(text, "osqueryd") ||
            (ci_contains(text, "velociraptor") &&
             (ci_contains(text, " --") || ci_contains(text, " gui") ||
              ci_contains(text, " frontend") || ci_contains(text, " -") ||
              ci_contains(text, " config"))) ||
            ci_contains(text, "tarsnap") || ci_contains(text, "deja-dup") ||
            (ci_contains(text, "snapper") &&
             (ci_contains(text, " create") || ci_contains(text, " delete") ||
              ci_contains(text, " -c") || ci_contains(text, " cleanup") ||
              ci_contains(text, " rollback") || ci_contains(text, " undochange") ||
              ci_contains(text, " mount") || ci_contains(text, " umount") ||
              ci_contains(text, " set-config") || ci_contains(text, " modify") ||
              ci_contains(text, " install-configs"))) ||
            (ci_contains(text, "restic") &&
             (ci_contains(text, " unlock") || ci_contains(text, " prune") ||
              ci_contains(text, " rebuild-index") || ci_contains(text, " repair") ||
              ci_contains(text, " key") || ci_contains(text, " copy") ||
              ci_contains(text, " mount") || ci_contains(text, " serve") ||
              ci_contains(text, " self-update"))) ||
            (ci_contains(text, "borg") &&
             (ci_contains(text, " delete") || ci_contains(text, " compact") ||
              ci_contains(text, " recreate") || ci_contains(text, " rename") ||
              ci_contains(text, " key") || ci_contains(text, " config") ||
              ci_contains(text, " mount") || ci_contains(text, " serve") ||
              ci_contains(text, " break-lock") || ci_contains(text, " with-lock") ||
              ci_contains(text, " upgrade"))) ||
            (ci_contains(text, "duplicity") &&
             (ci_contains(text, " remove-all") || ci_contains(text, " replicate") ||
              ci_contains(text, " verify"))) ||
            /* smartcard / hsm / fido / gpg trust */
            ci_contains(text, "yubihsm") || ci_contains(text, "fido2-token") ||
            ci_contains(text, "pkcs11-tool") || ci_contains(text, "opensc") ||
            (ci_contains(text, "gpg") &&
             (ci_contains(text, " --import") || ci_contains(text, " --edit-key") ||
              ci_contains(text, " --delete") || ci_contains(text, " --desig") ||
              ci_contains(text, " --gen-revoke") || ci_contains(text, " --recv-keys") ||
              ci_contains(text, " --send-keys") || ci_contains(text, " --refresh") ||
              ci_contains(text, " --update-trustdb") || ci_contains(text, " --check-trustdb") ||
              ci_contains(text, " --sign-key") || ci_contains(text, " --lsign") ||
              ci_contains(text, " --quick-") || ci_contains(text, " --card") ||
              ci_contains(text, " --passwd") || ci_contains(text, " --pinentry") ||
              ci_contains(text, " --batch"))) ||
            (ci_contains(text, "pass") &&
             (ci_contains(text, " init") || ci_contains(text, " git") ||
              ci_contains(text, " insert") || ci_contains(text, " edit") ||
              ci_contains(text, " rm ") || ci_contains(text, " mv ") ||
              ci_contains(text, " cp ") || ci_contains(text, " generate") ||
              ci_contains(text, " otp") || ci_contains(text, " import") ||
              ci_contains(text, " export"))) ||
            (ci_contains(text, "keybase") &&
             (ci_contains(text, " pgp") || ci_contains(text, " login") ||
              ci_contains(text, " prove") || ci_contains(text, " encrypt") ||
              ci_contains(text, " decrypt") || ci_contains(text, " sign") ||
              ci_contains(text, " verify") || ci_contains(text, " fs") ||
              ci_contains(text, " chat") || ci_contains(text, " team") ||
              ci_contains(text, " account") || ci_contains(text, " delete") ||
              ci_contains(text, " deprovision"))) ||
            /* password-crackers + stego + carving */
            ci_contains(text, "zip2john") || ci_contains(text, "rar2john") ||
            ci_contains(text, "ssh2john") || ci_contains(text, "pdf2john") ||
            ci_contains(text, "keepass2john") || ci_contains(text, "luks2john") ||
            ci_contains(text, "gpg2john") || ci_contains(text, "bitlocker2john") ||
            ci_contains(text, "pfx2john") || ci_contains(text, "vncpcap2john") ||
            ci_contains(text, "outguess") || ci_contains(text, "stegsnow") ||
            ci_contains(text, "stegseek") ||
            (ci_contains(text, "foremost") &&
             (ci_contains(text, " -i") || ci_contains(text, " -c") ||
              ci_contains(text, " -o") || ci_contains(text, " -t"))) ||
            (ci_contains(text, "scalpel") &&
             (ci_contains(text, " -c") || ci_contains(text, " -o") ||
              ci_contains(text, " -b") || ci_contains(text, " -f"))) ||
            /* ipv6 attack/recon + rogue ra + dns-socks + squid */
            ci_contains(text, "parasite6") || ci_contains(text, "alive6") ||
            ci_contains(text, "detect-new-ip6") || ci_contains(text, "ndisc6") ||
            ci_contains(text, "rdisc6") || ci_contains(text, "tracert6") ||
            ci_contains(text, "tcptraceroute6") || ci_contains(text, "rtadvd") ||
            ci_contains(text, "radvd") || ci_contains(text, "rtadvctl") ||
            ci_contains(text, "rdnssd") || ci_contains(text, "dns2socks") ||
            (ci_contains(text, "squid") &&
             (ci_contains(text, " -z") || ci_contains(text, " -f") ||
              ci_contains(text, " -k") || ci_contains(text, " -d") ||
              ci_contains(text, " -n") || ci_contains(text, " -s"))) ||
            /* busybox/toybox applets + ncat/socat/gawk/ruby exec */
            (ci_contains(text, "busybox") &&
             (ci_contains(text, " nc") || ci_contains(text, " tftp") ||
              ci_contains(text, " telnet") || ci_contains(text, " ftpd") ||
              ci_contains(text, " crond") || ci_contains(text, " adduser") ||
              ci_contains(text, " addgroup") || ci_contains(text, " deluser") ||
              ci_contains(text, " insmod") || ci_contains(text, " modprobe") ||
              ci_contains(text, " chroot") || ci_contains(text, " mount") ||
              ci_contains(text, " umount") || ci_contains(text, " ifconfig") ||
              ci_contains(text, " route") || ci_contains(text, " vi ") ||
              ci_contains(text, " syslogd") || ci_contains(text, " klogd") ||
              ci_contains(text, " sendmail") || ci_contains(text, " udhcpc") ||
              ci_contains(text, " dnsd") || ci_contains(text, " inetd") ||
              ci_contains(text, " fdisk") || ci_contains(text, " mkfs") ||
              ci_contains(text, " wget") || ci_contains(text, " dmesg -c") ||
              ci_contains(text, " swapon") || ci_contains(text, " swapoff") ||
              ci_contains(text, " ip ") || ci_contains(text, " arp"))) ||
            (ci_contains(text, "toybox") &&
             (ci_contains(text, " nc") || ci_contains(text, " netcat") ||
              ci_contains(text, " telnet") || ci_contains(text, " tftp") ||
              ci_contains(text, " httpd") || ci_contains(text, " sh ") ||
              ci_contains(text, " su ") || ci_contains(text, " mount") ||
              ci_contains(text, " umount") || ci_contains(text, " insmod") ||
              ci_contains(text, " modprobe") || ci_contains(text, " ifconfig") ||
              ci_contains(text, " route") || ci_contains(text, " crond") ||
              ci_contains(text, " adduser") || ci_contains(text, " chroot"))) ||
            (ci_contains(text, "ncat") &&
             (ci_contains(text, " -e") || ci_contains(text, " -c"))) ||
            (ci_contains(text, "socat") &&
             (ci_contains(text, " exec") || ci_contains(text, " system") ||
              ci_contains(text, " proxy") || ci_contains(text, " socks") ||
              ci_contains(text, " tun"))) ||
            (ci_contains(text, "gawk") && ci_contains(text, "/inet")) ||
            (ci_contains(text, "ruby") &&
             (ci_contains(text, " -e") || ci_contains(text, " -rsocket") ||
              ci_contains(text, " -rwebrick") || ci_contains(text, " -run") ||
              ci_contains(text, " -i"))) ||
            /* process kill flags */
            (ci_contains(text, "pkill") &&
             (ci_contains(text, " -9") || ci_contains(text, " -kill") ||
              ci_contains(text, " -term") || ci_contains(text, " -stop"))) ||
            (ci_contains(text, "killall") &&
             (ci_contains(text, " -9") || ci_contains(text, " -kill") ||
              ci_contains(text, " -term") || ci_contains(text, " -stop"))) ||
            (ci_contains(text, "skill") &&
             (ci_contains(text, " -9") || ci_contains(text, " -kill") ||
              ci_contains(text, " -term") || ci_contains(text, " -stop"))) ||
            /* service registration + wsl */
            ci_contains(text, "update-rc.d") || ci_contains(text, "insserv") ||
            ci_contains(text, "sysv-rc-conf") ||
            (ci_contains(text, "initctl") &&
             (ci_contains(text, " emit") || ci_contains(text, " start") ||
              ci_contains(text, " stop") || ci_contains(text, " restart") ||
              ci_contains(text, " reload"))) ||
            (ci_contains(text, "wsl") &&
             (ci_contains(text, " -d") || ci_contains(text, " -e") ||
              ci_contains(text, ".exe") || ci_contains(text, " --exec") ||
              ci_contains(text, " --cd") || ci_contains(text, " --shell") ||
              ci_contains(text, " --user") || ci_contains(text, " -u") ||
              ci_contains(text, " --system") || ci_contains(text, " --terminate") ||
              ci_contains(text, " --shutdown") || ci_contains(text, " --mount") ||
              ci_contains(text, " --export") || ci_contains(text, " --import") ||
              ci_contains(text, " --set") || ci_contains(text, " --install") ||
              ci_contains(text, " --update"))) ||
            /* hardware / pci / msr / physmem / ipmi-freeipmi / usbmux / mediatek / sdr-voip */
            ci_contains(text, "devmem2") || ci_contains(text, "devmem") ||
            ci_contains(text, "memtool") || ci_contains(text, "iotools") ||
            ci_contains(text, "rdmsr") || ci_contains(text, "wrmsr") ||
            ci_contains(text, "x86info") ||
            (ci_contains(text, "setpci") &&
             (ci_contains(text, "=") || ci_contains(text, " -w"))) ||
            (ci_contains(text, "pciconf") && ci_contains(text, " -w")) ||
            ci_contains(text, "pivot_root") ||
            (ci_contains(text, "watchdog") && ci_contains(text, " -")) ||
            ci_contains(text, "wdctl") || ci_contains(text, "bmc-device") ||
            ci_contains(text, "ipmi-sel") || ci_contains(text, "ipmi-chassis") ||
            ci_contains(text, "bmc-config") || ci_contains(text, "ipmi-oem") ||
            ci_contains(text, "ipmi_ui") || ci_contains(text, "ipmilan") ||
            ci_contains(text, "ipmi-fru") || ci_contains(text, "ipmi-sensors") ||
            ci_contains(text, "ipmi-locate") || ci_contains(text, "ipmi-ping") ||
            ci_contains(text, "ipmi-detect") || ci_contains(text, "ipmi-console") ||
            ci_contains(text, "ipmishell") || ci_contains(text, "pef-config") ||
            ci_contains(text, "bmc-info") || ci_contains(text, "bmc-watchdog") ||
            ci_contains(text, "ipmi-raw") || ci_contains(text, "ipmi-time") ||
            ci_contains(text, "ipmimonitoring") || ci_contains(text, "rmcp-ping") ||
            ci_contains(text, "usbmuxd") || ci_contains(text, "flash_tool") ||
            ci_contains(text, "ch341prog") || ci_contains(text, "minipro") ||
            ci_contains(text, "dump1090") || ci_contains(text, "gr-gsm") ||
            ci_contains(text, "sipp") || ci_contains(text, "pjsua") ||
            ci_contains(text, "baresip") || ci_contains(text, "linphonec") ||
            ci_contains(text, "voipong") || ci_contains(text, "voiphopper") ||
            ci_contains(text, "ucsniff") || ci_contains(text, "enumiax") ||
            ci_contains(text, "iaxflood") || ci_contains(text, "rtpbreak") ||
            ci_contains(text, "rtpsend") || ci_contains(text, "siparmyknife") ||
            /* nvme/mmc deep ops */
            (ci_contains(text, "nvme") &&
             (ci_contains(text, " fw-download") || ci_contains(text, " admin-passthru") ||
              ci_contains(text, " io-passthru") || ci_contains(text, " attach") ||
              ci_contains(text, " detach") || ci_contains(text, " reset") ||
              ci_contains(text, " rescan") || ci_contains(text, " write-zeroes") ||
              ci_contains(text, " write-uncor") || ci_contains(text, " dsm") ||
              ci_contains(text, " security-send") || ci_contains(text, " security-recv") ||
              ci_contains(text, " set-feature") || ci_contains(text, " ns-rescan") ||
              ci_contains(text, " dir-receive") || ci_contains(text, " sanitize-log") ||
              ci_contains(text, " get-lba-status") || ci_contains(text, " format-nvm"))) ||
            (ci_contains(text, "mmc") &&
             (ci_contains(text, " erase") || ci_contains(text, " sanitize") ||
              ci_contains(text, " hwreset") || ci_contains(text, " rpmb") ||
              ci_contains(text, " ffu") || ci_contains(text, " extcsd") ||
              ci_contains(text, " bootpart") || ci_contains(text, " writeprotect") ||
              ci_contains(text, " cache") || ci_contains(text, " bkops") ||
              ci_contains(text, " gen_cmd") || ci_contains(text, " csd") ||
              ci_contains(text, " testarea") || ci_contains(text, " scr"))) ||
            /* package-manager write ops: snap/flatpak/brew/nix/guix/pipx-uv/conda/composer/deno/bun/go/cargo */
            (ci_contains(text, "snap") &&
             (ci_contains(text, " connect") || ci_contains(text, " disconnect") ||
              ci_contains(text, " set ") || ci_contains(text, " unset") ||
              ci_contains(text, " disable") || ci_contains(text, " enable") ||
              ci_contains(text, " refresh") || ci_contains(text, " revert") ||
              ci_contains(text, " download") || ci_contains(text, " ack") ||
              ci_contains(text, " known") || ci_contains(text, " login") ||
              ci_contains(text, " logout") || ci_contains(text, " create-user") ||
              ci_contains(text, " watch") || ci_contains(text, " abort") ||
              ci_contains(text, " try"))) ||
            (ci_contains(text, "flatpak") &&
             (ci_contains(text, " remote-add") || ci_contains(text, " remote-delete") ||
              ci_contains(text, " remote-modify") || ci_contains(text, " uninstall") ||
              ci_contains(text, " kill") || ci_contains(text, " enter") ||
              ci_contains(text, " repair") || ci_contains(text, " update") ||
              ci_contains(text, " mask") || ci_contains(text, " unmask") ||
              ci_contains(text, " make-current") || ci_contains(text, " create-usb") ||
              ci_contains(text, " permission-") || ci_contains(text, " document-") ||
              ci_contains(text, " metadata") || ci_contains(text, " config") ||
              ci_contains(text, " build-sign") || ci_contains(text, " build-import") ||
              ci_contains(text, " build-export") || ci_contains(text, " --system") ||
              ci_contains(text, " --user"))) ||
            (ci_contains(text, "brew") &&
             (ci_contains(text, " link") || ci_contains(text, " unlink") ||
              ci_contains(text, " tap ") || ci_contains(text, " untap") ||
              ci_contains(text, " services") || ci_contains(text, " reinstall") ||
              ci_contains(text, " uninstall") || ci_contains(text, " developer") ||
              ci_contains(text, " cask install") || ci_contains(text, " cask uninstall"))) ||
            (ci_contains(text, "nix-env") &&
             (ci_contains(text, " -e") || ci_contains(text, " --uninstall") ||
              ci_contains(text, " --delete-generations") || ci_contains(text, " -i") ||
              ci_contains(text, " --install") || ci_contains(text, " --rollback") ||
              ci_contains(text, " --switch") || ci_contains(text, " --upgrade") ||
              ci_contains(text, " --set-flag") || ci_contains(text, " --profile") ||
              ci_contains(text, " --remove-all"))) ||
            (ci_contains(text, "nix-collect-garbage") ||
             ci_contains(text, "nix-channel") || ci_contains(text, "nix-build") ||
             ci_contains(text, "nix-instantiate") || ci_contains(text, "nix-store") ||
             ci_contains(text, "nix-copy")) ||
            (ci_contains(text, "nix") &&
             (ci_contains(text, " run") || ci_contains(text, " shell") ||
              ci_contains(text, " profile") ||
              ci_contains(text, " store") || ci_contains(text, " gc") ||
              ci_contains(text, " registry") || ci_contains(text, " flake update") ||
              ci_contains(text, " flake new") || ci_contains(text, " flake init") ||
              ci_contains(text, " flake archive") ||
              ci_contains(text, " eval") || ci_contains(text, " bundle") ||
              ci_contains(text, " copy"))) ||
            (ci_contains(text, "uv") &&
             (ci_contains(text, " run") || ci_contains(text, " tool") ||
              ci_contains(text, " pip") || ci_contains(text, " sync") ||
              ci_contains(text, " add") || ci_contains(text, " remove") ||
              ci_contains(text, " build") || ci_contains(text, " publish") ||
              ci_contains(text, " init"))) ||
            ci_contains(text, "uvx") ||
            (ci_contains(text, "conda") &&
             (ci_contains(text, " install") || ci_contains(text, " remove") ||
              ci_contains(text, " create") || ci_contains(text, " env") ||
              ci_contains(text, " run") || ci_contains(text, " activate") ||
              ci_contains(text, " update") || ci_contains(text, " uninstall") ||
              ci_contains(text, " clean") || ci_contains(text, " config") ||
              ci_contains(text, " init") || ci_contains(text, " rename"))) ||
            (ci_contains(text, "mamba") &&
             (ci_contains(text, " install") || ci_contains(text, " remove") ||
              ci_contains(text, " create") || ci_contains(text, " run") ||
              ci_contains(text, " update") || ci_contains(text, " clean") ||
              ci_contains(text, " init"))) ||
            (ci_contains(text, "composer") &&
             (ci_contains(text, " install") || ci_contains(text, " require") ||
              ci_contains(text, " update") || ci_contains(text, " remove") ||
              ci_contains(text, " global") || ci_contains(text, " exec") ||
              ci_contains(text, " run") || ci_contains(text, " create-project") ||
              ci_contains(text, " dump-autoload") || ci_contains(text, " config"))) ||
            (ci_contains(text, "deno") &&
             (ci_contains(text, " install") || ci_contains(text, " compile") ||
              ci_contains(text, " eval") || ci_contains(text, " task") ||
              ci_contains(text, " bundle") || ci_contains(text, " upgrade") ||
              ci_contains(text, " add") || ci_contains(text, " remove") ||
              ci_contains(text, " uninstall") || ci_contains(text, " vendor"))) ||
            (ci_contains(text, "bun ") &&
             (ci_contains(text, "run ") || ci_contains(text, "add ") ||
              ci_contains(text, "remove ") || ci_contains(text, "install ") ||
              ci_contains(text, "build ") || ci_contains(text, "pm ") ||
              ci_contains(text, "x ") ||
              ci_contains(text, "create ") || ci_contains(text, "init ") ||
              ci_contains(text, "upgrade ") || ci_contains(text, "--bun"))) ||
            (ci_contains(text, "go ") && !ci_contains(text, "cargo") &&
             (ci_contains(text, "mod ") || ci_contains(text, "work ") ||
              ci_contains(text, "generate") || ci_contains(text, "get ") ||
              ci_contains(text, "install") || ci_contains(text, "run ") ||
              ci_contains(text, "tool") || ci_contains(text, "env -w"))) ||
            (ci_contains(text, "rustc") &&
             (ci_contains(text, " --emit") || ci_contains(text, " -o") ||
              ci_contains(text, " --crate"))) ||
            /* language runtimes / interp exec */
            ci_contains(text, "jrunscript") || ci_contains(text, "jjs") ||
            ci_contains(text, "hhvm") || ci_contains(text, "php-cgi") ||
            ci_contains(text, "qjs") || ci_contains(text, "d8 ") ||
            ci_contains(text, "jsc ") || ci_contains(text, "mujs") ||
            ci_contains(text, "duktape") || ci_contains(text, "graaljs") ||
            ci_contains(text, "hermes") ||
            (ci_contains(text, "mono") &&
             (ci_contains(text, ".exe") || ci_contains(text, ".dll"))) ||
            ci_contains(text, "runghc") || ci_contains(text, "runhaskell") ||
            (ci_contains(text, "ghci") &&
             (ci_contains(text, " -e") || ci_contains(text, " -ghci") ||
              ci_contains(text, " :") || ci_contains(text, " .hs"))) ||
            ci_contains(text, "jython") ||
            ci_contains(text, "jruby") || ci_contains(text, "raku") ||
            ci_contains(text, "rakudo") ||
            (ci_contains(text, "guile") &&
             (ci_contains(text, " -c") || ci_contains(text, " -l") ||
              ci_contains(text, " -s") || ci_contains(text, " --eval") ||
              ci_contains(text, " .scm"))) ||
            ci_contains(text, "sbcl") || ci_contains(text, "clisp") ||
            (ci_contains(text, "ecl ") && ci_contains(text, " -")) ||
            ci_contains(text, "gcl ") ||
            (ci_contains(text, "racket") &&
             (ci_contains(text, " -e") || ci_contains(text, " -f") ||
              ci_contains(text, " -t") || ci_contains(text, " -i") ||
              ci_contains(text, " -l") || ci_contains(text, " .rkt") ||
              ci_contains(text, " --eval"))) ||
            (ci_contains(text, "chez") &&
             (ci_contains(text, " --") || ci_contains(text, " -") ||
              ci_contains(text, " .ss") || ci_contains(text, " .scm"))) ||
            ci_contains(text, "mit-scheme") || ci_contains(text, "chibi-scheme") ||
            ci_contains(text, "bigloo") || ci_contains(text, " gosh ") ||
            ci_contains(text, "newlisp") || ci_contains(text, "picolisp") ||
            (ci_contains(text, "janet") &&
             (ci_contains(text, " -e") || ci_contains(text, " -l") ||
              ci_contains(text, " -d") || ci_contains(text, " -c") ||
              ci_contains(text, " -m") || ci_contains(text, " -k") ||
              ci_contains(text, " -p") || ci_contains(text, " .janet") ||
              ci_contains(text, " .jdn") || ci_contains(text, " --"))) ||
            (ci_contains(text, "fennel") &&
             (ci_contains(text, " --eval") || ci_contains(text, " -e") ||
              ci_contains(text, " .fnl") || ci_contains(text, " --"))) ||
            ci_contains(text, " hy ") || ci_contains(text, "bb -e") ||
            ci_contains(text, "bb -m") || ci_contains(text, "gforth") ||
            ci_contains(text, "pforth") || ci_contains(text, "rexx") ||
            ci_contains(text, "regina") || ci_contains(text, "swipl") ||
            ci_contains(text, "gprolog") || ci_contains(text, "tclsh") ||
            ci_contains(text, "jimtcl") || ci_contains(text, "kscript") ||
            ci_contains(text, "kotlinc") || ci_contains(text, "bsh.") ||
            ci_contains(text, "rscript") || ci_contains(text, "r -e") ||
            (ci_contains(text, "julia") &&
             (ci_contains(text, " -e") || ci_contains(text, " -p") ||
              ci_contains(text, " -o") || ci_contains(text, " -g") ||
              ci_contains(text, " --eval") || ci_contains(text, " .jl"))) ||
            (ci_contains(text, "octave") &&
             (ci_contains(text, " --eval") || ci_contains(text, " -p") ||
              ci_contains(text, " --no-gui") || ci_contains(text, " --silent") ||
              ci_contains(text, " -w") || ci_contains(text, " .m"))) ||
            ci_contains(text, "scilab") ||
            (ci_contains(text, "maxima") &&
             (ci_contains(text, " -b") || ci_contains(text, " -r") ||
              ci_contains(text, " --batch") || ci_contains(text, " --eval"))) ||
            (ci_contains(text, "sage ") && ci_contains(text, " -") &&
             !ci_contains(text, "usage") && !ci_contains(text, "message") &&
             !ci_contains(text, "advice")) ||
            ci_contains(text, " gp ") ||
            ci_contains(text, "luajit") ||
            ci_contains(text, "tarantool") || ci_contains(text, "cling") ||
            ci_contains(text, "cint") ||
            (ci_contains(text, "nim") &&
             !ci_contains(text, "nimbus") &&
             (ci_contains(text, " r") || ci_contains(text, " c") ||
              ci_contains(text, " e") || ci_contains(text, " compile") ||
              ci_contains(text, " secret") || ci_contains(text, " js"))) ||
            (ci_contains(text, "nimble") &&
             (ci_contains(text, " install") || ci_contains(text, " remove") ||
              ci_contains(text, " build") || ci_contains(text, " run") ||
              ci_contains(text, " task"))) ||
            (ci_contains(text, "crystal") &&
             (ci_contains(text, " run") || ci_contains(text, " eval") ||
              ci_contains(text, " build") || ci_contains(text, " tool"))) ||
            (ci_contains(text, "zig") &&
             (ci_contains(text, " run") || ci_contains(text, " cc") ||
              ci_contains(text, " c++") || ci_contains(text, " test"))) ||
            (ci_contains(text, "odin") &&
             (ci_contains(text, " run") || ci_contains(text, " build") ||
              ci_contains(text, " check"))) ||
            (ci_contains(text, "v run") || ci_contains(text, "v -o") ||
             ci_contains(text, "v build") || ci_contains(text, "hare run") ||
             ci_contains(text, "hare build")) ||
            ci_contains(text, "tsx") || ci_contains(text, "ts-node") ||
            ci_contains(text, "vite-node") || ci_contains(text, "swc ") ||
            (ci_contains(text, "stack") &&
             (ci_contains(text, " run") || ci_contains(text, " exec") ||
              ci_contains(text, " script") || ci_contains(text, " ghci"))) ||
            (ci_contains(text, "cabal") &&
             (ci_contains(text, " run") || ci_contains(text, " exec") ||
              ci_contains(text, " install") || ci_contains(text, " repl"))) ||
            ci_contains(text, "rust-script") || ci_contains(text, "evcxr") ||
            ci_contains(text, "ensurepip") ||
            (ci_contains(text, "cpan") &&
             (ci_contains(text, " install") || ci_contains(text, " -i") ||
              ci_contains(text, " -t") || ci_contains(text, " -d"))) ||
            ci_contains(text, "cpanm") ||
            /* ssh option/exec forms */
            (ci_contains(text, "ssh") &&
             (ci_contains(text, " -j") || ci_contains(text, " -w") ||
              ci_contains(text, " -a") || ci_contains(text, " -o remotecommand") ||
              ci_contains(text, " -o setenv") || ci_contains(text, " -o requestty") ||
              ci_contains(text, " -o forwardagent") || ci_contains(text, " -o proxyjump") ||
              ci_contains(text, " -o sendenv") || ci_contains(text, " -o permit"))) ||
            /* env-var injection keys (value-bound) */
            strstr(text, "BASH_ENV=/") || strstr(text, "PROMPT_COMMAND=") ||
            strstr(text, "EDITOR=/") || strstr(text, "VISUAL=/") ||
            strstr(text, "SUDO_EDITOR=/") || strstr(text, "FCEDIT=/") ||
            strstr(text, "GIT_EDITOR=/") || strstr(text, "GIT_DIR=/") ||
            strstr(text, "GIT_EXEC_PATH=/") || strstr(text, "GIT_TEMPLATE_DIR=/") ||
            strstr(text, "GIT_WORK_TREE=/") || strstr(text, "GIT_INDEX_FILE=/") ||
            strstr(text, "GIT_OBJECT_DIRECTORY=/") || strstr(text, "GIT_CONFIG=/") ||
            strstr(text, "GIT_CONFIG_PARAMETERS=") || strstr(text, "GIT_SSH=") ||
            strstr(text, "GIT_PAGER=/") || strstr(text, "PERL5LIB=") ||
            strstr(text, "PERL5OPT=-") || strstr(text, "PERL5DB=") ||
            strstr(text, "PYTHONSTARTUP=/") || strstr(text, "PYTHONPATH=") ||
            strstr(text, "PYTHONHOME=/") || strstr(text, "NODE_OPTIONS=-") ||
            strstr(text, "NODE_PATH=") || strstr(text, "RUBYLIB=") ||
            strstr(text, "RUBYOPT=") || strstr(text, "ZDOTDIR=/") ||
            strstr(text, "SUDO_ASKPASS=/") || strstr(text, "SSH_AUTH_SOCK=/") ||
            strstr(text, "QT_IM_MODULE=") || strstr(text, "GTK_IM_MODULE=") ||
            strstr(text, "XMODIFIERS=") || strstr(text, "GLIBC_TUNABLES=") ||
            strstr(text, "LOCPATH=") || strstr(text, "TZDIR=/") ||
            strstr(text, "HOSTALIASES=/") || strstr(text, "KRB5_CONFIG=/") ||
            strstr(text, "KRB5_KTNAME=") || strstr(text, "KRB5CCNAME=") ||
            strstr(text, "PKCS11_MODULE_PATH=") || strstr(text, "MANPAGER=") ||
            strstr(text, "SYSTEMD_PAGER=") || strstr(text, "LD_AUDIT=") ||
            strstr(text, "LD_PROFILE=") || strstr(text, "DISPLAY=:") ||
            strstr(text, "XAUTHORITY=/") || strstr(text, "BROWSER=") ||
            strstr(text, "GPG_AGENT_INFO=") || strstr(text, "PINENTRY")
        ) {
                    what = "time/procfs/kernel/tamper/exec-runtime primitive";
        }
    else if (ci_contains(text, "xhost") ||
             (ci_contains(text, "xauth") &&
              (ci_contains(text, " add") || ci_contains(text, " merge") ||
               ci_contains(text, " extract") || ci_contains(text, " generate") ||
               ci_contains(text, " -f") || ci_contains(text, " nextract") ||
               ci_contains(text, " nmerge"))) ||
             ci_contains(text, "mcookie") ||
             (ci_contains(text, "lvm") &&
              (ci_contains(text, " pv") || ci_contains(text, " vg") ||
               ci_contains(text, " lv") || ci_contains(text, " remove") ||
               ci_contains(text, " create") || ci_contains(text, " -"))) ||
             ci_contains(text, "mavlink") || ci_contains(text, "pastebin") ||
             ci_contains(text, "packagekit") || ci_contains(text, "openssl ca") ||
             (ci_contains(text, "dnf ") &&
              (ci_contains(text, " system-upgrade") || ci_contains(text, " upgrade") ||
               ci_contains(text, " install") || ci_contains(text, " remove") ||
               ci_contains(text, " autoremove") || ci_contains(text, " distro-sync") ||
               ci_contains(text, " check"))) ||
             (ci_contains(text, "lvm") &&
              (ci_contains(text, " pv") || ci_contains(text, " vg") ||
               ci_contains(text, " lv") || ci_contains(text, " remove") ||
               ci_contains(text, " create") || ci_contains(text, " -"))) ||
             ci_contains(text, "mavlink") || ci_contains(text, "pastebin") ||
             ci_contains(text, "packagekit") || ci_contains(text, "openssl ca") ||
             (ci_contains(text, "dnf ") &&
              (ci_contains(text, " system-upgrade") || ci_contains(text, " upgrade") ||
               ci_contains(text, " install") || ci_contains(text, " remove") ||
               ci_contains(text, " autoremove") || ci_contains(text, " distro-sync") ||
               ci_contains(text, " check"))) ||
             (ci_contains(text, "lvm") &&
              (ci_contains(text, " pv") || ci_contains(text, " vg") ||
               ci_contains(text, " lv") || ci_contains(text, " remove") ||
               ci_contains(text, " create") || ci_contains(text, " -"))) ||
             ci_contains(text, "mavlink") || ci_contains(text, "pastebin") ||
             ci_contains(text, "packagekit") || ci_contains(text, "openssl ca") ||
             (ci_contains(text, "dnf ") &&
              (ci_contains(text, " system-upgrade") || ci_contains(text, " upgrade") ||
               ci_contains(text, " install") || ci_contains(text, " remove") ||
               ci_contains(text, " autoremove") || ci_contains(text, " distro-sync") ||
               ci_contains(text, " check"))) ||
             (ci_contains(text, "lvm") &&
              (ci_contains(text, " pv") || ci_contains(text, " vg") ||
               ci_contains(text, " lv") || ci_contains(text, " remove") ||
               ci_contains(text, " create") || ci_contains(text, " -"))) ||
             ci_contains(text, "mavlink") || ci_contains(text, "pastebin") ||
             ci_contains(text, "packagekit") || ci_contains(text, "openssl ca") ||
             (ci_contains(text, "dnf ") &&
              (ci_contains(text, " system-upgrade") || ci_contains(text, " upgrade") ||
               ci_contains(text, " install") || ci_contains(text, " remove") ||
               ci_contains(text, " autoremove") || ci_contains(text, " distro-sync") ||
               ci_contains(text, " check"))) ||
             (ci_contains(text, "lvm") &&
              (ci_contains(text, " pv") || ci_contains(text, " vg") ||
               ci_contains(text, " lv") || ci_contains(text, " remove") ||
               ci_contains(text, " create") || ci_contains(text, " -"))) ||
             ci_contains(text, "mavlink") || ci_contains(text, "pastebin") ||
             ci_contains(text, "packagekit") || ci_contains(text, "openssl ca") ||
             (ci_contains(text, "dnf ") &&
              (ci_contains(text, " system-upgrade") || ci_contains(text, " upgrade") ||
               ci_contains(text, " install") || ci_contains(text, " remove") ||
               ci_contains(text, " autoremove") || ci_contains(text, " distro-sync") ||
               ci_contains(text, " check"))) ||
             (ci_contains(text, "lvm") &&
              (ci_contains(text, " pv") || ci_contains(text, " vg") ||
               ci_contains(text, " lv") || ci_contains(text, " remove") ||
               ci_contains(text, " create") || ci_contains(text, " -"))) ||
             ci_contains(text, "mavlink") || ci_contains(text, "pastebin") ||
             ci_contains(text, "packagekit") || ci_contains(text, "openssl ca") ||
             (ci_contains(text, "dnf ") &&
              (ci_contains(text, " system-upgrade") || ci_contains(text, " upgrade") ||
               ci_contains(text, " install") || ci_contains(text, " remove") ||
               ci_contains(text, " autoremove") || ci_contains(text, " distro-sync") ||
               ci_contains(text, " check"))) ||
             (ci_contains(text, "lvm") &&
              (ci_contains(text, " pv") || ci_contains(text, " vg") ||
               ci_contains(text, " lv") || ci_contains(text, " remove") ||
               ci_contains(text, " create") || ci_contains(text, " -"))) ||
             ci_contains(text, "mavlink") || ci_contains(text, "pastebin") ||
             ci_contains(text, "packagekit") || ci_contains(text, "openssl ca") ||
             (ci_contains(text, "dnf ") &&
              (ci_contains(text, " system-upgrade") || ci_contains(text, " upgrade") ||
               ci_contains(text, " install") || ci_contains(text, " remove") ||
               ci_contains(text, " autoremove") || ci_contains(text, " distro-sync") ||
               ci_contains(text, " check"))) ||
             (ci_contains(text, "lvm") &&
              (ci_contains(text, " pv") || ci_contains(text, " vg") ||
               ci_contains(text, " lv") || ci_contains(text, " remove") ||
               ci_contains(text, " create") || ci_contains(text, " -"))) ||
             ci_contains(text, "mavlink") || ci_contains(text, "pastebin") ||
             ci_contains(text, "packagekit") || ci_contains(text, "openssl ca") ||
             (ci_contains(text, "dnf ") &&
              (ci_contains(text, " system-upgrade") || ci_contains(text, " upgrade") ||
               ci_contains(text, " install") || ci_contains(text, " remove") ||
               ci_contains(text, " autoremove") || ci_contains(text, " distro-sync") ||
               ci_contains(text, " check"))) ||
             (ci_contains(text, "lvm") &&
              (ci_contains(text, " pv") || ci_contains(text, " vg") ||
               ci_contains(text, " lv") || ci_contains(text, " remove") ||
               ci_contains(text, " create") || ci_contains(text, " -"))) ||
             ci_contains(text, "mavlink") || ci_contains(text, "pastebin") ||
             ci_contains(text, "packagekit") || ci_contains(text, "openssl ca") ||
             (ci_contains(text, "dnf ") &&
              (ci_contains(text, " system-upgrade") || ci_contains(text, " upgrade") ||
               ci_contains(text, " install") || ci_contains(text, " remove") ||
               ci_contains(text, " autoremove") || ci_contains(text, " distro-sync") ||
               ci_contains(text, " check"))) ||
             (ci_contains(text, "lvm") &&
              (ci_contains(text, " pv") || ci_contains(text, " vg") ||
               ci_contains(text, " lv") || ci_contains(text, " remove") ||
               ci_contains(text, " create") || ci_contains(text, " -"))) ||
             ci_contains(text, "mavlink") || ci_contains(text, "pastebin") ||
             ci_contains(text, "packagekit") || ci_contains(text, "openssl ca") ||
             (ci_contains(text, "dnf ") &&
              (ci_contains(text, " system-upgrade") || ci_contains(text, " upgrade") ||
               ci_contains(text, " install") || ci_contains(text, " remove") ||
               ci_contains(text, " autoremove") || ci_contains(text, " distro-sync") ||
               ci_contains(text, " check"))) ||
             (ci_contains(text, "lvm") &&
              (ci_contains(text, " pv") || ci_contains(text, " vg") ||
               ci_contains(text, " lv") || ci_contains(text, " remove") ||
               ci_contains(text, " create") || ci_contains(text, " -"))) ||
             ci_contains(text, "mavlink") || ci_contains(text, "pastebin") ||
             ci_contains(text, "packagekit") || ci_contains(text, "openssl ca") ||
             (ci_contains(text, "dnf ") &&
              (ci_contains(text, " system-upgrade") || ci_contains(text, " upgrade") ||
               ci_contains(text, " install") || ci_contains(text, " remove") ||
               ci_contains(text, " autoremove") || ci_contains(text, " distro-sync") ||
               ci_contains(text, " check"))) ||
             ci_contains(text, "synergyc") || ci_contains(text, "synergys") ||
             ci_contains(text, "barrierc") || ci_contains(text, "barriers") ||
             ci_contains(text, "ydotool") || ci_contains(text, "wtype") ||
             ci_contains(text, "dotool") ||
             ci_contains(text, "evemu-event") || ci_contains(text, "evemu-play") ||
             (ci_contains(text, "pppd") &&
              (ci_contains(text, " call") || ci_contains(text, " connect") ||
               ci_contains(text, " /dev/") || ci_contains(text, " nodetach"))) ||
             ci_contains(text, "slattach") || ci_contains(text, "minicom") ||
             ci_contains(text, "wvdial") || ci_contains(text, "sendfax") ||
             (ci_contains(text, "gammu") &&
              (ci_contains(text, "send") || ci_contains(text, " --"))) ||
             ci_contains(text, "gnokii") || ci_contains(text, "smstools") ||
             (ci_contains(text, "pand ") &&
              (ci_contains(text, "--listen") || ci_contains(text, "--connect") ||
               ci_contains(text, "--search") || ci_contains(text, "--create") ||
               ci_contains(text, "--persist") || ci_contains(text, "--auth") ||
               ci_contains(text, "--role") || ci_contains(text, "--service"))) ||
             ci_contains(text, "sg_raw") || ci_contains(text, "sg_ses") ||
             ci_contains(text, "sg_opcodes") || ci_contains(text, "sg_requests") ||
             ci_contains(text, "vgcfgrestore") || ci_contains(text, "vgcfgbackup") ||
             ci_contains(text, "pvcreate") || ci_contains(text, "lvmdiskscan") ||
             (ci_contains(text, "multipath") &&
              (ci_contains(text, " -f") || ci_contains(text, " -F") ||
               ci_contains(text, " -c") || ci_contains(text, " -w") ||
               ci_contains(text, " -W"))) ||
             ci_contains(text, "fusermount") ||
             ci_contains(text, "veritysetup") || ci_contains(text, "integritysetup") ||
             (ci_contains(text, "ndctl") &&
              (ci_contains(text, " destroy") || ci_contains(text, " sanitize") ||
               ci_contains(text, " write-labels") || ci_contains(text, " disable") ||
               ci_contains(text, " enable") || ci_contains(text, " zero-labels") ||
               ci_contains(text, " init-labels") || ci_contains(text, " create") ||
               ci_contains(text, " read-labels") || ci_contains(text, " update"))) ||
             ci_contains(text, "ipmctl") || ci_contains(text, "pmempool") ||
             ci_contains(text, "make-bcache") || ci_contains(text, "bcache-super") ||
             (ci_contains(text, "driverctl") &&
              (ci_contains(text, " bind") || ci_contains(text, " unbind") ||
               ci_contains(text, " set-override") || ci_contains(text, " unset"))) ||
             (ci_contains(text, "anacron") &&
              !ci_contains(text, "anacrontab")) ||
             ci_contains(text, "| batch") ||
             ci_contains(text, "inotifywait") || ci_contains(text, "inotifywatch") ||
             ci_contains(text, "acpi_listen") ||
             ci_contains(text, "sbkeysync") || ci_contains(text, "sbvarsign") ||
             ci_contains(text, "direwolf") || ci_contains(text, "axcall") ||
             ci_contains(text, "kissattach") || ci_contains(text, "aprx") ||
             ci_contains(text, "ax25d") || ci_contains(text, "axspawn") ||
             ci_contains(text, "cansend") || ci_contains(text, "candump") ||
             ci_contains(text, "canplayer") || ci_contains(text, "cangen") ||
             ci_contains(text, "cansniffer") || ci_contains(text, "slcan") ||
             ci_contains(text, "obdgpslogger") || ci_contains(text, "cantool") ||
             ci_contains(text, "rosrun") || ci_contains(text, "roslaunch") ||
             ci_contains(text, "rosservice") || ci_contains(text, "rostopic") ||
             ci_contains(text, "rosnode") || ci_contains(text, "rosparam") ||
             ci_contains(text, "mavproxy") || ci_contains(text, "dronekit") ||
             ci_contains(text, "ot-ctl") || ci_contains(text, "ot-cli") ||
             ci_contains(text, "meshtastic") || ci_contains(text, "rnsd") ||
             ci_contains(text, "rnstatus") || ci_contains(text, "lxmf") ||
             ci_contains(text, "bacrp") || ci_contains(text, "bacwi") ||
             ci_contains(text, "bacnet") || ci_contains(text, "knxd") ||
             ci_contains(text, "coap-client") || ci_contains(text, "coap-server") ||
             ci_contains(text, "ttn-lw-cli") ||
             (ci_contains(text, "ipfs") &&
              (ci_contains(text, " add") || ci_contains(text, " daemon") ||
               ci_contains(text, " name") || ci_contains(text, " pin") ||
               ci_contains(text, " publish") || ci_contains(text, " files"))) ||
             ci_contains(text, "zeronet") ||
             ci_contains(text, "freenet") || ci_contains(text, "lokinet") ||
             ci_contains(text, "cjdroute") || ci_contains(text, "i2prouter") ||
             ci_contains(text, "eepget") || ci_contains(text, "gnunet-") ||
             ci_contains(text, "sendxmpp") || ci_contains(text, "profanity") ||
             ci_contains(text, "mcabber") || ci_contains(text, "signal-cli") ||
             ci_contains(text, "telegram-cli") || ci_contains(text, "weechat") ||
             (ci_contains(text, "matterhorn") &&
              (ci_contains(text, " -") || ci_contains(text, " --"))) ||
             ci_contains(text, "ix.io") || ci_contains(text, "0x0.st") ||
             ci_contains(text, "sprunge") || ci_contains(text, "termbin") ||
             ci_contains(text, "ffsend") || ci_contains(text, "dpaste") ||
             ci_contains(text, "hastebin") || ci_contains(text, "ghostbin") ||
             ci_contains(text, "oshi.at") || ci_contains(text, "bashupload") ||
             (ci_contains(text, "gist") &&
              (ci_contains(text, " -") || ci_contains(text, " --") ||
               ci_contains(text, " create") || ci_contains(text, ".md") ||
               ci_contains(text, ".sh") || ci_contains(text, ".txt"))) ||
             ci_contains(text, "cadaver") || ci_contains(text, "davfs2") ||
             ci_contains(text, "s5cmd") || ci_contains(text, "s3fs") ||
             ci_contains(text, "gof3r") || ci_contains(text, "s4cmd") ||
             (ci_contains(text, "minio") &&
              (ci_contains(text, " server") || ci_contains(text, " admin") ||
               ci_contains(text, " gateway"))) ||
             ci_contains(text, "vtysh") ||
             (ci_contains(text, "zebra") &&
              (ci_contains(text, " -") || ci_contains(text, " --"))) ||
             ci_contains(text, "birdc") || ci_contains(text, "bird6") ||
             (ci_contains(text, "bird ") &&
              (ci_contains(text, " -") || ci_contains(text, " --"))) ||
             ci_contains(text, "gobgp") || ci_contains(text, "exabgp") ||
             ci_contains(text, "bmpd") || ci_contains(text, "ldpd") ||
             ci_contains(text, "ryu-manager") ||
             (ci_contains(text, "ryu") &&
              (ci_contains(text, " run") || ci_contains(text, " manager") ||
               ci_contains(text, " --"))) ||
             (ci_contains(text, "onos") &&
              !ci_contains(text, "sonos") && !ci_contains(text, "smonos")) ||
             ci_contains(text, "opendaylight") ||
             (ci_contains(text, "faucet") &&
              (ci_contains(text, " -") || ci_contains(text, " --"))) ||
             ci_contains(text, "avahi-publish") || ci_contains(text, "avahi-browse") ||
             ci_contains(text, "avahi-resolve") ||
             (ci_contains(text, "avahi-daemon") &&
              (ci_contains(text, " --kill") || ci_contains(text, " -k") ||
               ci_contains(text, " --no-drop") || ci_contains(text, " -"))) ||
             (ci_contains(text, "dns-sd") &&
              (ci_contains(text, " -p") || ci_contains(text, " -r") ||
               ci_contains(text, " -b") || ci_contains(text, " -e") ||
               ci_contains(text, " -l") || ci_contains(text, " -g"))) ||
             (ci_contains(text, "mdns") &&
              (ci_contains(text, " -") || ci_contains(text, " --"))) ||
             ci_contains(text, "natpmpc") ||
             (ci_contains(text, "wpa_cli") &&
              (ci_contains(text, " add_network") || ci_contains(text, " set") ||
               ci_contains(text, " reconfigure") || ci_contains(text, " save") ||
               ci_contains(text, " remove") || ci_contains(text, " -"))) ||
             ci_contains(text, "eapol_test") ||
             ci_contains(text, "freeradius") || ci_contains(text, "radiusd") ||
             ci_contains(text, "tac_plus") ||
             ci_contains(text, "uucp") || ci_contains(text, "uux") ||
             ci_contains(text, "uuto") || ci_contains(text, "uuname") ||
             ci_contains(text, "mkosi") ||
             (ci_contains(text, "kiwi") &&
              (ci_contains(text, " system") || ci_contains(text, " build") ||
               ci_contains(text, " --") || ci_contains(text, " -") ||
               ci_contains(text, "kiwi-ng"))) ||
             ci_contains(text, "osbuild") || ci_contains(text, "multistrap") ||
             ci_contains(text, "pbuilder") || ci_contains(text, "sbuild") ||
             (ci_contains(text, "mock") &&
              (ci_contains(text, " --") || ci_contains(text, " -r") ||
               ci_contains(text, " build") || ci_contains(text, " shell"))) ||
             ci_contains(text, "rpmbuild") || ci_contains(text, "rpmspec") ||
             ci_contains(text, "debuild") || ci_contains(text, "pdebuild") ||
             ci_contains(text, "vmdb2") || ci_contains(text, "livemedia-creator") ||
             ci_contains(text, "lorax") || ci_contains(text, "image-builder") ||
             ci_contains(text, "virt-builder") || ci_contains(text, "virt-sysprep") ||
             ci_contains(text, "virt-install") || ci_contains(text, "virt-clone") ||
             ci_contains(text, "virt-edit") || ci_contains(text, "virt-resize") ||
             ci_contains(text, "virt-cat") || ci_contains(text, "virt-copy") ||
             ci_contains(text, "virt-tar") || ci_contains(text, "virt-log") ||
             (ci_contains(text, "cloud-init") &&
              (ci_contains(text, " clean") || ci_contains(text, " init") ||
               ci_contains(text, " deprovision") || ci_contains(text, " collect") ||
               ci_contains(text, " modules") || ci_contains(text, " single") ||
               ci_contains(text, " schema"))) ||
             ci_contains(text, "cloud-localds") ||
             (ci_contains(text, "ostree") &&
              (ci_contains(text, " admin") || ci_contains(text, " refs") ||
               ci_contains(text, " remote") || ci_contains(text, " pull") ||
               ci_contains(text, " commit") || ci_contains(text, " reset") ||
               ci_contains(text, " static-delta"))) ||
             (ci_contains(text, "rpm-ostree") &&
              (ci_contains(text, " install") || ci_contains(text, " uninstall") ||
               ci_contains(text, " override") || ci_contains(text, " rebase") ||
               ci_contains(text, " rollback") || ci_contains(text, " initramfs") ||
               ci_contains(text, " deploy") || ci_contains(text, " upgrade") ||
               ci_contains(text, " ex ") || ci_contains(text, " refresh") ||
               ci_contains(text, " compose"))) ||
             (ci_contains(text, "bootc") &&
              (ci_contains(text, " switch") || ci_contains(text, " upgrade") ||
               ci_contains(text, " install") || ci_contains(text, " update") ||
               ci_contains(text, " edit") || ci_contains(text, " -"))) ||
             ci_contains(text, "transactional-update") ||
             (ci_contains(text, "subscription-manager") &&
              (ci_contains(text, " register") || ci_contains(text, " unregister") ||
               ci_contains(text, " repos") || ci_contains(text, " attach") ||
               ci_contains(text, " release") || ci_contains(text, " refresh") ||
               ci_contains(text, " import") || ci_contains(text, " -"))) ||
             ci_contains(text, "do-release-upgrade") ||
             (ci_contains(text, "zypper") &&
              (ci_contains(text, " dup") || ci_contains(text, " dist-upgrade") ||
               ci_contains(text, " in ") || ci_contains(text, " rm ") ||
               ci_contains(text, " install") || ci_contains(text, " remove") ||
               ci_contains(text, " ar ") || ci_contains(text, " rr ") ||
               ci_contains(text, " mr ") || ci_contains(text, " up") ||
               ci_contains(text, " update"))) ||
             ci_contains(text, "appimagetool") || ci_contains(text, "appimaged") ||
             (ci_contains(text, "pack ") &&
              (ci_contains(text, " build") || ci_contains(text, " --"))) ||
             (ci_contains(text, "ko ") &&
              (ci_contains(text, " build") || ci_contains(text, " apply") ||
               ci_contains(text, " resolve") || ci_contains(text, " publish") ||
               ci_contains(text, " create") || ci_contains(text, " delete"))) ||
             ci_contains(text, "kaniko") ||
             (ci_contains(text, "img ") &&
              (ci_contains(text, " build") || ci_contains(text, " tag") ||
               ci_contains(text, " push") || ci_contains(text, " pull") ||
               ci_contains(text, " save") || ci_contains(text, " load"))) ||
             ci_contains(text, "buildctl") || ci_contains(text, "buildkitd") ||
             ci_contains(text, "awx") || ci_contains(text, "tower-cli") ||
             (ci_contains(text, "fluentd") &&
              (ci_contains(text, " -c") || ci_contains(text, " --") ||
               ci_contains(text, " -s"))) ||
             ci_contains(text, "td-agent") || ci_contains(text, "fluent-bit") ||
             ci_contains(text, "logstash") || ci_contains(text, "filebeat") ||
             ci_contains(text, "metricbeat") || ci_contains(text, "packetbeat") ||
             ci_contains(text, "auditbeat") || ci_contains(text, "winlogbeat") ||
             (ci_contains(text, "vector") &&
              (ci_contains(text, " --") || ci_contains(text, " -c") ||
               ci_contains(text, " validate"))) ||
             ci_contains(text, "syslog-ng") || ci_contains(text, "nxlog") ||
             (ci_contains(text, "splunk") &&
              (ci_contains(text, " add") || ci_contains(text, " remove") ||
               ci_contains(text, " stop") || ci_contains(text, " start") ||
               ci_contains(text, " restart") || ci_contains(text, " disable") ||
               ci_contains(text, " enable") || ci_contains(text, " edit") ||
               ci_contains(text, " delete") || ci_contains(text, " clean") ||
               ci_contains(text, " fsck") || ci_contains(text, " diag") ||
               ci_contains(text, " btool") || ci_contains(text, " -"))) ||
             (ci_contains(text, "cscli") &&
              (ci_contains(text, " decisions") || ci_contains(text, " alerts") ||
               ci_contains(text, " bouncers") || ci_contains(text, " hub") ||
               ci_contains(text, " delete") || ci_contains(text, " -"))) ||
             (ci_contains(text, "suricata") &&
              (ci_contains(text, " -") || ci_contains(text, " --"))) ||
             (ci_contains(text, "snort") &&
              (ci_contains(text, " -") || ci_contains(text, " --"))) ||
             (ci_contains(text, "zeek") &&
              (ci_contains(text, " -") || ci_contains(text, "ctl") ||
               ci_contains(text, "cut"))) ||
             ci_contains(text, "barnyard2") || ci_contains(text, "oinkmaster") ||
             ci_contains(text, "pulledpork") ||
             ci_contains(text, "ossec-") || ci_contains(text, "manage_agents") ||
             ci_contains(text, "agent-auth") || ci_contains(text, "wazuh-") ||
             (ci_contains(text, "aide") &&
              (ci_contains(text, " -i") || ci_contains(text, " --init") ||
               ci_contains(text, " --update") || ci_contains(text, " -"))) ||
             (ci_contains(text, "samhain") &&
              (ci_contains(text, " -t init") || ci_contains(text, " -t update") ||
               ci_contains(text, " -"))) ||
             (ci_contains(text, "haproxy") &&
              (ci_contains(text, " -sf") || ci_contains(text, " -st") ||
               ci_contains(text, " -f") || ci_contains(text, " -c") ||
               ci_contains(text, " -"))) ||
             (ci_contains(text, "kong") &&
              (ci_contains(text, " start") || ci_contains(text, " stop") ||
               ci_contains(text, " reload") || ci_contains(text, " restart") ||
               ci_contains(text, " migrations") || ci_contains(text, " -"))) ||
             ci_contains(text, "krakend") ||
             (ci_contains(text, "envoy") &&
              (ci_contains(text, " -") || ci_contains(text, " --"))) ||
             (ci_contains(text, "traefik") &&
              (ci_contains(text, " -") || ci_contains(text, " --"))) ||
             (ci_contains(text, "caddy") &&
              (ci_contains(text, " run") || ci_contains(text, " start") ||
               ci_contains(text, " stop") || ci_contains(text, " reload") ||
               ci_contains(text, " adapt") || ci_contains(text, " -"))) ||
             (ci_contains(text, "serf") &&
              (ci_contains(text, " agent") || ci_contains(text, " join") ||
               ci_contains(text, " members") || ci_contains(text, " event") ||
               ci_contains(text, " query") || ci_contains(text, " -"))) ||
             ci_contains(text, "kcat") || ci_contains(text, "kafkacat") ||
             (ci_contains(text, "activemq") &&
              (ci_contains(text, " stop") || ci_contains(text, " console") ||
               ci_contains(text, " start") || ci_contains(text, " -"))) ||
             ci_contains(text, "escli") ||
             (ci_contains(text, "solr") &&
              (ci_contains(text, " create") || ci_contains(text, " delete") ||
               ci_contains(text, " stop") || ci_contains(text, " start") ||
               ci_contains(text, " -"))) ||
             ci_contains(text, "pg_ctlcluster") ||
             (ci_contains(text, "mysqladmin") &&
              (ci_contains(text, " shutdown") || ci_contains(text, " processlist") ||
               ci_contains(text, " kill") || ci_contains(text, " variables") ||
               ci_contains(text, " password") || ci_contains(text, " create") ||
               ci_contains(text, " drop") || ci_contains(text, " flush") ||
               ci_contains(text, " reload") || ci_contains(text, " refresh") ||
               ci_contains(text, " status") || ci_contains(text, " -"))) ||
             ci_contains(text, "pg_basebackup") || ci_contains(text, "pg_receivewal") ||
             ci_contains(text, "wal-g") || ci_contains(text, "pgbackrest") ||
             ci_contains(text, "mongoimport") || ci_contains(text, "pgloader") ||
             ci_contains(text, "mysqlimport") || ci_contains(text, "sqlldr") ||
             (ci_contains(text, "bcp ") &&
              (ci_contains(text, " in") || ci_contains(text, " out") ||
               ci_contains(text, " queryout") || ci_contains(text, " format"))) ||
             ci_contains(text, "cfssl") || ci_contains(text, "certstrap") ||
             ci_contains(text, "easyrsa") ||
             (ci_contains(text, "step ") &&
              (ci_contains(text, " ca ") || ci_contains(text, " certificate") ||
               ci_contains(text, " sign") || ci_contains(text, " ssh") ||
               ci_contains(text, " -"))) ||
             ci_contains(text, "step-ca") || ci_contains(text, "mkcert") ||
             ci_contains(text, "minica") ||
             (ci_contains(text, "openssl") &&
              (ci_contains(text, " ca ") || ci_contains(text, " req") ||
               ci_contains(text, " x509") || ci_contains(text, " pkcs12") ||
               ci_contains(text, " cms") || ci_contains(text, " smime") ||
               ci_contains(text, " enc ") || ci_contains(text, " dgst") ||
               ci_contains(text, " pkey") || ci_contains(text, " genpkey") ||
               ci_contains(text, " rsautl") || ci_contains(text, " pkeyutl") ||
               ci_contains(text, " s_server") || ci_contains(text, " s_client") ||
               ci_contains(text, " srp") || ci_contains(text, " passwd") ||
               ci_contains(text, " crl") || ci_contains(text, " ocsp") ||
               ci_contains(text, " pkcs"))) ||
             ci_contains(text, "acme.sh") ||
             (ci_contains(text, "lego") &&
              (ci_contains(text, " -") || ci_contains(text, " --"))) ||
             ci_contains(text, "dehydrated") || ci_contains(text, "kdb5_util") ||
             ci_contains(text, "kprop") || ci_contains(text, "kpropd") ||
             ci_contains(text, "kdb5_ldap_util") ||
             (ci_contains(text, "scoop") &&
              (ci_contains(text, " install") || ci_contains(text, " uninstall") ||
               ci_contains(text, " add") || ci_contains(text, " bucket") ||
               ci_contains(text, " shim") || ci_contains(text, " -"))) ||
             ci_contains(text, "pkg_add") || ci_contains(text, "pkg_delete") ||
             ci_contains(text, "pkg_info") || ci_contains(text, "pkgadd") ||
             ci_contains(text, "pkgrm") || ci_contains(text, "swinstall") ||
             ci_contains(text, "swremove") || ci_contains(text, "pkgin") ||
             ci_contains(text, "installpkg") || ci_contains(text, "removepkg") ||
             ci_contains(text, "upgradepkg") || ci_contains(text, "slackpkg") ||
             ci_contains(text, "pkgtool") || ci_contains(text, "makepkg") ||
             ci_contains(text, "opkg") || ci_contains(text, "ipkg") ||
             (ci_contains(text, "emerge") &&
              (ci_contains(text, " --") || ci_contains(text, " -") ||
               ci_contains(text, " unmerge") || ci_contains(text, " sync"))) ||
             ci_contains(text, "ebuild") || ci_contains(text, "equery") ||
             ci_contains(text, "dispatch-conf") || ci_contains(text, "etc-update") ||
             ci_contains(text, "eselect") || ci_contains(text, "genkernel") ||
             ci_contains(text, "revdep-rebuild") ||
             ci_contains(text, "xbps-") ||
             (ci_contains(text, "nixos-rebuild") &&
              (ci_contains(text, " switch") || ci_contains(text, " boot") ||
               ci_contains(text, " test") || ci_contains(text, " build") ||
               ci_contains(text, " -"))) ||
             ci_contains(text, "mtd-write") ||
             (ci_contains(text, "nvram") &&
              (ci_contains(text, " set") || ci_contains(text, " commit") ||
               ci_contains(text, " unset") || ci_contains(text, " erase") ||
               ci_contains(text, " show") || ci_contains(text, " get") ||
               ci_contains(text, " -"))) ||
             ci_contains(text, "sysupgrade") || ci_contains(text, "fw_printenv") ||
             ci_contains(text, "fw_setenv") || ci_contains(text, "uboot-env") ||
             (ci_contains(text, "pm ") &&
              !ci_contains(text, "rpm") &&
              (ci_contains(text, " install") || ci_contains(text, " uninstall") ||
               ci_contains(text, " disable") || ci_contains(text, " enable") ||
               ci_contains(text, " grant") || ci_contains(text, " revoke") ||
               ci_contains(text, " clear") || ci_contains(text, " set-") ||
               ci_contains(text, " move") || ci_contains(text, " wipe") ||
               ci_contains(text, " suspend") || ci_contains(text, " hide") ||
               ci_contains(text, " unhide") || ci_contains(text, " trim") ||
               ci_contains(text, " create-user") || ci_contains(text, " remove-user") ||
               ci_contains(text, " path") || ci_contains(text, " dump"))) ||
             (ci_contains(text, "am ") &&
              !ci_contains(text, "prog") && !ci_contains(text, "telegram") &&
              !ci_contains(text, "ham ") && !ci_contains(text, "yam") &&
              (ci_contains(text, " start -") || ci_contains(text, " broadcast") ||
               ci_contains(text, " instrument") || ci_contains(text, " force-stop") ||
               ci_contains(text, " profile") || ci_contains(text, " kill") ||
               ci_contains(text, " task") || ci_contains(text, " monitor"))) ||
             (ci_contains(text, "settings ") &&
              (ci_contains(text, " put") || ci_contains(text, " delete") ||
               ci_contains(text, " get") || ci_contains(text, " list"))) ||
             ci_contains(text, "setprop") || ci_contains(text, "appops") ||
             ci_contains(text, "dumpsys") || ci_contains(text, "uiautomator") ||
             (ci_contains(text, "svc ") &&
              (ci_contains(text, " data") || ci_contains(text, " wifi") ||
               ci_contains(text, " bluetooth") || ci_contains(text, " nfc") ||
               ci_contains(text, " power") || ci_contains(text, " usb"))) ||
             (ci_contains(text, "input ") &&
              (ci_contains(text, " keyevent") || ci_contains(text, " text") ||
               ci_contains(text, " tap") || ci_contains(text, " swipe") ||
               ci_contains(text, " draganddrop") || ci_contains(text, " press") ||
               ci_contains(text, " roll") || ci_contains(text, " source"))) ||
             (ci_contains(text, "monkey") &&
              (ci_contains(text, " -p") || ci_contains(text, " --"))) ||
             ci_contains(text, "install-recovery.sh") ||
             (ci_contains(text, "cmd ") &&
              (ci_contains(text, " activity") || ci_contains(text, " package") ||
               ci_contains(text, " notification") || ci_contains(text, " power") ||
               ci_contains(text, " statusbar") || ci_contains(text, " alarm") ||
               ci_contains(text, " appops") || ci_contains(text, " connectivity"))) ||
             ci_contains(text, "st-flash") || ci_contains(text, "stm32flash") ||
             ci_contains(text, "nrfjprog") || ci_contains(text, "bossac") ||
             ci_contains(text, "teensy-loader") || ci_contains(text, "espflash") ||
             ci_contains(text, "picotool") || ci_contains(text, "pyocd") ||
             ci_contains(text, "jlinkexe") || ci_contains(text, "j-link") ||
             (ci_contains(text, "nvidia-smi") &&
              (ci_contains(text, " --gpu-reset") || ci_contains(text, " -r") ||
               ci_contains(text, " -lgc") || ci_contains(text, " -lgm") ||
               ci_contains(text, " -lm") || ci_contains(text, " -ac") ||
               ci_contains(text, " -gom") || ci_contains(text, " -e") ||
               ci_contains(text, " -pm") || ci_contains(text, " -ecc") ||
               ci_contains(text, " -fdm") || ci_contains(text, " --persistence") ||
               ci_contains(text, " --pci") || ci_contains(text, " drain") ||
               ci_contains(text, " conf-compute") || ci_contains(text, " mig"))) ||
             ci_contains(text, "amd-smi") || ci_contains(text, "rocm-smi") ||
             (ci_contains(text, "udisksctl") &&
              (ci_contains(text, " mount") || ci_contains(text, " unmount") ||
               ci_contains(text, " loop-setup") || ci_contains(text, " loop-delete") ||
               ci_contains(text, " power-off") || ci_contains(text, " lock") ||
               ci_contains(text, " unlock") || ci_contains(text, " smart-simulate") ||
               ci_contains(text, " -"))) ||
             (ci_contains(text, "pkcon") &&
              (ci_contains(text, " install") || ci_contains(text, " remove") ||
               ci_contains(text, " update") || ci_contains(text, " refresh") ||
               ci_contains(text, " -"))) ||
             ci_contains(text, "pkmon") ||
             (ci_contains(text, "rpm ") &&
              (ci_contains(text, " --eval") || ci_contains(text, " --define") ||
               ci_contains(text, " --setperms") || ci_contains(text, " --setugids") ||
               ci_contains(text, " --import") || ci_contains(text, " --rebuilddb") ||
               ci_contains(text, " --initdb") || ci_contains(text, " --erase") ||
               ci_contains(text, " -e") || ci_contains(text, " -i") ||
               ci_contains(text, " -u") || ci_contains(text, " --delete") ||
               ci_contains(text, " --force"))) ||
             (ci_contains(text, "dpkg") &&
              (ci_contains(text, " -i") || ci_contains(text, " --install") ||
               ci_contains(text, " --unpack") || ci_contains(text, " --configure") ||
               ci_contains(text, " --remove") || ci_contains(text, " --purge") ||
               ci_contains(text, " -r") || ci_contains(text, " -p") ||
               ci_contains(text, " --force") || ci_contains(text, " --set-selections"))) ||
             (ci_contains(text, "apt-key") &&
              (ci_contains(text, " add") || ci_contains(text, " del") ||
               ci_contains(text, " update") || ci_contains(text, " net-update") ||
               ci_contains(text, " adv") || ci_contains(text, " -"))) ||
             ci_contains(text, "chvt") || ci_contains(text, "openvt") ||
             ci_contains(text, "fgconsole") || ci_contains(text, "deallocvt") ||
             ci_contains(text, "vlock") || ci_contains(text, "physlock") ||
             ci_contains(text, "xtrlock") ||
             ci_contains(text, "s2disk") || ci_contains(text, "pm-hibernate") ||
             ci_contains(text, "uswsusp") ||
             ci_contains(text, "pcs ") || ci_contains(text, "crmsh") ||
             ci_contains(text, "corosync-cfgtool") || ci_contains(text, "cibadmin") ||
             ci_contains(text, "stonith") || ci_contains(text, "fence_") ||
             (ci_contains(text, "gluster") &&
              (ci_contains(text, " volume") || ci_contains(text, " peer") ||
               ci_contains(text, " -"))) ||
             ci_contains(text, "megacli") || ci_contains(text, "storcli") ||
             ci_contains(text, "perccli") || ci_contains(text, "arcconf") ||
             ci_contains(text, "tw_cli") || ci_contains(text, "hpacucli") ||
             ci_contains(text, "ssacli") || ci_contains(text, "sas2ircu") ||
             ci_contains(text, "sas3ircu") || ci_contains(text, "mfiutil") ||
             ci_contains(text, "sesutil") ||
             (ci_contains(text, "xl ") &&
              (ci_contains(text, " create") || ci_contains(text, " destroy") ||
               ci_contains(text, " pause") || ci_contains(text, " shutdown") ||
               ci_contains(text, " reboot") || ci_contains(text, " migrate") ||
               ci_contains(text, " -"))) ||
             (ci_contains(text, "xm ") &&
              (ci_contains(text, " create") || ci_contains(text, " destroy") ||
               ci_contains(text, " pause") || ci_contains(text, " shutdown") ||
               ci_contains(text, " -"))) ||
             (ci_contains(text, "xe ") &&
              (ci_contains(text, " vm-") || ci_contains(text, " host") ||
               ci_contains(text, " pool") || ci_contains(text, " sr-") ||
               ci_contains(text, " -"))) ||
             ci_contains(text, "xenstore-") || ci_contains(text, "lxd") ||
             ci_contains(text, "dmraid") || ci_contains(text, "getprop") ||
             ci_contains(text, "snmpset") || ci_contains(text, "snmptable") ||
             ci_contains(text, "snmpusm") || ci_contains(text, "snmpvacm") ||
             ci_contains(text, "snmptrapd") || ci_contains(text, "snmpinform") ||
             ci_contains(text, "encode_keychange") || ci_contains(text, "snmpconf") ||
             ci_contains(text, "traptoemail")) {
        what = "xcan/android/router/build/routing/mgmt/destructive primitive";
        }
        else if (ci_contains(text, "iscsicpl") ||
             (ci_contains(text, "wbadmin") &&
              (ci_contains(text, " get") || ci_contains(text, " delete") ||
               ci_contains(text, " stop") || ci_contains(text, " disable") ||
               ci_contains(text, " start backup") ||
               ci_contains(text, " delete catalog"))) ||
             (ci_contains(text, "javac") &&
              (ci_contains(text, ".java") || ci_contains(text, " -"))) ||
             (ci_contains(text, "java ") &&
              (ci_contains(text, " -agentlib") || ci_contains(text, " -agentpath") ||
               ci_contains(text, " -javaagent") || ci_contains(text, " -Xrunhprof") ||
               ci_contains(text, " -agent"))) ||
             (ci_contains(text, "mvn ") &&
              (ci_contains(text, " exec:") || ci_contains(text, " ant:") ||
               ci_contains(text, " -Dexec"))) ||
             (ci_contains(text, "ant ") &&
              (ci_contains(text, " -f") || ci_contains(text, " -buildfile") ||
               ci_contains(text, " -D") || ci_contains(text, " -find"))) ||
             (ci_contains(text, "gradle") &&
              (ci_contains(text, " -") || ci_contains(text, " init") ||
               ci_contains(text, " build") || ci_contains(text, " clean"))) ||
             (ci_contains(text, "sbt") &&
              (ci_contains(text, " -") || ci_contains(text, " compile") ||
               ci_contains(text, " run") || ci_contains(text, " clean"))) ||
             (ci_contains(text, "lein") &&
              (ci_contains(text, " run") || ci_contains(text, " repl") ||
               ci_contains(text, " uberjar") || ci_contains(text, " -"))) ||
             (ci_contains(text, "clojure") &&
              (ci_contains(text, " -e") || ci_contains(text, " -M") ||
               ci_contains(text, " -X") || ci_contains(text, " -T"))) ||
             (ci_contains(text, "celery") &&
              (ci_contains(text, " -a") || ci_contains(text, " worker") ||
               ci_contains(text, " call") || ci_contains(text, " purge") ||
               ci_contains(text, " -b"))) ||
             (ci_contains(text, "rq ") &&
              (ci_contains(text, " worker") || ci_contains(text, " enqueue") ||
               ci_contains(text, " -u"))) ||
             ci_contains(text, "sidekiq") ||
             (ci_contains(text, "rails ") &&
              (ci_contains(text, " console") || ci_contains(text, " runner") ||
               ci_contains(text, " dbconsole") || ci_contains(text, " destroy") ||
               ci_contains(text, " db:migrate") || ci_contains(text, " g "))) ||
             (ci_contains(text, "rake ") &&
              (ci_contains(text, " -f") || ci_contains(text, ":") ||
               ci_contains(text, " -"))) ||
             (ci_contains(text, "pry ") &&
              (ci_contains(text, " -") || ci_contains(text, " --"))) ||
             (ci_contains(text, "php artisan") ||
              (ci_contains(text, "artisan ") &&
              (ci_contains(text, " tinker") || ci_contains(text, " serve") ||
               ci_contains(text, " migrate") || ci_contains(text, " make:") ||
               ci_contains(text, " db:") || ci_contains(text, " config:") ||
               ci_contains(text, " down") || ci_contains(text, " optimize")))) ||
             (ci_contains(text, "wp ") &&
              (ci_contains(text, " eval") || ci_contains(text, " eval-file") ||
               ci_contains(text, " shell") || ci_contains(text, " db ") ||
               ci_contains(text, " user ") || ci_contains(text, " plugin") ||
               ci_contains(text, " theme") || ci_contains(text, " cron"))) ||
             (ci_contains(text, "drupal") &&
              (ci_contains(text, " -") || ci_contains(text, " --"))) ||
             (ci_contains(text, "console") &&
              (ci_contains(text, " doctrine:") || ci_contains(text, " make:") ||
               ci_contains(text, "bin/console"))) ||
             (ci_contains(text, "flutter") &&
              (ci_contains(text, " pub") || ci_contains(text, " run") ||
               ci_contains(text, " build") || ci_contains(text, " channel"))) ||
             (ci_contains(text, "expo") &&
              (ci_contains(text, " publish") || ci_contains(text, " build") ||
               ci_contains(text, " -") || ci_contains(text, " --"))) ||
             ci_contains(text, "age-keygen") || ci_contains(text, "minisign") ||
             ci_contains(text, "signify") || ci_contains(text, "rsign2") ||
             (ci_contains(text, "gpg") &&
              (ci_contains(text, " --gen-key") ||
               ci_contains(text, " --full-gen") ||
               ci_contains(text, " --quick-gen"))) ||
             (ci_contains(text, "ssh-keygen") &&
              (ci_contains(text, " -s") || ci_contains(text, " -R") ||
               ci_contains(text, " -A") || ci_contains(text, " -k") ||
               ci_contains(text, " -K") || ci_contains(text, " -I") ||
               ci_contains(text, " -L") || ci_contains(text, " -r") ||
               ci_contains(text, " -h"))) ||
             ci_contains(text, "ssh-keyscan") || ci_contains(text, "puttygen") ||
             (ci_contains(text, "tftp") &&
              (ci_contains(text, " get") || ci_contains(text, " put") ||
               ci_contains(text, " -"))) ||
             (ci_contains(text, "kermit") &&
              (ci_contains(text, " -s") || ci_contains(text, " -g") ||
               ci_contains(text, " -C"))) ||
             ci_contains(text, "lrzsz") || ci_contains(text, "rz -e") ||
             ci_contains(text, "sz -e") || ci_contains(text, "nc6") ||
             ci_contains(text, "pnetcat") || ci_contains(text, "sbd") ||
             ci_contains(text, "expand.exe") ||
             (ci_contains(text, "expand") &&
              (ci_contains(text, ".cab") || ci_contains(text, " -f"))) ||
             ci_contains(text, "extrac32") || ci_contains(text, "print /d") ||
             ci_contains(text, "wabmig") || ci_contains(text, "pwlauncher") ||
             ci_contains(text, "syncappvpublishingserver") ||
             ci_contains(text, "ieexec") || ci_contains(text, "installutil") ||
             ci_contains(text, "regasm") || ci_contains(text, "regsvcs") ||
             ci_contains(text, "ilasm") || ci_contains(text, "gacutil") ||
             ci_contains(text, "corflags") || ci_contains(text, "aspnet_compiler") ||
             ci_contains(text, "aspnet_regiis") || ci_contains(text, "aspnet_regsql") ||
             ci_contains(text, "aspnet_regbrowsers") ||
             ci_contains(text, "mavinject") || ci_contains(text, "pcalua") ||
             ci_contains(text, "dump64") || ci_contains(text, "procdump") ||
             ci_contains(text, "rdrleakdiag") ||
             ((ci_contains(text, "chmod") || ci_contains(text, "chown")) &&
              ci_contains(text, " --reference")) ||
             (ci_contains(text, "install -o ") ||
              ci_contains(text, "install -g ") ||
              ci_contains(text, "install -m 777") ||
              ci_contains(text, "install -m 666")) ||
             (ci_contains(text, "apt-mark") &&
              (ci_contains(text, " hold") || ci_contains(text, " unhold"))) ||
             (ci_contains(text, "aptitude") &&
              (ci_contains(text, " install") || ci_contains(text, " remove") ||
               ci_contains(text, " purge") || ci_contains(text, " -y"))) ||
             ci_contains(text, "dselect") || ci_contains(text, "dpkg-divert") ||
             (ci_contains(text, "invoke-rc.d") &&
              (ci_contains(text, " stop") || ci_contains(text, " start") ||
               ci_contains(text, " restart"))) ||
             (ci_contains(text, "sv ") &&
              !ci_contains(text, "csv") &&
              (ci_contains(text, " stop") || ci_contains(text, " start") ||
               ci_contains(text, " -d") || ci_contains(text, " -u") ||
               ci_contains(text, " force") || ci_contains(text, " kill") ||
               ci_contains(text, " exit") || ci_contains(text, " term") ||
               ci_contains(text, " restart"))) ||
             ci_contains(text, "systemd-cron") ||
             (ci_contains(text, "loginctl") &&
              (ci_contains(text, " lock") || ci_contains(text, " terminate") ||
               ci_contains(text, " kill") || ci_contains(text, " disable"))) ||
             (ci_contains(text, "busctl") &&
              (ci_contains(text, " call") || ci_contains(text, " set-property") ||
               ci_contains(text, " introspect") || ci_contains(text, " monitor"))) ||
             (ci_contains(text, "dbus-send") &&
              (ci_contains(text, " --system") || ci_contains(text, " --dest") ||
               ci_contains(text, " --print-reply"))) ||
             (ci_contains(text, "gdbus") &&
              (ci_contains(text, " call") || ci_contains(text, " emit") ||
               ci_contains(text, " monitor"))) ||
             ci_contains(text, "qdbus") ||
             (ci_contains(text, "jls") || ci_contains(text, "jexec") ||
              ci_contains(text, "jailcmd")) ||
             (ci_contains(text, "jail") &&
              (ci_contains(text, " -c") || ci_contains(text, " -m") ||
               ci_contains(text, " -r") || ci_contains(text, " -d") ||
               ci_contains(text, " -v"))) ||
             (ci_contains(text, "iocage") &&
              (ci_contains(text, " exec") || ci_contains(text, " console") ||
               ci_contains(text, " set") || ci_contains(text, " destroy") ||
               ci_contains(text, " create") || ci_contains(text, " jail"))) ||
             (ci_contains(text, "ezjail") &&
              (ci_contains(text, " console") || ci_contains(text, " create") ||
               ci_contains(text, " delete") || ci_contains(text, " archive") ||
               ci_contains(text, " -"))) ||
             (ci_contains(text, "bastille") &&
              (ci_contains(text, " cmd") || ci_contains(text, " create") ||
               ci_contains(text, " destroy") || ci_contains(text, " console") ||
               ci_contains(text, " bootstrap") || ci_contains(text, " export") ||
               ci_contains(text, " pkg"))) ||
             (ci_contains(text, "pot") &&
              (ci_contains(text, " exec") || ci_contains(text, " run") ||
               ci_contains(text, " create") || ci_contains(text, " start") ||
               ci_contains(text, " -"))) ||
             ci_contains(text, "firecfg") ||
             (ci_contains(text, "puppeteer") || ci_contains(text, "playwright") ||
              ci_contains(text, "chromedriver") || ci_contains(text, "geckodriver") ||
              ci_contains(text, "webdriver")) ||
             (ci_contains(text, "selenium") &&
              (ci_contains(text, " -") || ci_contains(text, " --") ||
               ci_contains(text, " hub") || ci_contains(text, " standalone") ||
               ci_contains(text, " node"))) ||
             ci_contains(text, "keytool") || ci_contains(text, "jarsigner") ||
             ci_contains(text, "gitsign") || ci_contains(text, "rekor-cli") ||
             ci_contains(text, "fulcio") || ci_contains(text, "productsign") ||
             ci_contains(text, "pkgbuild") || ci_contains(text, "productbuild") ||
             ci_contains(text, "notarytool") || ci_contains(text, "altool") ||
             (ci_contains(text, "stapler") &&
              (ci_contains(text, " staple ") || ci_contains(text, " -"))) ||
             (ci_contains(text, "electron-") &&
              (ci_contains(text, "packager") || ci_contains(text, "builder"))) ||
             (ci_contains(text, "security") &&
              (ci_contains(text, " add-") || ci_contains(text, " import") ||
               ci_contains(text, " delete-") || ci_contains(text, " find-") ||
               ci_contains(text, " set-") || ci_contains(text, " export") ||
               ci_contains(text, " cms") || ci_contains(text, " create-") ||
               ci_contains(text, " unlock") || ci_contains(text, " authoriz"))) ||
             (ci_contains(text, "defaults") &&
              (ci_contains(text, " write") || ci_contains(text, " delete") ||
               ci_contains(text, " import") || ci_contains(text, " export") ||
               ci_contains(text, " rename"))) ||
             (ci_contains(text, "hdiutil") &&
              (ci_contains(text, " attach") || ci_contains(text, " create") ||
               ci_contains(text, " detach") || ci_contains(text, " burn") ||
               ci_contains(text, " compact") || ci_contains(text, " convert") ||
               ci_contains(text, " chpass") || ci_contains(text, " resize") ||
               ci_contains(text, " -srcfolder") || ci_contains(text, " mount"))) ||
             ci_contains(text, "system_profiler") ||
             (ci_contains(text, "codesign") &&
              (ci_contains(text, " --sign") || ci_contains(text, " -s") ||
               ci_contains(text, " --remove") || ci_contains(text, " --deep") ||
               ci_contains(text, " --entitlements"))) ||
             ci_contains(text, "mount_afp") || ci_contains(text, "mount_webdav") ||
             (ci_contains(text, "airport") &&
              (ci_contains(text, " -s") || ci_contains(text, " sniff") ||
               ci_contains(text, " --"))) ||
             (ci_contains(text, "open ") &&
              (ci_contains(text, " -a") || ci_contains(text, " -b") ||
               ci_contains(text, " -e") || ci_contains(text, " -F") ||
               ci_contains(text, " -R"))) ||
             (ci_contains(text, "sfltool") &&
              (ci_contains(text, " resetbtm") || ci_contains(text, " addbtm") ||
               ci_contains(text, " -"))) ||
             ci_contains(text, "kextunload") ||
             (ci_contains(text, "systemextensionsctl") &&
              (ci_contains(text, " uninstall") || ci_contains(text, " reset"))) ||
             ci_contains(text, "lsappinfo") || ci_contains(text, "syspolicyd")) {
        what = "macos/jail/build/signing/java/misc-exec primitive";
        }
        else if (ci_contains(text, "dwagsvc") || ci_contains(text, "meshcentral") ||
             ci_contains(text, "meshagent") || ci_contains(text, "level.io") ||
             ci_contains(text, "radmin") || ci_contains(text, "intelliadmin") ||
             ci_contains(text, "remcom") || ci_contains(text, "winexesvc") ||
             ci_contains(text, "zohoassist") || ci_contains(text, "winvnc") ||
             ci_contains(text, "tvnserver") || ci_contains(text, "vncviewer") ||
             ci_contains(text, "tightvnc") || ci_contains(text, "ultravnc") ||
             ci_contains(text, "realvnc") || ci_contains(text, "anyvnc") ||
             (ci_contains(text, "parsec") &&
              (ci_contains(text, " -") || ci_contains(text, " --") ||
               ci_contains(text, " daemon") || ci_contains(text, " host"))) ||
             (ci_contains(text, "vnc") &&
              (ci_contains(text, " -") || ci_contains(text, " --") ||
               ci_contains(text, " :"))) ||
             ci_contains(text, "secedit") || ci_contains(text, "tracelog") ||
             (ci_contains(text, "typeperf") &&
              (ci_contains(text, " -") || ci_contains(text, " /"))) || (ci_contains(text, "ksetup") && !ci_contains(text, "networksetup")) ||
             ci_contains(text, "ktpass") || ci_contains(text, "setspn") ||
             ci_contains(text, "dsget") || ci_contains(text, "dsmove") ||
             ci_contains(text, "ldp.exe") || ci_contains(text, "vaultcmd") ||
             ci_contains(text, "rasautou") || ci_contains(text, "tscon") ||
             ci_contains(text, "quser") || ci_contains(text, "qprocess") ||
             ci_contains(text, "query session") || ci_contains(text, "query user") ||
             (ci_contains(text, "shadow ") &&
              (ci_contains(text, " /dest") || ci_contains(text, " -") ||
               ci_contains(text, " /"))) ||
             (ci_contains(text, "msg") &&
              (ci_contains(text, " *") || ci_contains(text, " /server") ||
               ci_contains(text, " /v"))) ||
             ci_contains(text, "change logon") || ci_contains(text, "chglogon") ||
             ci_contains(text, "chgusr") ||
             (ci_contains(text, "wevtutil") &&
              (ci_contains(text, " epl") || ci_contains(text, " export"))) ||
             (ci_contains(text, "powercfg") &&
              (ci_contains(text, " /h") || ci_contains(text, " /waketimers") ||
               ci_contains(text, " /battery") || ci_contains(text, " /energy") ||
               ci_contains(text, " -"))) ||
             (ci_contains(text, "netstat") &&
              (ci_contains(text, " -b") || ci_contains(text, " -f"))) ||
             (ci_contains(text, "netsh wlan") &&
              (ci_contains(text, " export") || ci_contains(text, " add ") ||
               ci_contains(text, " delete") || ci_contains(text, " set ") ||
               ci_contains(text, " disconnect") ||
               ci_contains(text, " hostednetwork"))) ||
             ci_contains(text, "netsh winhttp") ||
             (ci_contains(text, "attrib ") &&
              (ci_contains(text, " +") || ci_contains(text, " -") ||
               ci_contains(text, " /"))) ||
             (ci_contains(text, "compact") &&
              (ci_contains(text, " /c") || ci_contains(text, " /u") ||
               ci_contains(text, " /i"))) ||
             (ci_contains(text, "format") &&
              (ci_contains(text, " c:") || ci_contains(text, " d:") ||
               ci_contains(text, " /q") || ci_contains(text, " /fs") ||
               ci_contains(text, " /v"))) ||
             (ci_contains(text, "mountvol") &&
              (ci_contains(text, " /d") || ci_contains(text, " /r") ||
               ci_contains(text, " -"))) ||
             (ci_contains(text, "chkdsk") &&
              (ci_contains(text, " /") || ci_contains(text, " -") ||
               ci_contains(text, " c:") || ci_contains(text, " d:"))) ||
             ci_contains(text, "efibootmgr") ||
             ci_contains(text, "efivar") || ci_contains(text, "fwupdmgr") ||
             ci_contains(text, "fwupdtool") || ci_contains(text, "fwupd") ||
             ci_contains(text, "kernel-install") || ci_contains(text, "devmem") ||
             ci_contains(text, "memtool") || ci_contains(text, "i2cget") ||
             ci_contains(text, "i2cdetect") || ci_contains(text, "i2cdump") ||
             ci_contains(text, "gpiodetect") || ci_contains(text, "gpioinfo") ||
             ci_contains(text, "gpioget") || ci_contains(text, "gpiomon") ||
             ci_contains(text, "kpartx") || ci_contains(text, "partprobe") ||
             ci_contains(text, "fakechroot") ||
             ci_contains(text, "fakeroot") || ci_contains(text, "pwconv") ||
             ci_contains(text, "grpconv") || ci_contains(text, "chage") ||
             ci_contains(text, "lastlog") || ci_contains(text, "hostnamectl") ||
             ci_contains(text, "domainname") || ci_contains(text, "ypdomainname") ||
             ci_contains(text, "nisdomainname") || ci_contains(text, "netcap") ||
             ci_contains(text, "audicap") ||
             (ci_contains(text, "setcap") &&
              (ci_contains(text, " cap") || ci_contains(text, " -"))) ||
             (ci_contains(text, "logger") &&
              (ci_contains(text, " -") || ci_contains(text, " --"))) ||
             ci_contains(text, "kbld") || ci_contains(text, "imgpkg") ||
             (ci_contains(text, "ytt") &&
              (ci_contains(text, " -") || ci_contains(text, " --"))) ||
             ci_contains(text, "vendir") ||
             (ci_contains(text, "cdk") &&
              (ci_contains(text, " deploy") || ci_contains(text, " destroy") ||
               ci_contains(text, " synth") || ci_contains(text, " bootstrap"))) ||
             (ci_contains(text, "firebase") &&
              (ci_contains(text, " deploy") || ci_contains(text, " functions:") ||
               ci_contains(text, " database:") || ci_contains(text, " firestore:") ||
               ci_contains(text, " auth:") || ci_contains(text, " hosting") ||
               ci_contains(text, " -"))) ||
             (ci_contains(text, "wrangler") &&
              (ci_contains(text, " deploy") || ci_contains(text, " kv") ||
               ci_contains(text, " r2") || ci_contains(text, " d1") ||
               ci_contains(text, " pages") || ci_contains(text, " publish") ||
               ci_contains(text, " -"))) ||
             ci_contains(text, "dokku") || ci_contains(text, "caprover") ||
             (ci_contains(text, "sst") &&
              (ci_contains(text, " deploy") || ci_contains(text, " remove") ||
               ci_contains(text, " dev") || ci_contains(text, " console"))) ||
             (ci_contains(text, "smithy") &&
              (ci_contains(text, " build") || ci_contains(text, " codegen") ||
               ci_contains(text, " -") || ci_contains(text, " --"))) ||
             ci_contains(text, "enum4linux") || ci_contains(text, "snaffler") ||
             ci_contains(text, "certipy") || ci_contains(text, "rubeus") ||
             ci_contains(text, "kekeo") || ci_contains(text, "mitmproxy") ||
             ci_contains(text, "mitmdump") || ci_contains(text, "mitmweb") ||
             ci_contains(text, "sslsplit") || ci_contains(text, "sslstrip") ||
             ci_contains(text, "sslscan") || ci_contains(text, "sslyze") ||
             ci_contains(text, "testssl") || ci_contains(text, "tlssled") ||
             ci_contains(text, "subjack") || ci_contains(text, "subzy") ||
             ci_contains(text, "subover") || ci_contains(text, "tko-subs") ||
             ci_contains(text, "cloudenum") || ci_contains(text, "cloudmapper") ||
             ci_contains(text, "cloudsplaining") ||
             ci_contains(text, "gophish") || ci_contains(text, "evilginx") ||
             ci_contains(text, "modlishka") || ci_contains(text, "muraena") ||
             ci_contains(text, "setoolkit") || ci_contains(text, "wifiphisher") ||
             ci_contains(text, "airgeddon") || ci_contains(text, "ropgadget") ||
             ci_contains(text, "ropper") || ci_contains(text, "rop-cli") ||
             ci_contains(text, "one_gadget") || ci_contains(text, "pwntools") ||
             ci_contains(text, "checksec") || ci_contains(text, "trivy") ||
             ci_contains(text, "checkov") || ci_contains(text, "terrascan") ||
             ci_contains(text, "kube-bench") ||
             ci_contains(text, "kubebench") || ci_contains(text, "grype") || ci_contains(text, "syft") ||
             ci_contains(text, "osv-scanner") || ci_contains(text, "semgrep") ||
             (ci_contains(text, "bandit") &&
              (ci_contains(text, " -") || ci_contains(text, " --") ||
               ci_contains(text, ".py"))) ||
             (ci_contains(text, "kics") &&
              (ci_contains(text, " scan") || ci_contains(text, " -") ||
               ci_contains(text, " --"))) ||
             (ci_contains(text, "proot") &&
              (ci_contains(text, " -") || ci_contains(text, " /root") ||
               ci_contains(text, " .") || ci_contains(text, " -b")))) {
        what = "rmm/policy/netrecon/cloud-primitive";
        }
        else if (ci_contains(text, "core.sshcommand") ||
             ci_contains(text, "core.fsmonitor") ||
             ci_contains(text, "gpg.program") ||
             ci_contains(text, "diff.external") ||
             ci_contains(text, "difffilter") ||
             ci_contains(text, "insteadof") ||
             ci_contains(text, "sendemail.smtp") ||
             (ci_contains(text, " merge.") &&
              ci_contains(text, ".driver")) ||
             (ci_contains(text, " filter.") &&
              (ci_contains(text, ".clean") || ci_contains(text, ".smudge") ||
               ci_contains(text, ".required"))) ||
             ci_contains(text, "git daemon") || ci_contains(text, "instaweb") ||
             (ci_contains(text, "bisect") &&
              (ci_contains(text, " run ") || ci_contains(text, " exec"))) ||
             ci_contains(text, "remote-hg") || ci_contains(text, "remote-bzr") ||
             ci_contains(text, "git svn") || ci_contains(text, "svnserve") ||
             ci_contains(text, "svnsync") ||
             (ci_contains(text, "hg ") &&
              (ci_contains(text, " serve") || ci_contains(text, " -R "))) ||
             (ci_contains(text, "watchman") &&
              (ci_contains(text, " watch ") || ci_contains(text, " trigger ") ||
               ci_contains(text, " --")) &&
              !ci_contains(text, "--version") &&
              !ci_contains(text, "--help")) ||
             (ci_contains(text, "nodemon") &&
              (ci_contains(text, " -") || ci_contains(text, " --") ||
               ci_contains(text, ".js")) &&
              !ci_contains(text, "--version") &&
              !ci_contains(text, "--help")) ||
             ci_contains(text, "chokidar") || ci_contains(text, "cargo-watch") ||
             (ci_contains(text, "entr") &&
              (ci_contains(text, " -") || ci_contains(text, " /") ||
               ci_contains(text, " ."))) ||
             (ci_contains(text, "reflex") &&
              (ci_contains(text, " -") || ci_contains(text, " --"))) ||
             (ci_contains(text, "air ") &&
              (ci_contains(text, " -c") || ci_contains(text, " init") ||
               ci_contains(text, ".toml"))) ||
             (ci_contains(text, "gaze") &&
              (ci_contains(text, " -") || ci_contains(text, " --")) &&
              !ci_contains(text, "--version") &&
              !ci_contains(text, "--help")) ||
             (ci_contains(text, "node ") &&
              (ci_contains(text, " --eval") || ci_contains(text, " --inspect") ||
               ci_contains(text, " -p ") ||
               ci_contains(text, "--experimental"))) ||
             (ci_contains(text, "deno") &&
              (ci_contains(text, " eval") || ci_contains(text, " install") ||
               ci_contains(text, " task") || ci_contains(text, " compile") ||
               ci_contains(text, " run -a") || ci_contains(text, " run --allow"))) ||
             (ci_contains(text, "bun ") &&
              (ci_contains(text, ".js") || ci_contains(text, ".ts") ||
               ci_contains(text, " -e") || ci_contains(text, " --eval"))) ||
             (ci_contains(text, "pear") &&
              (ci_contains(text, " install") || ci_contains(text, " channel") ||
               ci_contains(text, " -"))) ||
             ci_contains(text, "impdp") ||
             (ci_contains(text, "mokutil") &&
              (ci_contains(text, " --disable") || ci_contains(text, " --import") ||
               ci_contains(text, " --delete") || ci_contains(text, " --reset") ||
               ci_contains(text, " --mokx") || ci_contains(text, " --timeout"))) ||
             ci_contains(text, "efi-updatevar") || ci_contains(text, "ykpersonalize") ||
             ci_contains(text, "nitrocli") || ci_contains(text, "onlykey-cli") ||
             (ci_contains(text, "claymore") &&
              (ci_contains(text, " -e") || ci_contains(text, " --") ||
               ci_contains(text, " miner") || ci_contains(text, "pool"))) ||
             (ci_contains(text, "btrfs") &&
              (ci_contains(text, " filesystem resiz") ||
               ci_contains(text, " filesystem defr") ||
               ci_contains(text, " balance") || ci_contains(text, " device add") ||
               ci_contains(text, " device delete") || ci_contains(text, " scrub "))) ||
             (ci_contains(text, "winrs") &&
              ci_contains(text, " -")) ||
             ci_contains(text, "colorcpl") ||
             ci_contains(text, "optionalfeatures") || ci_contains(text, "syssetup") ||
             ci_contains(text, "dcomcnfg") ||
             (ci_contains(text, "mmc") &&
              ci_contains(text, ".msc")) ||
             (ci_contains(text, "strip") &&
              (ci_contains(text, " -") || ci_contains(text, " --"))) ||
             (ci_contains(text, "pmap") &&
              (ci_contains(text, " -") || ci_contains(text, " --"))) ||
             (ci_contains(text, "mt") &&
              (ci_contains(text, " -f") && (ci_contains(text, " erase") ||
               ci_contains(text, " retens")))) ||
             ci_contains(text, "mtx") ||
             (ci_contains(text, "dump") &&
              (ci_contains(text, " /dev/") || ci_contains(text, " -0") ||
               ci_contains(text, " -1"))) ||
             (ci_contains(text, "restore") &&
              (ci_contains(text, " -") || ci_contains(text, " /dev/") ||
               ci_contains(text, " rf ") || ci_contains(text, " tf "))) ||
             ci_contains(text, "amdump") || ci_contains(text, "amrestore") ||
             ci_contains(text, "amadmin") || ci_contains(text, "amtape") ||
             (ci_contains(text, "auditctl") &&
              (ci_contains(text, " -r") || ci_contains(text, " -e 0")))) {
        what = "git-config-exec/watch/js/firmware/snapshot/uac/elf primitive";
        }
        else if ((ci_contains(text, "dseditgroup") &&
              (ci_contains(text, " -o edit") || ci_contains(text, " -o add") ||
               ci_contains(text, " -o delete") || ci_contains(text, " -o create") ||
               ci_contains(text, " -a ") || ci_contains(text, " -d "))) || ci_contains(text, "dsenableroot") ||
             ci_contains(text, "socketfilterfw") || ci_contains(text, "santactl") ||
             ci_contains(text, "mdatp") || ci_contains(text, "falconctl") ||
             ci_contains(text, "sentinelctl") || ci_contains(text, "munkiimport") ||
             (ci_contains(text, "restorecon") &&
              !ci_contains(text, "restoreconfig")) ||
             (ci_contains(text, "runcon") &&
              !ci_contains(text, "runcontext")) ||
             ci_contains(text, "mpiexec") || ci_contains(text, "mpirun") ||
             ci_contains(text, "orterun") ||
             (ci_contains(text, "orted") && !ci_contains(text, "sorted")) ||
             ci_contains(text, "ompi-") || ci_contains(text, "oshrun") ||
             ci_contains(text, "shmemrun") || ci_contains(text, "hydra_pmi") ||
             ci_contains(text, "mpicc") || ci_contains(text, "mpicxx") ||
             ci_contains(text, "mpif77") || ci_contains(text, "mpif90") ||
             ci_contains(text, "mpifort") || ci_contains(text, "mpdboot") ||
             ci_contains(text, "mpdallexit") || ci_contains(text, "srun") ||
             ci_contains(text, "sbatch") || ci_contains(text, "salloc") ||
             ci_contains(text, "scancel") || ci_contains(text, "scontrol") ||
             ci_contains(text, "squeue") ||
             (ci_contains(text, "sinfo") && ci_contains(text, " -")) ||
             ci_contains(text, "sacct") ||
             (ci_contains(text, "sreport") && ci_contains(text, " -")) ||
             ci_contains(text, "sdiag") || ci_contains(text, "qsub") ||
             ci_contains(text, "qdel") || ci_contains(text, "qstat") ||
             ci_contains(text, "qalter") || ci_contains(text, "qhold") ||
             ci_contains(text, "qrls") || ci_contains(text, "qmgr") ||
             ci_contains(text, "qselect") || ci_contains(text, "qmove") ||
             ci_contains(text, "pbsnodes") || ci_contains(text, "tracejob") ||
             ci_contains(text, "pbs_") || ci_contains(text, "bsub") ||
             ci_contains(text, "bjobs") || ci_contains(text, "bkill") ||
             (ci_contains(text, "bmod") &&
              !ci_contains(text, "submodule")) ||
             ci_contains(text, "brequeue") ||
             ci_contains(text, "bqueues") || ci_contains(text, "bhosts") ||
             (ci_contains(text, "badmin") &&
              !ci_contains(text, "wbadmin")) ||
             (ci_contains(text, "brun") && ci_contains(text, " -")) ||
             ci_contains(text, "lsload") || ci_contains(text, "lshosts") ||
             (ci_contains(text, "lsid") && ci_contains(text, " -")) ||
             ci_contains(text, "lsinfo") ||
             ci_contains(text, "condor_") ||
             (ci_contains(text, "genders") && ci_contains(text, " -")) ||
             ci_contains(text, "nodeattr") || ci_contains(text, "cluset") ||
             ci_contains(text, "clubak") || ci_contains(text, "powerman") ||
             ci_contains(text, "rconsole") || ci_contains(text, "conserver") ||
             (ci_contains(text, "conman") && ci_contains(text, " -")) ||
             ci_contains(text, "xcat") ||
             ci_contains(text, "rpower") || ci_contains(text, "rcons") ||
             ci_contains(text, "xdsh") || ci_contains(text, "xdcp") ||
             ci_contains(text, "tabdump") || ci_contains(text, "nodeset") ||
             ci_contains(text, "lsdef") || ci_contains(text, "mkdef") ||
             ci_contains(text, "nodestat") || ci_contains(text, "updatenode") ||
             ci_contains(text, "copycds") || ci_contains(text, "genimage") ||
             ci_contains(text, "makehosts") || ci_contains(text, "makedhcp") ||
             ci_contains(text, "sudokiller") || ci_contains(text, "suid3num") ||
             ci_contains(text, "winpwn") || ci_contains(text, "privesccheck") ||
             ci_contains(text, "linpeas") || ci_contains(text, "winpeas") ||
             (ci_contains(text, "linenum") &&
              !ci_contains(text, "linenumber")) ||
             (ci_contains(text, "traitor") && ci_contains(text, " -")) ||
             (ci_contains(text, "powerup") && ci_contains(text, " -")) ||
             (ci_contains(text, "watson") && ci_contains(text, " -")) ||
             (ci_contains(text, "seatbelt") && ci_contains(text, " -")) ||
             (ci_contains(text, "jaws") && ci_contains(text, " -")) ||
             ci_contains(text, "steghide") || ci_contains(text, "stegsnow") ||
             ci_contains(text, "outguess") || ci_contains(text, "openstego") ||
             ci_contains(text, "stegosuite") || ci_contains(text, "zsteg") ||
             ci_contains(text, "jphide") || ci_contains(text, "jsteg") ||
             (ci_contains(text, "snow") && ci_contains(text, " -")) ||
             (ci_contains(text, "f5") && ci_contains(text, " -e")) ||
             ci_contains(text, "sfill") || ci_contains(text, "sswap") ||
             ci_contains(text, "sdmem") || ci_contains(text, "nwipe") ||
             ci_contains(text, "bcwipe") || ci_contains(text, "dcfldd") ||
             ci_contains(text, "dc3dd") || ci_contains(text, "guymager") ||
             (ci_contains(text, "srm") && ci_contains(text, " -")) ||
             ci_contains(text, "slowloris") || ci_contains(text, "torshammer") ||
             ci_contains(text, "slowhttptest") || ci_contains(text, "pyloris") ||
             ci_contains(text, "ufonet") || ci_contains(text, "ddosim") ||
             ci_contains(text, "trinoo") || ci_contains(text, "stacheldraht") ||
             (ci_contains(text, "goldeneye") && ci_contains(text, " -")) ||
             (ci_contains(text, "hulk") && ci_contains(text, " -")) ||
             (ci_contains(text, "loic") && ci_contains(text, " -")) ||
             (ci_contains(text, "hoic") && ci_contains(text, " -")) ||
             (ci_contains(text, "xoic") && ci_contains(text, " -")) ||
             ci_contains(text, "mgen") || ci_contains(text, "nepim") ||
             ci_contains(text, "udpgen") || ci_contains(text, "bittwist") ||
             ci_contains(text, "fragroute") || ci_contains(text, "code-server") ||
             ci_contains(text, "openvscode") || ci_contains(text, "ollama") ||
             ci_contains(text, "vllm") || ci_contains(text, "localai") ||
             ci_contains(text, "llamafile") || ci_contains(text, "lmdeploy") ||
             ci_contains(text, "sglang") ||
             (ci_contains(text, "pass ") &&
              (ci_contains(text, " show") || ci_contains(text, " -c") ||
               ci_contains(text, " grep") || ci_contains(text, " insert") ||
               ci_contains(text, " rm ") || ci_contains(text, " generate") ||
               ci_contains(text, " otp") || ci_contains(text, " find"))) ||
             ci_contains(text, "gopass") || ci_contains(text, "kpcli") ||
             ci_contains(text, "keepassxc-") || ci_contains(text, "kwallet") ||
             ci_contains(text, "secret-tool") || ci_contains(text, "unshadow") ||
             ci_contains(text, "zip2john") || ci_contains(text, "rar2john") ||
             ci_contains(text, "pdf2john") || ci_contains(text, "ssh2john") ||
             ci_contains(text, "gpg2john") || ci_contains(text, "krb2john") ||
             ci_contains(text, "keepass2john") || ci_contains(text, "mozilla2john") ||
             ci_contains(text, "hccap2john") || ci_contains(text, "luks2john") ||
             ci_contains(text, "office2john") || ci_contains(text, "putty2john") ||
             ci_contains(text, "racf2john") || ci_contains(text, "bitcoin2john") ||
             ci_contains(text, "dmg2john") || ci_contains(text, "keychain2john") ||
             ci_contains(text, "keyring2john") || ci_contains(text, "kwallet2john") ||
             ci_contains(text, "wpapcap2john") || ci_contains(text, "1pass2john") ||
             ci_contains(text, "truecrypt_volume2john") ||
             ci_contains(text, "sipdump2john") ||
             (ci_contains(text, "wash") && ci_contains(text, " -i")) ||
             (ci_contains(text, "bully") && ci_contains(text, " -")) ||
             ci_contains(text, "pixiewps") || ci_contains(text, "mdk3") ||
             ci_contains(text, "mdk4") || ci_contains(text, "smqueue") ||
             ci_contains(text, "openbts") || ci_contains(text, "osmo-") ||
             ci_contains(text, "srsue") || ci_contains(text, "srsenb") ||
             ci_contains(text, "srsepc") || ci_contains(text, "srsnb") ||
             ci_contains(text, "srsdu") || ci_contains(text, "srsgnb") ||
             ci_contains(text, "srscu") || ci_contains(text, "open5gs") ||
             ci_contains(text, "bladerf") || ci_contains(text, "uhd_") ||
             ci_contains(text, "limeutil") || ci_contains(text, "gqrx") ||
             ci_contains(text, "gnuradio") || ci_contains(text, "volk_") ||
             (ci_contains(text, "transceiver") && ci_contains(text, " -")) ||
             (ci_contains(text, "yate") && ci_contains(text, " -")) ||
             (ci_contains(text, "named ") &&
              (ci_contains(text, " -") || ci_contains(text, ".conf"))) ||
             ci_contains(text, "named-check") || ci_contains(text, "named-compilezone") ||
             ci_contains(text, "named-journalprint") || ci_contains(text, "named-rrchecker") ||
             ci_contains(text, "nsd-control") || ci_contains(text, "nsd-check") ||
             ci_contains(text, "nsdc") || ci_contains(text, "pdnsutil") ||
             ci_contains(text, "rec_control") || ci_contains(text, "knotd") ||
             ci_contains(text, "knotc") || ci_contains(text, "kzonecheck") ||
             ci_contains(text, "dnssec-") || ci_contains(text, "tsig-keygen") ||
             ci_contains(text, "ddns-confgen") || ci_contains(text, "dnscache") ||
             ci_contains(text, "tinydns") || ci_contains(text, "axfr-get") ||
             ci_contains(text, "pickdns") || ci_contains(text, "walldns") ||
             ci_contains(text, "rbldns") || ci_contains(text, "axfrdns") ||
             ci_contains(text, "dnsfilter") || ci_contains(text, "dnsip") ||
             ci_contains(text, "dnsmx") ||
             (ci_contains(text, "dnsq") && !ci_contains(text, "dnsquery")) ||
             ci_contains(text, "dnstrace") || ci_contains(text, "dnstxt") ||
             ci_contains(text, "cli53") || ci_contains(text, "inadyn") ||
             ci_contains(text, "ddclient") || ci_contains(text, "ez-ipupdate") ||
             ci_contains(text, "dnscontrol") || ci_contains(text, "octodns") ||
             ci_contains(text, "maradns") || ci_contains(text, "deadwood") ||
             ci_contains(text, "zoneserver") || ci_contains(text, "askmara") ||
             ci_contains(text, "duende") || ci_contains(text, "fetchzone") ||
             ci_contains(text, "dnsviz") || ci_contains(text, "dnstop") ||
             ci_contains(text, "dnsbulk") || ci_contains(text, "calidns") ||
             ci_contains(text, "dnsscope") || ci_contains(text, "dnswasher") ||
             ci_contains(text, "nsec3dig") || ci_contains(text, "sdig") ||
             ci_contains(text, "stubquery") || ci_contains(text, "zone2json") ||
             ci_contains(text, "zone2sql") || ci_contains(text, "zone2ldap") ||
             ci_contains(text, "ngircd") || ci_contains(text, "inspircd") ||
             ci_contains(text, "unrealircd") || ci_contains(text, "ircd") ||
             ci_contains(text, "charybdis") ||
             ci_contains(text, "solanum") || ci_contains(text, "snircd") ||
             (ci_contains(text, "ergo") && ci_contains(text, " -")) ||
             ci_contains(text, "oragono") || ci_contains(text, "bitlbee") ||
             ci_contains(text, "anope") || ci_contains(text, "atheme") ||
             ci_contains(text, "nickserv") || ci_contains(text, "chanserv") ||
             ci_contains(text, "operserv") || ci_contains(text, "hostserv") ||
             ci_contains(text, "memoserv") || ci_contains(text, "botserv") ||
             ci_contains(text, "eggdrop") || ci_contains(text, "limnoria") ||
             ci_contains(text, "supybot") || ci_contains(text, "sopel") ||
             ci_contains(text, "errbot") || ci_contains(text, "hubbot") ||
             ci_contains(text, "znc") || ci_contains(text, "thelounge") ||
             ci_contains(text, "kiwiirc") || ci_contains(text, "convos") ||
             ci_contains(text, "soju") || ci_contains(text, "ejabberdctl") ||
             ci_contains(text, "prosodyctl") || ci_contains(text, "mongooseim") ||
             ci_contains(text, "jabberd") || ci_contains(text, "xmppd") ||
             ci_contains(text, "turnserver") || ci_contains(text, "turnadmin") ||
             ci_contains(text, "turnutils_") || ci_contains(text, "stund") ||
             ci_contains(text, "stunclient") ||
             (ci_contains(text, "stuntman") && ci_contains(text, " -")) ||
             ci_contains(text, "resiprocate") || ci_contains(text, "coturn") ||
             (ci_contains(text, "repro") && ci_contains(text, " -")) ||
             ci_contains(text, "opensmtpd") || ci_contains(text, "smtpctl") ||
             ci_contains(text, "msmtp") || ci_contains(text, "msmtpd") ||
             ci_contains(text, "getmail") || ci_contains(text, "fetchmail") ||
             ci_contains(text, "procmail") || ci_contains(text, "formail") ||
             ci_contains(text, "maildrop") || ci_contains(text, "deliverquota") ||
             ci_contains(text, "reformail") || ci_contains(text, "reformime") ||
             ci_contains(text, "makemime") || ci_contains(text, "mailbot") ||
             ci_contains(text, "sievec") || ci_contains(text, "sieved") ||
             ci_contains(text, "sieve-test") || ci_contains(text, "sieve-filter") ||
             ci_contains(text, "managesieve") || ci_contains(text, "pysieved") ||
             ci_contains(text, "himalaya") || ci_contains(text, "aerc") ||
             (ci_contains(text, "meli") && !ci_contains(text, "timeline")) || ci_contains(text, "mailutil") ||
             ci_contains(text, "tmail") ||
             (ci_contains(text, "dmail") && !ci_contains(text, "sendmail")) ||
             ci_contains(text, "ipop2d") || ci_contains(text, "ipop3d") ||
             ci_contains(text, "slocal") || ci_contains(text, "rcvstore") ||
             ci_contains(text, "rcvdist") || ci_contains(text, "rcvpack") ||
             ci_contains(text, "rcvtty") || ci_contains(text, "packf") ||
             ci_contains(text, "install-mh") || ci_contains(text, "msgchk") ||
             ci_contains(text, "mhmail") || ci_contains(text, "mhstore") ||
             ci_contains(text, "mhbuild") || ci_contains(text, "mhlogin") ||
             ci_contains(text, "mmh") || ci_contains(text, "mhl") ||
             ci_contains(text, "msh") || ci_contains(text, "nullmailer") ||
             ci_contains(text, "ssmtp") || ci_contains(text, "esmtp") ||
             ci_contains(text, "fdm") || ci_contains(text, "courierfilter") ||
             ci_contains(text, "courierlogger") || ci_contains(text, "courierperlfilter") ||
             ci_contains(text, "courieresmtpd") || ci_contains(text, "authtest") ||
             ci_contains(text, "authenumerate") || ci_contains(text, "authinfo") ||
             ci_contains(text, "authdaemond") || ci_contains(text, "makeuserdb") ||
             ci_contains(text, "userdb") || ci_contains(text, "userdbpw") ||
             ci_contains(text, "greylistd") || ci_contains(text, "postgrey") ||
             ci_contains(text, "policyd") || ci_contains(text, "sqlgrey") ||
             ci_contains(text, "milter-greylist") || ci_contains(text, "tumgreyspf") ||
             ci_contains(text, "opendkim") || ci_contains(text, "opendmarc") ||
             ci_contains(text, "arcsign") || ci_contains(text, "arcverify") ||
             ci_contains(text, "dkimproxy") || ci_contains(text, "dkimsign") ||
             ci_contains(text, "spfd") || ci_contains(text, "spfquery") ||
             ci_contains(text, "spfmilter") || ci_contains(text, "dspam") ||
             ci_contains(text, "razor-") || ci_contains(text, "dccproc") ||
             ci_contains(text, "dccifd") || ci_contains(text, "dccm") ||
             ci_contains(text, "dblist") || ci_contains(text, "dccd") ||
             ci_contains(text, "dccif") || ci_contains(text, "crm114") ||
             ci_contains(text, "cssutil") || ci_contains(text, "cssdiff") ||
             ci_contains(text, "cssmerge") || ci_contains(text, "mailmanctl") ||
             (ci_contains(text, "mailman") && ci_contains(text, " -")) ||
             (ci_contains(text, "newlist") &&
              !ci_contains(text, "newlisten")) ||
             (ci_contains(text, "rmlist") && !ci_contains(text, "termlist")) || ci_contains(text, "add_members") ||
             ci_contains(text, "remove_members") || ci_contains(text, "sync_members") ||
             ci_contains(text, "find_member") || ci_contains(text, "list_members") ||
             ci_contains(text, "list_lists") || ci_contains(text, "list_owners") ||
             ci_contains(text, "config_list") || ci_contains(text, "withlist") ||
             ci_contains(text, "mmsitepass") || ci_contains(text, "sympa") ||
             ci_contains(text, "ezmlm") || ci_contains(text, "majordomo") ||
             ci_contains(text, "cyradm") || ci_contains(text, "ctl_cyrusdb") ||
             ci_contains(text, "ctl_deliver") || ci_contains(text, "ctl_mboxlist") ||
             ci_contains(text, "cyr_dbtool") || ci_contains(text, "cyr_deny") ||
             ci_contains(text, "cyr_df") || ci_contains(text, "cyr_expire") ||
             ci_contains(text, "cyrdeliver") || ci_contains(text, "ipurge") ||
             ci_contains(text, "mbexamine") || ci_contains(text, "mbpath") ||
             ci_contains(text, "mbpurge") || ci_contains(text, "cyrpasswd") ||
             ci_contains(text, "ptdump") || ci_contains(text, "ptexpire") ||
             (ci_contains(text, "squatter") && ci_contains(text, " -")) || ci_contains(text, "timsieved") ||
             ci_contains(text, "tls_prune") || ci_contains(text, "unexpunge") ||
             ci_contains(text, "cvt_cyrusdb") || ci_contains(text, "mkimap") ||
             ci_contains(text, "lmtpd") || ci_contains(text, "mupdate") ||
             ci_contains(text, "notifyd") || ci_contains(text, "pcscd") ||
             ci_contains(text, "pcsc_scan") || ci_contains(text, "pcsctest") ||
             ci_contains(text, "opensc") || ci_contains(text, "pkcs11") ||
             ci_contains(text, "pkcs15") ||
             (ci_contains(text, "piv") && ci_contains(text, " -")) ||
             ci_contains(text, "openpgp") || ci_contains(text, "pn53x") ||
             ci_contains(text, "acr122") || ci_contains(text, "ykinfo") ||
             ci_contains(text, "ykclient") || ci_contains(text, "ykpam") ||
             ci_contains(text, "yubioath") || ci_contains(text, "yubipiv") ||
             ci_contains(text, "yubitotp") || ci_contains(text, "yubitoken") ||
             ci_contains(text, "ykcs11") || ci_contains(text, "nitropy") ||
             (ci_contains(text, "solo") && ci_contains(text, " -")) ||
             ci_contains(text, "solo1") || ci_contains(text, "solokey") ||
             ci_contains(text, "ledgerctl") || ci_contains(text, "ledgerblue") ||
             ci_contains(text, "ledgerwallet") || ci_contains(text, "trezorctl") ||
             ci_contains(text, "trezor-agent") || ci_contains(text, "ckcc") ||
             ci_contains(text, "softhsm") || ci_contains(text, "yubihsm") ||
             ci_contains(text, "nethsm") || ci_contains(text, "nfkm") ||
             ci_contains(text, "lunacm") || ci_contains(text, "lunash") ||
             ci_contains(text, "ctconf") || ci_contains(text, "ckdemo") ||
             ci_contains(text, "cloudhsm") || ci_contains(text, "key_mgmt_util") ||
             ci_contains(text, "keylime_") || ci_contains(text, "swtpm") ||
             ci_contains(text, "evmctl") ||
             (ci_contains(text, "adcli") && ci_contains(text, " -")) ||
             ci_contains(text, "realmd") || ci_contains(text, "msktutil") ||
             ci_contains(text, "adclient") || ci_contains(text, "adleave") ||
             ci_contains(text, "adflush") || ci_contains(text, "adpasswd") ||
             ci_contains(text, "adquery") || ci_contains(text, "dzdo") ||
             ci_contains(text, "dzsh") || ci_contains(text, "dzjoin") ||
             ci_contains(text, "pbis") || ci_contains(text, "lwconfig") ||
             ci_contains(text, "lwsm") || ci_contains(text, "lsassd") ||
             ci_contains(text, "domainjoin") || ci_contains(text, "vastool") ||
             ci_contains(text, "vasd") || ci_contains(text, "realm join") ||
             ci_contains(text, "net ads join") || ci_contains(text, "net rpc join") ||
             (ci_contains(text, "adjoin") && ci_contains(text, " -")) ||
             ci_contains(text, "sss_useradd") || ci_contains(text, "sss_userdel") ||
             ci_contains(text, "sss_usermod") || ci_contains(text, "sss_obfuscate") ||
             ci_contains(text, "sss_seed") || ci_contains(text, "sss_override") ||
             ci_contains(text, "sss_debuglevel") || ci_contains(text, "pdflatex") ||
             ci_contains(text, "xelatex") || ci_contains(text, "lualatex") ||
             ci_contains(text, "texlua") || ci_contains(text, "texluac") ||
             ci_contains(text, "latexmk") || ci_contains(text, "arara") ||
             ci_contains(text, "tlmgr") || ci_contains(text, "fmtutil") ||
             ci_contains(text, "updmap") || ci_contains(text, "mktexlsr") ||
             ci_contains(text, "texconfig") || ci_contains(text, "texmfstart") ||
             ci_contains(text, "mtxrun") || ci_contains(text, "gnuplot") ||
             ci_contains(text, "mmdc") || ci_contains(text, "plantuml") ||
             ci_contains(text, "contextjit") || ci_contains(text, "texexec") ||
             (ci_contains(text, "latex") &&
              (ci_contains(text, " -") || ci_contains(text, ".tex"))) ||
             (ci_contains(text, "asy") && ci_contains(text, " -")) ||
             (ci_contains(text, "dscacheutil") && ci_contains(text, " -f")) ||
             ci_contains(text, "scutil --set") ||
             (ci_contains(text, "bless") && ci_contains(text, " -")) ||
             (ci_contains(text, "lipo") && ci_contains(text, " -"))) {
        what = "hpc/domainjoin/hsm/dns/mail/privesc/stego/tex primitive";
        }
        else if (ci_contains(text, "wsadmin") || ci_contains(text, "startserver") ||
             ci_contains(text, "stopserver") || ci_contains(text, "wlst") ||
             ci_contains(text, "startweblogic") || ci_contains(text, "nmenroll") ||
             ci_contains(text, "nmkill") || ci_contains(text, "nmexeccmd") ||
             ci_contains(text, "jboss-cli") || ci_contains(text, "asadmin") ||
             ci_contains(text, "imqcmd") ||
             (ci_contains(text, "catalina") && ci_contains(text, " -")) ||
             ci_contains(text, "tcruntime-ctl") || ci_contains(text, "opmnctl") ||
             ci_contains(text, "dcmctl") || ci_contains(text, "oidctl") ||
             ci_contains(text, "bulkload") || ci_contains(text, "bulkmodify") ||
             ci_contains(text, "bulkdelete") || ci_contains(text, "dipassistant") ||
             ci_contains(text, "pkispawn") || ci_contains(text, "pkidestroy") ||
             ci_contains(text, "ipa-server-install") ||
             ci_contains(text, "ipa-replica-") || ci_contains(text, "ipactl") ||
             ci_contains(text, "hdbsql") || ci_contains(text, "hdbcons") ||
             ci_contains(text, "hdblcm") || ci_contains(text, "hdbuserstore") ||
             ci_contains(text, "sapcontrol") || ci_contains(text, "saprouter") ||
             ci_contains(text, "r3trans") || ci_contains(text, "r3load") ||
             ci_contains(text, "oninit") || ci_contains(text, "onmode") ||
             ci_contains(text, "ontape") || ci_contains(text, "dbaccess") ||
             ci_contains(text, "dbexport") || ci_contains(text, "bteq") ||
             ci_contains(text, "fastload") || ci_contains(text, "fastexport") ||
             ci_contains(text, "multiload") || ci_contains(text, "tpump") ||
             ci_contains(text, "vprocmanager") || ci_contains(text, "nzsql") ||
             ci_contains(text, "nzload") || ci_contains(text, "nzbackup") ||
             ci_contains(text, "nzrestore") || ci_contains(text, "gpfdist") ||
             ci_contains(text, "gpload") || ci_contains(text, "gpstart") ||
             ci_contains(text, "gpstop") || ci_contains(text, "gpbackup") ||
             ci_contains(text, "gprestore") || ci_contains(text, "gpssh") ||
             ci_contains(text, "gpcopy") || ci_contains(text, "vsql") ||
             ci_contains(text, "admintools") || ci_contains(text, "mclient") ||
             ci_contains(text, "monetdbd") || ci_contains(text, "fbsql") ||
             ci_contains(text, "gbak") || ci_contains(text, "gfix") ||
             ci_contains(text, "gsec") || ci_contains(text, "nbackup") ||
             ci_contains(text, "fbtracemgr") || ci_contains(text, "prodb") ||
             ci_contains(text, "proutil") || ci_contains(text, "proshut") ||
             ci_contains(text, "probkup") || ci_contains(text, "prorest") ||
             ci_contains(text, "fmsadmin") || ci_contains(text, "fmserverd") ||
             ci_contains(text, "isql") || ci_contains(text, "tsql") ||
             ci_contains(text, "bsqldb") || ci_contains(text, "freebcp") ||
             ci_contains(text, "defncopy") || ci_contains(text, "datacopy") ||
             ci_contains(text, "ddbsh") || ci_contains(text, "ibmcloud") ||
             ci_contains(text, "linode-cli") || ci_contains(text, "vultr-cli") ||
             (ci_contains(text, "exo") && ci_contains(text, " -")) ||
             ci_contains(text, "cloudmonkey") || ci_contains(text, "cmk") ||
             ci_contains(text, "euca-") || ci_contains(text, "ncli") ||
             ci_contains(text, "acli") || ci_contains(text, "dapr") ||
             ci_contains(text, "faas-cli") ||
             (ci_contains(text, "fission") && ci_contains(text, " -")) ||
             ci_contains(text, "nuctl") || ci_contains(text, "wsk") ||
             ci_contains(text, "supabase") || ci_contains(text, "pscale") ||
             ci_contains(text, "neonctl") || ci_contains(text, "turso") ||
             ci_contains(text, "flyway") || ci_contains(text, "liquibase") ||
             ci_contains(text, "atlasgo") || ci_contains(text, "gh-ost") ||
             ci_contains(text, "alembic") ||
             (ci_contains(text, "prisma") && ci_contains(text, " -")) ||
             ci_contains(text, "n98-magerun") || ci_contains(text, "shopify") ||
             ci_contains(text, "kapacitor") || ci_contains(text, "nrpe") ||
             ci_contains(text, "check_nrpe") || ci_contains(text, "centcore") ||
             ci_contains(text, "centengine") || ci_contains(text, "gmond") ||
             ci_contains(text, "gmetad") || ci_contains(text, "gmetric") ||
             ci_contains(text, "rrdcached") || ci_contains(text, "munin-node") ||
             ci_contains(text, "munin-run") || ci_contains(text, "carbon-cache") ||
             ci_contains(text, "whisper-") || ci_contains(text, "vmagent") ||
             ci_contains(text, "vmalert") || ci_contains(text, "vmbackup") ||
             (ci_contains(text, "thanos") && ci_contains(text, " -")) ||
             (ci_contains(text, "cortex") && ci_contains(text, " -")) ||
             ci_contains(text, "logcli") ||
             (ci_contains(text, "promtool") && ci_contains(text, " -")) ||
             ci_contains(text, "pmacct") || ci_contains(text, "nfacctd") ||
             ci_contains(text, "sfacctd") || ci_contains(text, "nfdump") ||
             ci_contains(text, "nfcapd") ||
             (ci_contains(text, "silk") && ci_contains(text, " -")) ||
             ci_contains(text, "yaf") || ci_contains(text, "softflowd") ||
             ci_contains(text, "agent_control") || ci_contains(text, "fleetctl") ||
             (ci_contains(text, "velociraptor") && ci_contains(text, " -")) ||
             ci_contains(text, "oscap") || ci_contains(text, "autotailor") ||
             ci_contains(text, "mpcmdrun") || ci_contains(text, "repcli") ||
             ci_contains(text, "reputil") || ci_contains(text, "cbdaemon") ||
             (ci_contains(text, "parity") && ci_contains(text, " -")) ||
             ci_contains(text, "kesl-control") || ci_contains(text, "klnagent") ||
             ci_contains(text, "esets_") || ci_contains(text, "savdctl") ||
             (ci_contains(text, "sweep") && ci_contains(text, " -")) ||
             ci_contains(text, "maconfig") || ci_contains(text, "msainfo") ||
             ci_contains(text, "uvscan") || ci_contains(text, "cmdscan") ||
             ci_contains(text, "mfemactl") || ci_contains(text, "bdscan") ||
             ci_contains(text, "bdcheck") || ci_contains(text, "sigtool") ||
             ci_contains(text, "a2cmd") || ci_contains(text, "fsav") ||
             ci_contains(text, "avscan") || ci_contains(text, "avconfig") ||
             ci_contains(text, "pavsig") || ci_contains(text, "psanhost") ||
             ci_contains(text, "sbamscan") || ci_contains(text, "wrsa") ||
             ci_contains(text, "cylancesvc") || ci_contains(text, "cyoptics") ||
             ci_contains(text, "xagt") || ci_contains(text, "feagent") ||
             ci_contains(text, "hxagent") || ci_contains(text, "hurukai") ||
             ci_contains(text, "taniumclient") || ci_contains(text, "fw ctl") ||
             ci_contains(text, "fwm ") || ci_contains(text, "cpconfig") ||
             ci_contains(text, "cphaprob") || ci_contains(text, "cpwd") ||
             ci_contains(text, "cpinfo") || ci_contains(text, "pan_comm") ||
             ci_contains(text, "panxapi") || ci_contains(text, "fcconfig") ||
             ci_contains(text, "fnsysctl") || ci_contains(text, "fnbamd") ||
             ci_contains(text, "phionctrl") || ci_contains(text, "acpf") ||
             ci_contains(text, "cgtool") || ci_contains(text, "ngfirewall") ||
             ci_contains(text, "ngadmin") || ci_contains(text, "confd") ||
             (ci_contains(text, "awed") && ci_contains(text, " -")) ||
             ci_contains(text, "midd") || ci_contains(text, "routeros") ||
             (ci_contains(text, "dude") && ci_contains(text, " -") &&
              !ci_contains(text, "avrdude")) ||
             ci_contains(text, "capsman") || ci_contains(text, "userman") ||
             ci_contains(text, "unms") || ci_contains(text, "ucrm") ||
             ci_contains(text, "edgeos") || ci_contains(text, "vyatta") ||
             ci_contains(text, "vyos") || ci_contains(text, "vbash") ||
             ci_contains(text, "bigpipe") ||
             (ci_contains(text, "icontrol") && ci_contains(text, " -")) ||
             ci_contains(text, "tmctl") || ci_contains(text, "bigstart") ||
             ci_contains(text, "mcpd") || ci_contains(text, "restjavad") ||
             (ci_contains(text, "sod") && !ci_contains(text, "sodium") &&
              !ci_contains(text, "episode") && !ci_contains(text, "soda")) ||
             ci_contains(text, "tmm") ||
             (ci_contains(text, "nscli") && !ci_contains(text, "dnsclient")) ||
             ci_contains(text, "nsconmsg") || ci_contains(text, "nstrace") ||
             ci_contains(text, "nstcpdump") || ci_contains(text, "nssavecore") ||
             (ci_contains(text, "nsstats") && !ci_contains(text, "dnsstats")) ||
             ci_contains(text, "nswfs") || ci_contains(text, "nswl") ||
             ci_contains(text, "aaad") || ci_contains(text, "mgd") ||
             ci_contains(text, "jsnap") || ci_contains(text, "jnpr") ||
             ci_contains(text, "contrail") ||
             (ci_contains(text, "mist") && ci_contains(text, " -")) ||
             ci_contains(text, "airwave") || ci_contains(text, "clearpass") ||
             ci_contains(text, "cppm") || ci_contains(text, "vsh") ||
             ci_contains(text, "dcnm") || ci_contains(text, "ncs_cli") ||
             ci_contains(text, "apic") ||
             (ci_contains(text, "sum") && ci_contains(text, " -")) ||
             ci_contains(text, "onecli") ||
             (ci_contains(text, "asu") && ci_contains(text, " -")) ||
             ci_contains(text, "xclarity") || ci_contains(text, "ilomconfig") ||
             ci_contains(text, "itpconfig") || ci_contains(text, "hwmgmtcli") ||
             ci_contains(text, "ubiosconfig") || ci_contains(text, "biosconfig") ||
             ci_contains(text, "conrep") || ci_contains(text, "ssaducli") ||
             (ci_contains(text, "omconfig") && ci_contains(text, " -")) ||
             ci_contains(text, "omreport") ||
             ci_contains(text, "srvadmin") || ci_contains(text, "idracadm") ||
             (ci_contains(text, "racadm") && ci_contains(text, " -")) ||
             ci_contains(text, "dsu") ||
             ci_contains(text, "horcm") || ci_contains(text, "raidcom") ||
             ci_contains(text, "pairsplit") || ci_contains(text, "paircreate") ||
             ci_contains(text, "naviseccli") || ci_contains(text, "powermt") ||
             ci_contains(text, "emcpadm") || ci_contains(text, "3paradm") ||
             ci_contains(text, "pureadmin") || ci_contains(text, "purevol") ||
             (ci_contains(text, "isi") && ci_contains(text, " -")) ||
             ci_contains(text, "vserver") || ci_contains(text, "ontapcli") ||
             ci_contains(text, "asmb") || ci_contains(text, "aswm") ||
             ci_contains(text, "asmc") || ci_contains(text, "dsmc") ||
             ci_contains(text, "dsmcad") || ci_contains(text, "bpbackup") ||
             ci_contains(text, "bprestore") || ci_contains(text, "bplist") ||
             ci_contains(text, "simpana") || ci_contains(text, "qoperation") ||
             ci_contains(text, "qcommand") || ci_contains(text, "cvcl") ||
             ci_contains(text, "veeamconfig") || ci_contains(text, "acrocmd") ||
             ci_contains(text, "duply") || ci_contains(text, "borgmatic") ||
             ci_contains(text, "backuppc_") || ci_contains(text, "b2-linux") ||
             ci_contains(text, "crashplan") || ci_contains(text, "code42") ||
             (ci_contains(text, "ditto") && ci_contains(text, " -")) ||
             ci_contains(text, "revsocks") ||
             (ci_contains(text, "stowaway") && ci_contains(text, " -")) ||
             (ci_contains(text, "xray") && ci_contains(text, " -") &&
              !ci_contains(text, "--version")) ||
             (ci_contains(text, "clash") && ci_contains(text, " -")) ||
             ci_contains(text, "hysteria") ||
             (ci_contains(text, "brook") && ci_contains(text, " -")) ||
             ci_contains(text, "ipt2socks") || ci_contains(text, "trojan-go") ||
             (ci_contains(text, "inlets") && ci_contains(text, " -")) ||
             ci_contains(text, "interactsh-") ||
             (ci_contains(text, "meek") && ci_contains(text, " -")) ||
             (ci_contains(text, "snowflake") && ci_contains(text, " -")) ||
             ci_contains(text, "webtunnel") || ci_contains(text, "onionshare") ||
             ci_contains(text, "onionbalance") || ci_contains(text, "sipsak") ||
             ci_contains(text, "svreport") || ci_contains(text, "svcrash") ||
             ci_contains(text, "pjsystest") || ci_contains(text, "opensipsctl") ||
             ci_contains(text, "osipsconsole") || ci_contains(text, "fs_ctl") ||
             ci_contains(text, "fsctl") || ci_contains(text, "gnugk") ||
             ci_contains(text, "ohphone") || ci_contains(text, "simph323") ||
             (ci_contains(text, "amm") && ci_contains(text, " -")) ||
             ci_contains(text, "coursier") ||
             (ci_contains(text, "ros") && ci_contains(text, " -")) ||
             (ci_contains(text, "gambit") && ci_contains(text, " -")) ||
             ci_contains(text, "nuitka") || ci_contains(text, "pyinstaller") ||
             ci_contains(text, "cx_freeze") || (ci_contains(text, "pex") && !ci_contains(text, "apex")) ||
             ci_contains(text, "shiv") || ci_contains(text, "pyoxidizer") ||
             ci_contains(text, "cython") || ci_contains(text, "wasmtime") ||
             ci_contains(text, "wasmer") || ci_contains(text, "wasmedge") ||
             ci_contains(text, "iwasm") ||
             (ci_contains(text, "spin") && ci_contains(text, " -")) ||
             ci_contains(text, "native-image") ||
             (ci_contains(text, "gu") && ci_contains(text, " -") &&
              !ci_contains(text, "pkgutil")) ||
             ci_contains(text, "zmodload") ||
             ci_contains(text, "basher") || ci_contains(text, "zinit") ||
             (ci_contains(text, "sheldon") && ci_contains(text, " -")) ||
             (ci_contains(text, "fisher") && ci_contains(text, " -")) ||
             (ci_contains(text, "mise") && ci_contains(text, " -")) ||
             ci_contains(text, "asdf") ||
             (ci_contains(text, "rtx") && ci_contains(text, " -")) ||
             (ci_contains(text, "proto") && ci_contains(text, " -")) ||
             (ci_contains(text, "aqua") && ci_contains(text, " -")) ||
             (ci_contains(text, "ubi") && ci_contains(text, " -")) ||
             (ci_contains(text, "eget") && ci_contains(text, " -")) ||
             ci_contains(text, "topgrade") || ci_contains(text, "lefthook") ||
             (ci_contains(text, "husky") && ci_contains(text, " -")) ||
             ci_contains(text, "lint-staged") ||
             (ci_contains(text, "overcommit") && ci_contains(text, " -")) ||
             ci_contains(text, "mmctl") || ci_contains(text, "zulip-send") ||
             ci_contains(text, "murmurd") || ci_contains(text, "ts3server") ||
             ci_contains(text, "tsdns") || ci_contains(text, "matterbridge") ||
             ci_contains(text, "xmodmap") || ci_contains(text, "xkbcomp") ||
             ci_contains(text, "xset") || ci_contains(text, "xwud") ||
             ci_contains(text, "jackrec") ||
             (ci_contains(text, "maim") && ci_contains(text, " -")) ||
             (ci_contains(text, "grim") && ci_contains(text, " -")) ||
             (ci_contains(text, "v4l2-ctl") && (ci_contains(text, "--set") ||
              ci_contains(text, "--stream") || ci_contains(text, " -d"))) ||
             (ci_contains(text, "motion") && ci_contains(text, " -") &&
              !ci_contains(text, "motion -h") &&
              !ci_contains(text, "motion --help")) ||
             ci_contains(text, "lkl") || ci_contains(text, "uberkey") ||
             ci_contains(text, "kea-") || ci_contains(text, "keactrl") ||
             ci_contains(text, "kea-shell") || ci_contains(text, "kea-dhcp-ddns") ||
             ci_contains(text, "kea-netconf") || ci_contains(text, "dhcpd") ||
             ci_contains(text, "dhcptest") || ci_contains(text, "dhcpdump") ||
             ci_contains(text, "dhcpstarv") || ci_contains(text, "dhcpig") ||
             ci_contains(text, "dibbler-")) {
        what = "appserver/db/monitoring/edr/netdev/bmc/backup/tunnel/exec primitive";
        }
        else if (ci_contains(text, "fls") ||
             (ci_contains(text, "istat") && ci_contains(text, " -")) ||
             ci_contains(text, "img_stat") || ci_contains(text, "fsstat") ||
             ci_contains(text, "srch_strings") ||
             (ci_contains(text, "foremost") && ci_contains(text, " -")) ||
             (ci_contains(text, "scalpel") && ci_contains(text, " -")) ||
             ci_contains(text, "mac-robber") || ci_contains(text, "hfind") ||
             (ci_contains(text, "sorter") && ci_contains(text, " -")) ||
             ci_contains(text, "sigfind") || ci_contains(text, "jcat") ||
             ci_contains(text, "vol.py") || ci_contains(text, "vol3") ||
             ci_contains(text, "memprocfs") || ci_contains(text, "pmem") ||
             (ci_contains(text, "lime") && ci_contains(text, " -")) ||
             ci_contains(text, "ramcapture") || ci_contains(text, "dumplt") ||
             ci_contains(text, "wimcapture") || ci_contains(text, "wimapply") ||
             ci_contains(text, "wimlib") || ci_contains(text, "dism++") ||
             ci_contains(text, "bootice") ||
             (ci_contains(text, "reagentc") &&
              (ci_contains(text, " /set") || ci_contains(text, " /disable") ||
               ci_contains(text, " /boottarge"))) ||
             ci_contains(text, "partclone") || ci_contains(text, "ntfsclone") ||
             ci_contains(text, "fsarchiver") || ci_contains(text, "partimage") ||
             ci_contains(text, "clonezilla") || ci_contains(text, "ocs-sr") ||
             ci_contains(text, "ocs-onthefly") || ci_contains(text, "ntfscat") ||
             ci_contains(text, "ntfsfix") || ci_contains(text, "ntfsls") ||
             ci_contains(text, "ext3grep") ||
             ci_contains(text, "mkntfs") || ci_contains(text, "exfatlabel") ||
             ci_contains(text, "udfinfo") || ci_contains(text, "xorrisofs") ||
             ci_contains(text, "genisoimage") || ci_contains(text, "isohybrid") ||
             (ci_contains(text, "rufus") && ci_contains(text, " -")) ||
             (ci_contains(text, "etcher") && ci_contains(text, " -")) ||
             ci_contains(text, "rpi-imager") || ci_contains(text, "ventoy") ||
             ci_contains(text, "readpst") || ci_contains(text, "pst2ldif") ||
             ci_contains(text, "lspst") || ci_contains(text, "pffexport") ||
             ci_contains(text, "evtxexport") || ci_contains(text, "regexport") ||
             ci_contains(text, "sbag") || ci_contains(text, "amcacheparser") ||
             ci_contains(text, "jumplist") || ci_contains(text, "lnkanalyzer") ||
             ci_contains(text, "pf.exe") || ci_contains(text, "usnjrnl") ||
             ci_contains(text, "msiecfexport") || ci_contains(text, "olecfexport") ||
             ci_contains(text, "lnkexport") || ci_contains(text, "wminfo") ||
             ci_contains(text, "pyluina") || ci_contains(text, "libesedb") ||
             ci_contains(text, "bkhive") || ci_contains(text, "clipman") ||
             ci_contains(text, "tesseract") || (ci_contains(text, "gocr") && ci_contains(text, " -")) ||
             ci_contains(text, "ocrmypdf") ||
             (ci_contains(text, "aider") && ci_contains(text, " -")) ||
             ci_contains(text, "claude-code") || ci_contains(text, "cursor-agent") ||
             (ci_contains(text, "opencode") && ci_contains(text, " -")) ||
             (ci_contains(text, "codex") && ci_contains(text, " -")) ||
             (ci_contains(text, "gemini") && ci_contains(text, " -")) ||
             ci_contains(text, "llxprt") ||
             (ci_contains(text, "llm") && ci_contains(text, " -")) ||
             (ci_contains(text, "mods") && ci_contains(text, " -")) ||
             (ci_contains(text, "fabric") && ci_contains(text, " -")) ||
             ci_contains(text, "aichat") || ci_contains(text, "tgpt") ||
             ci_contains(text, "shell_gpt") || ci_contains(text, "sgpt") ||
             ci_contains(text, "yai") || ci_contains(text, "plz") ||
             (ci_contains(text, "ask") && ci_contains(text, " -") &&
              !ci_contains(text, "taskkill") &&
              !ci_contains(text, "taskset")) ||
             (ci_contains(text, "howto") && ci_contains(text, " -")) ||
             (ci_contains(text, "copilot") && ci_contains(text, " -")) ||
             ci_contains(text, "oidc-agent") || ci_contains(text, "oidc-token") ||
             ci_contains(text, "gtoken") || ci_contains(text, "jwtgen") ||
             ci_contains(text, "jose") || ci_contains(text, "cmctl") ||
             ci_contains(text, "dexctl") ||
             ci_contains(text, "kratos") || ci_contains(text, "oathkeeper") ||
             ci_contains(text, "authelia") || ci_contains(text, "kcadm") ||
             ci_contains(text, "berglas") ||
             ci_contains(text, "credhub") ||
             ci_contains(text, "envchain") || ci_contains(text, "conjur") ||
             ci_contains(text, "secrethub") ||
             ci_contains(text, "keywhiz") || ci_contains(text, "akeyless") ||
             (ci_contains(text, "boundary") && ci_contains(text, " -")) ||
             ci_contains(text, "afl-fuzz") || ci_contains(text, "honggfuzz") ||
             ci_contains(text, "syzkaller") || ci_contains(text, "winafl") ||
             ci_contains(text, "boofuzz") || ci_contains(text, "zzuf") ||
             ci_contains(text, "radamsa") || ci_contains(text, "sulley") ||
             ci_contains(text, "domato") || ci_contains(text, "jazzer") ||
             ci_contains(text, "litmusctl") || ci_contains(text, "chaosd") ||
             ci_contains(text, "chaosblade") || ci_contains(text, "pumba") ||
             ci_contains(text, "kraken") || ci_contains(text, "airbyte") ||
             ci_contains(text, "singer") || ci_contains(text, "meltano") ||
             ci_contains(text, "dlt") || ci_contains(text, "debezium") ||
             ci_contains(text, "maxwell") || ci_contains(text, "canal") ||
             (ci_contains(text, "beam") && ci_contains(text, " -")) ||
             ci_contains(text, "prefect") ||
             ci_contains(text, "dagster") || ci_contains(text, "luigi") ||
             ci_contains(text, "dbt") || ci_contains(text, "metabase") ||
             ci_contains(text, "superset") || ci_contains(text, "mlflow") ||
             ci_contains(text, "dvc") || ci_contains(text, "kubeflow") ||
             ci_contains(text, "clearml") || ci_contains(text, "wandb") ||
             ci_contains(text, "sagemaker") || ci_contains(text, "aziotctl") ||
             ci_contains(text, "iotedge") || ci_contains(text, "greengrass") ||
             ci_contains(text, "particle") || ci_contains(text, "balena") ||
             ci_contains(text, "steamcmd") || ci_contains(text, "lutris") ||
             ci_contains(text, "protontricks") || ci_contains(text, "winetricks") ||
             ci_contains(text, "dosbox") || ci_contains(text, "virt-viewer") ||
             ci_contains(text, "weylus") || 
             ci_contains(text, "dayon") || ci_contains(text, "meshcmd") ||
             ci_contains(text, "kvmd") || ci_contains(text, "pikvm") ||
             ci_contains(text, "tinypilot") || ci_contains(text, "jetkvm") ||
             ci_contains(text, "runtipi") || ci_contains(text, "umbrel") ||
             ci_contains(text, "casaos") || ci_contains(text, "yunohost") ||
             ci_contains(text, "sandstorm") || ci_contains(text, "freedombox") ||
             ci_contains(text, "homelabos") || ci_contains(text, "dockge") ||
             ci_contains(text, "portainer") || ci_contains(text, "yacht") ||
             ci_contains(text, "komodo") || ci_contains(text, "dozzle") ||
             ci_contains(text, "lazydocker") ||
             (ci_contains(text, "lens") && ci_contains(text, " -")) ||
             ci_contains(text, "headlamp") ||
             (ci_contains(text, "octant") && ci_contains(text, " -")) ||
             ci_contains(text, "kubedashboard") || ci_contains(text, "weave-scope") ||
             (ci_contains(text, "grafana") && ci_contains(text, " -")) ||
             (ci_contains(text, "alloy") && ci_contains(text, " -")) ||
             ci_contains(text, "promtail") ||
             (ci_contains(text, "mimir") && ci_contains(text, " -")) ||
             (ci_contains(text, "loki") && ci_contains(text, " -")) ||
             (ci_contains(text, "tempo") && ci_contains(text, " -")) ||
             ci_contains(text, "pyroscope") ||
             (ci_contains(text, "faro") && ci_contains(text, " -")) ||
             (ci_contains(text, "kuma") && ci_contains(text, " -")) ||
             ci_contains(text, "kumactl") ||
             (ci_contains(text, "osm") && ci_contains(text, " -")) ||
             ci_contains(text, "glooctl") || ci_contains(text, "edgectl") ||
             (ci_contains(text, "contour") && ci_contains(text, " -")) ||
             ci_contains(text, "emissary") ||
             ci_contains(text, "solo-io") || ci_contains(text, "cmctl") ||
             ci_contains(text, "spire-agent") || ci_contains(text, "spiffe") ||
             ci_contains(text, "in-toto") ||
             (ci_contains(text, "witness") && ci_contains(text, " -")) ||
             ci_contains(text, "vexctl") ||
             (ci_contains(text, "bom") && ci_contains(text, " -")) ||
             ci_contains(text, "kritis") || ci_contains(text, "kyverno") ||
             (ci_contains(text, "gatekeeper") && ci_contains(text, " -")) ||
             ci_contains(text, "falcoctl") ||
             (ci_contains(text, "tetragon") && ci_contains(text, " -")) ||
             ci_contains(text, "pwru") ||
             ci_contains(text, "inspektor") || ci_contains(text, "kubeshark") ||
             ci_contains(text, "kubepug") ||
             (ci_contains(text, "pluto") && ci_contains(text, " -")) ||
             (ci_contains(text, "popeye") && ci_contains(text, " -")) ||
             ci_contains(text, "krr") ||
             (ci_contains(text, "robusta") && ci_contains(text, " -")) ||
             ci_contains(text, "holmesgpt") ||
             ci_contains(text, "kagent") || ci_contains(text, "kmctl") ||
             ci_contains(text, "kgctl") || ci_contains(text, "gitea") ||
             ci_contains(text, "gitbucket") || ci_contains(text, "gitlab-ctl") ||
             ci_contains(text, "bucket4j") ||
             (ci_contains(text, "arc") && ci_contains(text, " -")) ||
             (ci_contains(text, "arcanist") && ci_contains(text, " -")) ||
             ci_contains(text, "phab") ||
             ci_contains(text, "repo init") || ci_contains(text, "repo sync") ||
             ci_contains(text, "repo upload") || ci_contains(text, "git-review") ||
             ci_contains(text, "git-imerge") || ci_contains(text, "git-absorb") ||
             ci_contains(text, "git-revise") || ci_contains(text, "ghq") ||
             (ci_contains(text, "hub") && ci_contains(text, " -")) ||
             (ci_contains(text, "laconic") && ci_contains(text, " -")) ||
             ci_contains(text, "git-lfs") ||
             (ci_contains(text, "dolt") && ci_contains(text, " -")) ||
             ci_contains(text, "lakefs") || ci_contains(text, "xet") ||
             (ci_contains(text, "zookeeper") && ci_contains(text, " -")) ||
             ci_contains(text, "etcdkeeper") || ci_contains(text, "consul-template") ||
             (ci_contains(text, "vaulted") && ci_contains(text, " -")) ||
             ci_contains(text, "approle") || ci_contains(text, "pomerium") ||
             ci_contains(text, "oauth2-proxy") ||
             (ci_contains(text, "dex") && ci_contains(text, " -") &&
              !ci_contains(text, "index")) ||
             (ci_contains(text, "teleport") && ci_contains(text, " -")) ||
             (ci_contains(text, "tbot") && !ci_contains(text, "certbot")) || ci_contains(text, "boundary-worker") ||
             ci_contains(text, "openbao") ||
             (ci_contains(text, "bao") && ci_contains(text, " -")) ||
             (ci_contains(text, "doppler") && ci_contains(text, " -")) ||
             ci_contains(text, "openfga") || ci_contains(text, "fga") ||
             (ci_contains(text, "topaz") && ci_contains(text, " -")) ||
             ci_contains(text, "aserto") ||
             (ci_contains(text, "permit") && ci_contains(text, " -")) ||
             (ci_contains(text, "oso") && ci_contains(text, " -")) ||
             (ci_contains(text, "cedar") && ci_contains(text, " -")) ||
             ci_contains(text, "xacml") ||
             (ci_contains(text, "sentinel") && ci_contains(text, " -")) ||
             (ci_contains(text, "regal") && ci_contains(text, " -")) ||
             (ci_contains(text, "polaris") && ci_contains(text, " -")) ||
             ci_contains(text, "kubescape") || ci_contains(text, "kube-score") ||
             ci_contains(text, "kube-linter") || ci_contains(text, "kubeval") ||
             ci_contains(text, "kubeaudit") || ci_contains(text, "kubesec") ||
             ci_contains(text, "kubereport") || ci_contains(text, "kuttl") ||
             (ci_contains(text, "chaos") && ci_contains(text, " -")) ||
             ci_contains(text, "k0sctl") || ci_contains(text, "rke2") ||
             ci_contains(text, "microk8s") ||
             ci_contains(text, "vcluster") ||
             (ci_contains(text, "loft") && ci_contains(text, " -")) ||
             (ci_contains(text, "capsule") && ci_contains(text, " -")) ||
             ci_contains(text, "kamaji") || ci_contains(text, "hyperv") ||
             ci_contains(text, "okd") ||
             (ci_contains(text, "crc") && ci_contains(text, " -")) ||
             ci_contains(text, "minishift") ||
             (ci_contains(text, "rosa") && ci_contains(text, " -")) ||
             (ci_contains(text, "aro") && ci_contains(text, " -") && !ci_contains(text, "paro")) ||
             ci_contains(text, "eksctl") || ci_contains(text, "aks-engine") ||
             ci_contains(text, "clusterawsadm") || ci_contains(text, "clusterctl") ||
             ci_contains(text, "kops") || ci_contains(text, "kubespray") ||
             ci_contains(text, "kubeasz") ||
             ci_contains(text, "kubekey") ||
             (ci_contains(text, "kk") && ci_contains(text, " -") &&
              !ci_contains(text, "taskkill")) ||
             ci_contains(text, "sealos") || ci_contains(text, "rancherd") ||
             (ci_contains(text, "fleet") && ci_contains(text, " -")) ||
             (ci_contains(text, "elemental") && ci_contains(text, " -")) ||
             (ci_contains(text, "harvester") && ci_contains(text, " -")) ||
             ci_contains(text, "epinio") ||
             (ci_contains(text, "waypoint") && ci_contains(text, " -")) ||
             ci_contains(text, "nocalhost") ||
             (ci_contains(text, "garden") && ci_contains(text, " -")) ||
             ci_contains(text, "okteto") || ci_contains(text, "bridge-to-kubernetes") ||
             (ci_contains(text, "tanka") && ci_contains(text, " -")) ||
             ci_contains(text, "jsonnet") ||
             (ci_contains(text, "cue") && ci_contains(text, " -")) ||
             ci_contains(text, "dhall") ||
             (ci_contains(text, "hcl") && !ci_contains(text, "dhclient") &&
              !ci_contains(text, "hcloud")) ||
             ci_contains(text, "starlark") ||
             (ci_contains(text, "tilt") && ci_contains(text, " -")) ||
             ci_contains(text, "sko") || ci_contains(text, "chainguard") ||
             (ci_contains(text, "melange") && ci_contains(text, " -")) ||
             ci_contains(text, "apko") || ci_contains(text, "wolfictl") ||
             (ci_contains(text, "undock") && ci_contains(text, " -")) ||
             ci_contains(text, "image-spec") || ci_contains(text, "regclient") ||
             ci_contains(text, "regbot") || ci_contains(text, "regsync") ||
             ci_contains(text, "cinc") ||
             (ci_contains(text, "inspec") && !ci_contains(text, "pythoninspect")) ||
             ci_contains(text, "chef-apply") || ci_contains(text, "test-kitchen") ||
             (ci_contains(text, "kitchen") && ci_contains(text, " -")) ||
             (ci_contains(text, "molecule") && ci_contains(text, " -")) ||
             (ci_contains(text, "goss") && ci_contains(text, " -") &&
              !ci_contains(text, "gossa")) || ci_contains(text, "gossa") ||
             ci_contains(text, "serverspec") || ci_contains(text, "ansible-vault") ||
             ci_contains(text, "ansible-galaxy") ||
             ci_contains(text, "salt-call") ||
             ci_contains(text, "salt-run") || ci_contains(text, "salt-cloud") ||
             ci_contains(text, "cfengine") || ci_contains(text, "cf-agent") ||
             ci_contains(text, "cf-key") || ci_contains(text, "bcfg2") ||
             (ci_contains(text, "puppet") &&
              (ci_contains(text, " resource") || ci_contains(text, " apply") ||
               ci_contains(text, " run"))) ||
             ci_contains(text, "r10k") ||
             (ci_contains(text, "facter") && ci_contains(text, " -")) ||
             ci_contains(text, "hiera") || ci_contains(text, "eyaml") ||
             ci_contains(text, "terragrunt") || ci_contains(text, "tfenv") ||
             ci_contains(text, "tfswitch") ||
             (ci_contains(text, "tofu") && ci_contains(text, " -")) ||
             ci_contains(text, "openbao") || ci_contains(text, "valut") ||
             ci_contains(text, "runecast") || ci_contains(text, "env0") ||
             ci_contains(text, "spacelift") || ci_contains(text, "env0ctl") ||
             ci_contains(text, "brainboard") || ci_contains(text, "inframap") ||
             ci_contains(text, "terraformer") || ci_contains(text, "tf2pulumi") ||
             ci_contains(text, "former2") || ci_contains(text, "aztfexport") ||
             ci_contains(text, "terraforming") || ci_contains(text, "terracognita")) {
        what = "forensics/idp/fuzz/chaos/data/ml/k8s/iac/git/llm/img primitive";
        }
        
        else if (ci_contains(text, "owneredit.py") || ci_contains(text, "ticketconverter.py") ||
             ci_contains(text, "services.py") || ci_contains(text, "reg.py") ||
             ci_contains(text, "sniffer.py") || ci_contains(text, "rdp_check.py") ||
             ci_contains(text, "mssqlclient.py") ||
             (ci_contains(text, "sliver") && ci_contains(text, " -")) ||
             (ci_contains(text, "mythic") && ci_contains(text, " -")) ||
             (ci_contains(text, "havoc") && ci_contains(text, " -")) ||
             (ci_contains(text, "covenant") && ci_contains(text, " -")) ||
             (ci_contains(text, "merlin") && ci_contains(text, " -")) ||
             (ci_contains(text, "empire") && ci_contains(text, " -")) ||
             ci_contains(text, "poshc2") ||
             ci_contains(text, "koadic") ||
             (ci_contains(text, "deimos") && ci_contains(text, " -")) ||
             ci_contains(text, "wso") || ci_contains(text, "b374k") ||
             (ci_contains(text, "chopper") && ci_contains(text, " -")) ||
             ci_contains(text, "kubeletctl") ||
             (ci_contains(text, "cdk") && ci_contains(text, " -")) ||
             (ci_contains(text, "donut") && ci_contains(text, " -")) ||
             ci_contains(text, "avet") || ci_contains(text, "bdf") ||
             ci_contains(text, "cymothoa") ||
             (ci_contains(text, "unicorn") && ci_contains(text, " -")) ||
             ci_contains(text, "msfpc") || ci_contains(text, "revshells") ||
             ci_contains(text, "phpsploit") ||
             (ci_contains(text, "beef") && ci_contains(text, " -")) ||
             (ci_contains(text, "meg") && ci_contains(text, " -") &&
              !ci_contains(text, "omega")) ||
             ci_contains(text, "gowitness") || ci_contains(text, "aquatone") ||
             ci_contains(text, "eyewitness") || ci_contains(text, "wafw00f") ||
             (ci_contains(text, "nikto") && ci_contains(text, " -")) ||
             (ci_contains(text, "zap") && ci_contains(text, " -") &&
              !ci_contains(text, "zapier")) ||
             (ci_contains(text, "burp") && ci_contains(text, " -")) ||
             ci_contains(text, "tplmap") || ci_contains(text, "kxss") ||
             ci_contains(text, "gopherus") ||
             /* web terminals / hosting panels */
             ci_contains(text, "mosh-server") ||
             ci_contains(text, "ttyd") || ci_contains(text, "gotty") ||
             ci_contains(text, "wetty") || ci_contains(text, "shellinaboxd") ||
             ci_contains(text, "webssh") || ci_contains(text, "sshwifty") ||
             ci_contains(text, "cockpit") || ci_contains(text, "webmin") ||
             ci_contains(text, "usermin") || ci_contains(text, "virtualmin") ||
             ci_contains(text, "ajenti") || ci_contains(text, "froxlor") ||
             ci_contains(text, "vesta") || ci_contains(text, "hestia") ||
             ci_contains(text, "cyberpanel") || ci_contains(text, "aapanel") ||
             ci_contains(text, "cpanel") || ci_contains(text, "whmapi1") ||
             ci_contains(text, "uapi") || ci_contains(text, "plesk") ||
             ci_contains(text, "directadmin") || ci_contains(text, "imscp") ||
             ci_contains(text, "ispconfig") || ci_contains(text, "sentora") ||
             ci_contains(text, "keyhelp") ||
             (ci_contains(text, "enhance") && ci_contains(text, " -")) ||
             ci_contains(text, "solusvm") || ci_contains(text, "virtualizor") ||
             ci_contains(text, "runcloud") || ci_contains(text, "serverpilot") ||
             ci_contains(text, "ploi") || ci_contains(text, "gridpanel") ||
             (ci_contains(text, "moss") && ci_contains(text, " -")) ||
             /* selinux / apparmor policy control */
             ci_contains(text, "setenforce 0") ||
             (ci_contains(text, "semanage") &&
              (ci_contains(text, " -a") || ci_contains(text, " -m") ||
               ci_contains(text, " -d") || ci_contains(text, " -D"))) ||
             (ci_contains(text, "semodule") &&
              (ci_contains(text, " -i") || ci_contains(text, " -r") ||
               ci_contains(text, " -R") || ci_contains(text, " -u") ||
               ci_contains(text, " -e") || ci_contains(text, " -d") ||
               ci_contains(text, " -X"))) ||
             (ci_contains(text, "getsebool") && ci_contains(text, " -")) ||
             (ci_contains(text, "setsebool") && ci_contains(text, " -")) || ci_contains(text, "audit2allow") ||
             ci_contains(text, "aa-complain") || ci_contains(text, "aa-enforce") ||
             ci_contains(text, "aa-disable") || ci_contains(text, "apparmor_parser") ||
             ci_contains(text, "tomoyo") || ci_contains(text, "gradm") ||
             /* backup → exfil */
             (ci_contains(text, "restic") && ci_contains(text, " -") &&
              !ci_contains(text, "--version")) ||
             (ci_contains(text, "duplicity") && ci_contains(text, " -") &&
              !ci_contains(text, "--version")) ||
             ci_contains(text, "vdump") ||
             /* bootloader / initramfs rewrite */
             ci_contains(text, "mkinitramfs") || ci_contains(text, "update-initramfs") ||
             ci_contains(text, "mkinitrd") ||
             ci_contains(text, "update-grub") || ci_contains(text, "grub-install") ||
             ci_contains(text, "grub2-install") ||
             /* big data exec */
             ci_contains(text, "spark-submit") || ci_contains(text, "spark-shell") ||
             ci_contains(text, "pyspark") ||
             ci_contains(text, "hdfs dfs -put") || ci_contains(text, "hadoop fs -put") ||
             (ci_contains(text, "yarn") && ci_contains(text, " -") &&
              !ci_contains(text, "--version")) ||
             ci_contains(text, "hbase") || ci_contains(text, "cypher-shell") ||
             
             ci_contains(text, "duckdb") ||
             /* mq */
             (ci_contains(text, "emqx") &&
              (ci_contains(text, " ctl") || ci_contains(text, " eval") ||
               ci_contains(text, " stop") || ci_contains(text, " kill") ||
               ci_contains(text, " restart") || ci_contains(text, " reload"))) ||
             ci_contains(text, "vernemq") ||
             (ci_contains(text, "nats") && ci_contains(text, " -") &&
              !ci_contains(text, "gnats")) ||
             (ci_contains(text, "nsq") && !ci_contains(text, "dnsquery")) ||
             /* ebpf snoop / tracing */
             ci_contains(text, "mountsnoop") || ci_contains(text, "syncsnoop") ||
             ci_contains(text, "ttysnoop") || ci_contains(text, "biotop") ||
             ci_contains(text, "tcptop") || ci_contains(text, "tcplife") ||
             ci_contains(text, "tcpstates") || ci_contains(text, "tcpretrans") ||
             ci_contains(text, "stackcount") || ci_contains(text, "offcputime") ||
             ci_contains(text, "syscount") || ci_contains(text, "runqlat") ||
             ci_contains(text, "cpudist") || ci_contains(text, "dcstat") ||
             ci_contains(text, "dcsnoop") || ci_contains(text, "fileslower") ||
             ci_contains(text, "filetop") || ci_contains(text, "ext4slower") ||
             ci_contains(text, "mysqld_qslower") || ci_contains(text, "gethostlatency") ||
             ci_contains(text, "cachestat") || ci_contains(text, "cachetop") ||
             ci_contains(text, "memleak") || ci_contains(text, "oomkill") ||
             (ci_contains(text, "deadlock") && ci_contains(text, " -")) ||
             ci_contains(text, "solisten") || ci_contains(text, "hardirqs") ||
             ci_contains(text, "fatrace") || ci_contains(text, "filelife") ||
             /* sandbox runtimes */
             (ci_contains(text, "runsc") && !ci_contains(text, "runscript")) ||
             ci_contains(text, "gvisor") ||
             ci_contains(text, "kata-runtime") || ci_contains(text, "firecracker") ||
             ci_contains(text, "firectl") ||
             (ci_contains(text, "ignite") && ci_contains(text, " -")) ||
             /* document converters / renderers */
             ci_contains(text, "pandoc") || ci_contains(text, "unoconv") ||
             (ci_contains(text, "soffice") && ci_contains(text, "--headless")) ||
             ci_contains(text, "weasyprint") ||
             (ci_contains(text, "prince") && ci_contains(text, " -")) ||
             ci_contains(text, "dompdf") || ci_contains(text, "enscript") ||
             ci_contains(text, "a2ps") || ci_contains(text, "paps") ||
             ci_contains(text, "cupsfilter") || ci_contains(text, "html2text") ||
             ci_contains(text, "ps2pdf") || ci_contains(text, "pdfjam") ||
             ci_contains(text, "pdftk") || ci_contains(text, "mutool") ||
             (ci_contains(text, "qpdf") && (ci_contains(text, "--decrypt") ||
              ci_contains(text, "--password"))) ||
             /* printing */
             ci_contains(text, "cupsd") ||
             (ci_contains(text, "cupsctl") && ci_contains(text, " --share")) ||
             ci_contains(text, "lpoptions") || ci_contains(text, "cups-browsed") ||
             ci_contains(text, "foomatic") ||
             /* accessibility backdoor binaries */
             ci_contains(text, "sethc") ||
             (ci_contains(text, "utilman") && ci_contains(text, " -")) ||
             (ci_contains(text, "magnify") && ci_contains(text, " -")) ||
             (ci_contains(text, "narrator") && ci_contains(text, " -")) ||
             (ci_contains(text, "osk") && ci_contains(text, " -")) ||
             ci_contains(text, "displayswitch") ||
             ci_contains(text, "atbroker") ||
             /* windows admin/debug misc */
             ci_contains(text, "register-cimprovider") || ci_contains(text, "changepk") ||
             (ci_contains(text, "msra") && ci_contains(text, " -")) ||
             ci_contains(text, "iisreset") ||
             (ci_contains(text, "appcmd") &&
              (ci_contains(text, " add ") || ci_contains(text, " set ") ||
               ci_contains(text, " delete "))) ||
             (ci_contains(text, "msdeploy") && ci_contains(text, " -")) ||
             ci_contains(text, "ngen") || ci_contains(text, "mscorsvw") ||
             ci_contains(text, "dotnet-dump") || ci_contains(text, "windbg") ||
             ci_contains(text, "cdb") ||
             ci_contains(text, "adplus") || ci_contains(text, "dcdiag") ||
             (ci_contains(text, "dsacls") && ci_contains(text, " -")) ||
             ci_contains(text, "csvde") ||
             ci_contains(text, "ldifde") || ci_contains(text, "smbcontrol") ||
             ci_contains(text, "smbstatus") ||
             (ci_contains(text, "rpcclient") && ci_contains(text, " -")) ||
             /* libguestfs image write */
             ci_contains(text, "virt-make-fs") || ci_contains(text, "libguestfs") ||
             (ci_contains(text, "iceman") && ci_contains(text, " -"))) {
        what = "c2/webshell/recon/bt/panel/selinux/backup-exfil/boot/bigdata/mq/ebpf/sandbox/doc/print/a11y/dbg primitive";
        }

        /* cycle-260: blockchain/web3 + memdump/credview + token/privesc + ad-aux + obfuscate + vm primitives */
        else if (
             /* web3 / blockchain dev & node clis */
             (ci_contains(text, "cast ") &&
              (ci_contains(text, " send") || ci_contains(text, " call") ||
               ci_contains(text, " wallet") || ci_contains(text, " -")) &&
              !ci_contains(text, "broadcast") && !ci_contains(text, "podcast")) ||
             (ci_contains(text, "forge ") &&
              (ci_contains(text, " script") || ci_contains(text, " create") ||
               ci_contains(text, " test") || ci_contains(text, " build") ||
               ci_contains(text, " verify") || ci_contains(text, " -"))) ||
             (ci_contains(text, "anvil") && ci_contains(text, " -")) ||
             ci_contains(text, "hardhat") ||
             (ci_contains(text, "brownie") && ci_contains(text, " -")) ||
             (ci_contains(text, "truffle") && ci_contains(text, " -")) ||
             (ci_contains(text, "ganache") && ci_contains(text, " -")) ||
             (ci_contains(text, "mythril") && ci_contains(text, " -")) ||
             (ci_contains(text, "slither") && ci_contains(text, " -")) ||
             (ci_contains(text, "echidna") && ci_contains(text, " -")) ||
             (ci_contains(text, "clef") && ci_contains(text, " -")) ||
             ci_contains(text, "bootnode") || ci_contains(text, "abigen") ||
             ci_contains(text, "solc") || ci_contains(text, "vyper") ||
             ci_contains(text, "scarb") || ci_contains(text, "cairo-run") ||
             ci_contains(text, "starknet") || ci_contains(text, "aptos") ||
             (ci_contains(text, "sui") && ci_contains(text, " -") &&
              !ci_contains(text, "pursuit")) ||
             (ci_contains(text, "solana") && ci_contains(text, " -")) ||
             (ci_contains(text, "anchor") && ci_contains(text, " -")) ||
             ci_contains(text, "near-cli") || ci_contains(text, "polkadot") ||
             ci_contains(text, "wasm-pack") || ci_contains(text, "parity-bridges") ||
             ci_contains(text, "ipfs-cluster-ctl") || ci_contains(text, "btfs") ||
             ci_contains(text, "filecoin") ||
             (ci_contains(text, "lotus") && ci_contains(text, " -")) ||
             (ci_contains(text, "oasis") && ci_contains(text, " -")) ||
             ci_contains(text, "safecmd") || ci_contains(text, "monero-cli") ||
             (ci_contains(text, "evm") && !ci_contains(text, "devm")) ||
             /* memory dump / credential viewers */
             ci_contains(text, "safetykatz") || ci_contains(text, "dumpert") ||
             (ci_contains(text, "mdr") && ci_contains(text, " -")) ||
             ci_contains(text, "wmdump") || ci_contains(text, "credwmap") ||
             (ci_contains(text, "hindsight") && ci_contains(text, " -")) ||
             ci_contains(text, "dumpzilla") || ci_contains(text, "powerram") ||
             ci_contains(text, "memfetch") || ci_contains(text, "dumpit") ||
             ci_contains(text, "defenderatp") || ci_contains(text, "firepwd") ||
             ci_contains(text, "firefox_decrypt") || ci_contains(text, "chromepass") ||
             ci_contains(text, "browserpassview") || ci_contains(text, "webbrowserpassview") ||
             ci_contains(text, "keepassx") || ci_contains(text, "credman") ||
             ci_contains(text, "regripper") || ci_contains(text, "jwt_tool") ||
             ci_contains(text, "getnthash") || ci_contains(text, "kirbi2john") ||
             /* windows token / privesc loaders */
             (ci_contains(text, "incognito") && ci_contains(text, " -")) ||
             ci_contains(text, "tokenvator") || ci_contains(text, "runascs") ||
             ci_contains(text, "delegateexec") || ci_contains(text, "ppldump") ||
             ci_contains(text, "blockdlls") || ci_contains(text, "srdi") ||
             (ci_contains(text, "frozen") && ci_contains(text, " -")) ||
             /* ad / kerberos aux */
             ci_contains(text, "certi.py") || ci_contains(text, "soaphound") ||
             ci_contains(text, "bloodyad") || ci_contains(text, "gmsadumper") ||
             ci_contains(text, "tgsrepcrack") || ci_contains(text, "aspxspy") ||
             ci_contains(text, "wmi.py") ||
             /* obfuscators + wordlist gens */
             ci_contains(text, "invoke-obfuscation") || ci_contains(text, "dyscoblue") ||
             ci_contains(text, "confuserex") ||
             (ci_contains(text, "crunch") && ci_contains(text, " -")) ||
             ci_contains(text, "statsprocessor") || ci_contains(text, "maskprocessor") ||
             ci_contains(text, "cewl") ||
             /* vm / emulation primitives */
             ci_contains(text, "vmrun") || ci_contains(text, "qemu-img") ||
             ci_contains(text, "qemu-system") ||
             (ci_contains(text, "kvm") && ci_contains(text, " -")) ||
             ci_contains(text, "virtiofsd") || ci_contains(text, "multipass") ||
             ci_contains(text, "podman machine") ||
             ci_contains(text, "hivexsh") || ci_contains(text, "hivexregedit") ||
             ci_contains(text, "supermin") ||
             (ci_contains(text, "lima") && ci_contains(text, " -") &&
              !ci_contains(text, "climate") && !ci_contains(text, "sublim"))) {
        what = "web3/memdump/credview/token/ad-aux/obfuscate/wordlist/vm primitive";
        }

        /* cycle-261: esxi/msc-cpl/macos/devops/disk-quota/init-log/fw primitives */
        else if (
             /* esxi / vsphere */
             ci_contains(text, "ovftool") || ci_contains(text, "vicfg-") ||
             ci_contains(text, "vim-cmd") || ci_contains(text, "powercli") ||
             ci_contains(text, "connect-viserver") || ci_contains(text, "vmconnect") ||
             ci_contains(text, "vmwp") ||
             /* windows msc / cpl / misc admin */
             ci_contains(text, "rasdial") ||
             (ci_contains(text, "w32tm") &&
              (ci_contains(text, " /resync") || ci_contains(text, " /register") ||
               ci_contains(text, " /unregister") || ci_contains(text, " /stripchart"))) ||
             ci_contains(text, "dsamain") || ci_contains(text, "adsiedit") ||
             ci_contains(text, "cliconfg") || ci_contains(text, "compmgmt.msc") ||
             ci_contains(text, "diskmgmt.msc") || ci_contains(text, "services.msc") ||
             ci_contains(text, "taskschd.msc") || ci_contains(text, "gpedit.msc") ||
             ci_contains(text, "secpol.msc") || ci_contains(text, "lusrmgr.msc") ||
             ci_contains(text, "certmgr.msc") || ci_contains(text, "certlm.msc") ||
             ci_contains(text, "certim.msc") || ci_contains(text, "fsmgmt.msc") ||
             ci_contains(text, "wf.msc") || ci_contains(text, "rsop.msc") ||
             ci_contains(text, "tpm.msc") || ci_contains(text, "virtmgmt.msc") ||
             ci_contains(text, "printmanagement.msc") || ci_contains(text, "azman.msc") ||
             ci_contains(text, "comexp.msc") || ci_contains(text, "netplwiz") ||
             ci_contains(text, "control userpasswords2") || ci_contains(text, "sysprep") ||
             ci_contains(text, "inetcpl.cpl") || ci_contains(text, "ncpa.cpl") ||
             ci_contains(text, "appwiz.cpl") || ci_contains(text, "main.cpl") ||
             ci_contains(text, "timedate.cpl") || ci_contains(text, "mmsys.cpl") ||
             (ci_contains(text, "powerpnt") && ci_contains(text, " /m")) ||
             ci_contains(text, "acrord32") || ci_contains(text, "foxitreader") ||
             ci_contains(text, "outlook.exe") || ci_contains(text, "msimn") ||
             /* macos dev / misc */
             (ci_contains(text, "swift ") &&
              (ci_contains(text, " -e") || ci_contains(text, " build") ||
               ci_contains(text, " run"))) ||
             (ci_contains(text, "carthage") && ci_contains(text, " -")) ||
             (ci_contains(text, "xed") && ci_contains(text, " -") &&
              !ci_contains(text, "fixed")) ||
             (ci_contains(text, "xcrun") && ci_contains(text, " -")) ||
             (ci_contains(text, "sips") && ci_contains(text, " -")) ||
             ci_contains(text, "caffeinate") || ci_contains(text, "scselect") ||
             ci_contains(text, "textutil") || ci_contains(text, "pod install") ||
             /* ios signing / delivery toolchain */
             (ci_contains(text, "fastlane") && ci_contains(text, " -")) ||
             (ci_contains(text, "sigh") && ci_contains(text, " -")) ||
             (ci_contains(text, "gym") && ci_contains(text, " -")) ||
             (ci_contains(text, "match") && ci_contains(text, " -")) ||
             (ci_contains(text, "deliver") && ci_contains(text, " -")) ||
             (ci_contains(text, "pilot") && ci_contains(text, " -")) ||
             (ci_contains(text, "snapshot") && ci_contains(text, " -")) ||
             (ci_contains(text, "screengrab") && ci_contains(text, " -")) ||
             (ci_contains(text, "pem ") && ci_contains(text, " -") &&
              !ci_contains(text, ".pem")) ||
             /* disk quota / fs maintenance */
             ci_contains(text, "accton") || ci_contains(text, "quotacheck") ||
             ci_contains(text, "edquota") || ci_contains(text, "setquota") ||
             ci_contains(text, "quotaon") || ci_contains(text, "repquota") ||
             ci_contains(text, "vgcreate") || ci_contains(text, "lvcreate") ||
             ci_contains(text, "vgreduce") || ci_contains(text, "pvmove") ||
             ci_contains(text, "sfdisk") || ci_contains(text, "gdisk") ||
             ci_contains(text, "smartd") || ci_contains(text, "dumpe2fs") ||
             ci_contains(text, "btrfsck") || ci_contains(text, "fsadm") ||
             ci_contains(text, "mdev") || ci_contains(text, "modinfo") ||
             ci_contains(text, "setpci") ||
             /* account / log maintenance */
             ci_contains(text, "groupadd") || ci_contains(text, "groupmod") ||
             ci_contains(text, "grpck") || ci_contains(text, "pwck") ||
             ci_contains(text, "faillog") ||
             (ci_contains(text, "pinky") && ci_contains(text, " -")) ||
             ci_contains(text, "scriptreplay") || ci_contains(text, "klogd") ||
             ci_contains(text, "metalog") || ci_contains(text, "socklog") ||
             ci_contains(text, "svlogd") || ci_contains(text, "rotatelogs") ||
             ci_contains(text, "multilog") ||
             /* init / cron variants */
             ci_contains(text, "openrc") || ci_contains(text, "runit-init") ||
             ci_contains(text, "fcron") || ci_contains(text, "dcron") ||
             ci_contains(text, "atq") ||
             (ci_contains(text, "batch ") && ci_contains(text, " -") &&
              !ci_contains(text, "--help")) ||
             /* vpn / firewall extras */
             ci_contains(text, "charon-cmd") ||
             (ci_contains(text, "charon") && ci_contains(text, " -")) ||
             ci_contains(text, "pptp") || ci_contains(text, "snx") ||
             ci_contains(text, "ip6tables") ||
             (ci_contains(text, "nft") &&
              (ci_contains(text, " add ") || ci_contains(text, " flush") ||
               ci_contains(text, " delete ") || ci_contains(text, " -"))) ||
             ci_contains(text, "arptables") || ci_contains(text, "shorewall") ||
             (ci_contains(text, "ferm") &&
              (ci_contains(text, " -") || ci_contains(text, " .conf"))) ||
             ci_contains(text, "firehol")) {
        what = "esxi/msc-cpl/macos/fastlane/disk-quota/init-log/fw primitive";
        } else if (
             /* cycle-262: vcs-daemon/sci-re/build/js-runtime/firmware/pwmgr-cli/
                re-tools/wsl-subshell/exfil-chan/scanner/sysinternals/gpg-aux/
                cloud-cli/version-mgr/iac-aux/ci-runner/kv primitives */
             ci_contains(text, "git-daemon") || ci_contains(text, "git-shell") ||
             ci_contains(text, "p4d") || ci_contains(text, "p4admin") ||
             ci_contains(text, "rscript") || ci_contains(text, "sbcl") ||
             ci_contains(text, "clisp") ||
             (ci_contains(text, "ecl ") && ci_contains(text, " -")) ||
             (ci_contains(text, "ccl ") && ci_contains(text, " -")) ||
             ci_contains(text, "gprolog") ||
             ci_contains(text, "swipl") ||
             (ci_contains(text, "yap ") && ci_contains(text, " -")) ||
             ci_contains(text, "bprolog") ||
             (ci_contains(text, "julia") && ci_contains(text, " -") &&
              !ci_contains(text, "--version")) ||
             (ci_contains(text, "racket") && ci_contains(text, " -")) ||
             (ci_contains(text, "guile") && ci_contains(text, " -")) ||
             (ci_contains(text, "mathematica") && ci_contains(text, " -")) ||
             ci_contains(text, "cargo install") || ci_contains(text, "cargo run ") ||
             ci_contains(text, "cargo test ") || ci_contains(text, "cargo audit") ||
             ci_contains(text, "cargo publish") || ci_contains(text, "rustup install") ||
             ci_contains(text, "rustup target") ||
             (ci_contains(text, "rustc ") && !ci_contains(text, "--version")) ||
             ci_contains(text, "go install") || ci_contains(text, "go run ") ||
             ci_contains(text, "go build") || ci_contains(text, "go test ") ||
             ci_contains(text, "meson") || ci_contains(text, "scons") ||
             (ci_contains(text, "waf ") && ci_contains(text, " -")) ||
             ci_contains(text, "bazel") ||
             ci_contains(text, "buck2") ||
             (ci_contains(text, "buck ") && ci_contains(text, " -")) ||
             (ci_contains(text, "pants ") &&
              (ci_contains(text, " -") || ci_contains(text, " ::")) &&
              !ci_contains(text, "--help")) || ci_contains(text, "plz ") ||
             ci_contains(text, "soong") || ci_contains(text, "autoconf") ||
             ci_contains(text, "automake") || ci_contains(text, "libtool") ||
             ci_contains(text, "autoreconf") || ci_contains(text, "cpack") ||
             ci_contains(text, "ctest") || ci_contains(text, "premake") ||
             ci_contains(text, "qmake") || ci_contains(text, "gmake") ||
             (ci_contains(text, "ninja") && ci_contains(text, " -")) ||
             ci_contains(text, "ts-node") || ci_contains(text, "esbuild") ||
             ci_contains(text, "swc ") || ci_contains(text, "heroku") ||
             ci_contains(text, "netlify") || ci_contains(text, "vercel") ||
             ci_contains(text, "flyctl") || ci_contains(text, "supabase") ||
             ci_contains(text, "bun run") || ci_contains(text, "bun install") ||
             ci_contains(text, "bun test") || ci_contains(text, "bun build") ||
             ci_contains(text, "bun x ") ||
             ci_contains(text, "vite dev") || ci_contains(text, "vite build") ||
             ci_contains(text, "vite preview") || ci_contains(text, "vite create") ||
             ci_contains(text, "next dev") || ci_contains(text, "next build") ||
             ci_contains(text, "next start") || ci_contains(text, "next telemetry") ||
             ci_contains(text, "nuxt dev") || ci_contains(text, "nuxt build") ||
             ci_contains(text, "nuxt generate") || ci_contains(text, "nuxi ") ||
             ci_contains(text, "remix dev") || ci_contains(text, "remix build") ||
             ci_contains(text, "remix vite") || ci_contains(text, "astro dev") ||
             ci_contains(text, "astro build") || ci_contains(text, "astro preview") ||
             ci_contains(text, "astro add") ||
             ci_contains(text, "flashtool") || ci_contains(text, "nrfutil") ||
             ci_contains(text, "teensy_loader") || ci_contains(text, "dbxtool") ||
             ci_contains(text, "spicec") || ci_contains(text, "freerdp") ||
             ci_contains(text, "wayvnc") || ci_contains(text, "wlvncc") ||
             ci_contains(text, "rbw ") || ci_contains(text, "passhole") ||
             ci_contains(text, "pass-import") || ci_contains(text, "pass-otp") ||
             ci_contains(text, "gopass-jsonapi") || ci_contains(text, "bitwarden") ||
             ci_contains(text, "lastpass") || ci_contains(text, "1password") ||
             ci_contains(text, "jd-gui") || ci_contains(text, "procyon") ||
             ci_contains(text, "fernflower") || ci_contains(text, "ilspy") ||
             ci_contains(text, "dnspy") || ci_contains(text, "monodis") ||
             ci_contains(text, "objdump") || ci_contains(text, "dex2jar") ||
             ci_contains(text, "d2j-") || ci_contains(text, "smali") ||
             ci_contains(text, "enjarify") || ci_contains(text, "javap") ||
             ci_contains(text, "bytecode-viewer") || ci_contains(text, "recaf") ||
             ci_contains(text, "ollydbg") || ci_contains(text, "immunity debugger") ||
             (ci_contains(text, "cfr ") && ci_contains(text, " -")) ||
             ci_contains(text, "wslconfig") || ci_contains(text, "lxssmanager") ||
             ci_contains(text, "ubuntu.exe") || ci_contains(text, "cygwin") ||
             ci_contains(text, "msys2") || ci_contains(text, "git-bash") ||
             ci_contains(text, "lsaars") || ci_contains(text, "outminidump") ||
             ci_contains(text, "memshell") || ci_contains(text, "file.io") ||
             ci_contains(text, "qrcp") || ci_contains(text, "pingfs") ||
             ci_contains(text, "dnsteal") || ci_contains(text, "phantun") ||
             ci_contains(text, "snyk") || ci_contains(text, "sonar-scanner") ||
             ci_contains(text, "codacy") || ci_contains(text, "detekt") ||
             ci_contains(text, "ktlint") || ci_contains(text, "checkstyle") ||
             ci_contains(text, "pmd ") || ci_contains(text, "spotbugs") ||
             ci_contains(text, "scalafmt") || ci_contains(text, "rubocop") ||
             ci_contains(text, "sfc /") || ci_contains(text, "bootcfg") ||
             ci_contains(text, "accessenum") || ci_contains(text, "procdump64") ||
             (ci_contains(text, "handle") && ci_contains(text, ".exe")) ||
             ci_contains(text, "gpg-connect-agent") || ci_contains(text, "gpgconf") ||
             ci_contains(text, "gpgsm") || ci_contains(text, "dirmngr") ||
             ci_contains(text, "azure-cli") || ci_contains(text, "aliyun") ||
             ci_contains(text, "tencent") || ci_contains(text, "ucloud") ||
             (ci_contains(text, "cbt ") && ci_contains(text, " -")) ||
             ci_contains(text, "nodeenv") || ci_contains(text, "pyenv") ||
             ci_contains(text, "rbenv") || ci_contains(text, "nvm ") ||
             ci_contains(text, "fnm ") || ci_contains(text, "sdkman") ||
             ci_contains(text, "jabba") || ci_contains(text, "jenv") ||
             ci_contains(text, "phpbrew") || ci_contains(text, "plenv") ||
             ci_contains(text, "goenv") || ci_contains(text, "dvm ") ||
             ci_contains(text, "rvm install") || ci_contains(text, "rvm use") ||
             ci_contains(text, "rvm gemset") ||
             ci_contains(text, "volta install") || ci_contains(text, "volta pin") ||
             ci_contains(text, "terraform-docs") || ci_contains(text, "infracost") ||
             ci_contains(text, "spacectl") || ci_contains(text, "terratag") ||
             ci_contains(text, "tflint") || ci_contains(text, "github-runner") ||
             ci_contains(text, "nektos") ||
             ci_contains(text, "act -j") || ci_contains(text, "act --job") ||
             ci_contains(text, "act -l") || ci_contains(text, "act -w ") ||
             ci_contains(text, "memcached") || ci_contains(text, "k3s ") ||
             ci_contains(text, "k0s ") || ci_contains(text, "openshift-install")) {
        what = "vcs/sci/build/js/firmware/pwmgr/re/wsl/exfil/scan/aux primitive";
        } else if (
             /* cycle-263: capture/usb-serial/jvm-introspection/isolation/binmod/
                win-deploy/mount-share/kernel-trace/mailer/pkg-build/tunnel/legacy-
                remote/initramfs/debug-server primitives */
             ci_contains(text, "clip.exe") || ci_contains(text, "xf86-screenshot") ||
             ci_contains(text, "maimshot") || ci_contains(text, "paplay") ||
             ci_contains(text, "obs-cli") || ci_contains(text, "gpu-screen-recorder") ||
             ci_contains(text, "ffplay") || ci_contains(text, "kazam") ||
             ci_contains(text, "simplescreenrecorder") || ci_contains(text, "vokoscreen") ||
             ci_contains(text, "uhubctl") || ci_contains(text, "hidapi") ||
             ci_contains(text, "libusb") || ci_contains(text, "pyusb") ||
             ci_contains(text, "usb-modeswitch") || ci_contains(text, "usbguard") ||
             (ci_contains(text, "tio ") &&
              (ci_contains(text, " -") || ci_contains(text, " /dev"))) ||
             (ci_contains(text, "cu ") &&
              (ci_contains(text, " -") || ci_contains(text, " /dev"))) ||
             ci_contains(text, "jstat") || ci_contains(text, "jfr ") ||
             ci_contains(text, "async-profiler") || ci_contains(text, "cgget") ||
             ci_contains(text, "prlimit") || ci_contains(text, "numactl") ||
             ci_contains(text, "cpuset") || ci_contains(text, "dwarfdump") ||
             ci_contains(text, "readelf") || ci_contains(text, "eu-readelf") ||
             (ci_contains(text, "nm ") && ci_contains(text, " -") &&
              !ci_contains(text, ".nm")) ||
             ci_contains(text, "drvload") ||
             ci_contains(text, "/add-provisionedpackage") ||
             ci_contains(text, "mount.cifs") || ci_contains(text, "mount.nfs") ||
             ci_contains(text, "gvfs-mount") || ci_contains(text, "mount -o loop") ||
             ci_contains(text, "mount --bind") || ci_contains(text, "mount --rbind") ||
             ci_contains(text, "mount -t tmpfs") || ci_contains(text, "losetup") ||
             ci_contains(text, "cryptsetup open") || ci_contains(text, "dmsetup create") ||
             ci_contains(text, "ftrace") || ci_contains(text, "kernelshark") ||
             (ci_contains(text, "plymouth") && ci_contains(text, " -")) ||
             (ci_contains(text, "lighthouse") && ci_contains(text, " -")) ||
             (ci_contains(text, "prysm") && ci_contains(text, " -")) ||
             ci_contains(text, "teku") ||
             (ci_contains(text, "nimbus") && ci_contains(text, " -")) ||
             ci_contains(text, "cardano-cli") ||
             (ci_contains(text, "lessopen") && !ci_contains(text, "lessopen=")) ||
             ci_contains(text, "neomutt") ||
             (ci_contains(text, "shar ") && !ci_contains(text, "share") &&
              !ci_contains(text, " pei")) ||
             (ci_contains(text, "fpm ") &&
              (ci_contains(text, " -") && !ci_contains(text, "--help"))) ||
             ci_contains(text, "nfpm") ||
             ci_contains(text, "goreleaser") || ci_contains(text, "jpackage") ||
             ci_contains(text, "jmod") || ci_contains(text, "jdeps") ||
             ci_contains(text, "jimage") || ci_contains(text, "zerotier-cli") ||
             (ci_contains(text, "mesg ") && !ci_contains(text, "dmesg")) ||
             (ci_contains(text, "wall ") &&
              (ci_contains(text, " -") && !ci_contains(text, "firewall") &&
               !ci_contains(text, "seawall") && !ci_contains(text, "wallpaper"))) ||
             (ci_contains(text, "talk ") && ci_contains(text, " -")) ||
             ci_contains(text, "ntalk") || ci_contains(text, "rwall") ||
             ci_contains(text, "lsinitrd") || ci_contains(text, "unmkinitramfs") ||
             ci_contains(text, "udevctl") || ci_contains(text, "llvm-objdump") ||
             ci_contains(text, "gdbserver") || ci_contains(text, "lldb-server") ||
             ci_contains(text, "sysdig-inspect") || ci_contains(text, "wireshark")) {
        what = "capture/usb/jvm/isolation/binmod/deploy/mount/trace/mailer/tunnel primitive";
        } else if (
             /* cycle-264a: theorem-prover/functional-lang/alt-interp/asm/translation */
             ci_contains(text, "coqc") || ci_contains(text, "coqtop") ||
             ci_contains(text, "coqchk") || ci_contains(text, "agda") ||
             ci_contains(text, "idris2") || ci_contains(text, "tlapm") ||
             ci_contains(text, "tlaps") || ci_contains(text, "why3") ||
             ci_contains(text, "frama-c") || ci_contains(text, "cbmc") ||
             ci_contains(text, "klee") || ci_contains(text, "cvc4") ||
             ci_contains(text, "cvc5") || ci_contains(text, "z3 ") ||
             ci_contains(text, "boolector") || ci_contains(text, "yices") ||
             ci_contains(text, "eprover") || ci_contains(text, "acl2") ||
             ci_contains(text, "hol-light") || ci_contains(text, "hol88") ||
             (ci_contains(text, "lean ") && ci_contains(text, " -") &&
              !ci_contains(text, "clean")) ||
             (ci_contains(text, "lake ") && ci_contains(text, " -")) ||
             (ci_contains(text, "idris ") && ci_contains(text, " -")) ||
             (ci_contains(text, "isabelle") && ci_contains(text, " -")) ||
             (ci_contains(text, "hol ") && ci_contains(text, " -")) ||
             (ci_contains(text, "princess") && ci_contains(text, " -")) ||
             (ci_contains(text, "vampire") && ci_contains(text, " -")) ||
             (ci_contains(text, "spass") && ci_contains(text, " -")) ||
             ci_contains(text, "fsharp") || ci_contains(text, "elm-reactor") ||
             ci_contains(text, "elm-make") || ci_contains(text, "purescript") ||
             ci_contains(text, "spago") || ci_contains(text, "rescript") ||
             (ci_contains(text, "elm ") && ci_contains(text, " -")) ||
             (ci_contains(text, "purs ") && ci_contains(text, " -")) ||
             (ci_contains(text, "bsc ") && ci_contains(text, " -")) ||
             (ci_contains(text, "chicken ") && ci_contains(text, " -")) ||
             ci_contains(text, "gsi ") || ci_contains(text, "gsc ") ||
             ci_contains(text, "kawa") || ci_contains(text, "ironpython") ||
             ci_contains(text, "pypy") || ci_contains(text, "graalpython") ||
             ci_contains(text, "truffleruby") || ci_contains(text, "mirb") ||
             ci_contains(text, "c3c") || ci_contains(text, "vala") ||
             ci_contains(text, "fpc") || ci_contains(text, "ppcx64") ||
             ci_contains(text, "lazbuild") || ci_contains(text, "chibicc") ||
             ci_contains(text, "cproc") || ci_contains(text, "kellnr") ||
             (ci_contains(text, "genie") && ci_contains(text, " -")) ||
             ci_contains(text, "wineserver") || ci_contains(text, "wine64") ||
             ci_contains(text, "box64") || ci_contains(text, "box86") ||
             ci_contains(text, "fex ") ||
             (ci_contains(text, "wine ") &&
              (ci_contains(text, ".exe") || ci_contains(text, " -"))) ||
             (ci_contains(text, "proton") && ci_contains(text, " -")) ||
             (ci_contains(text, "rosetta") && ci_contains(text, " -"))) {
        what = "prover/functional/alt-interp/translation primitive";
        } else if (
             /* cycle-264b: sandbox-escape/privexec/ipc/broker/storage/dir/
                overlay/supervision/fuse/envpkg/profiler primitives */
             ci_contains(text, "criu") || ci_contains(text, "checkpointctl") ||
             ci_contains(text, "minijail") || ci_contains(text, "jailer") ||
             ci_contains(text, "systemd-nspawn") || ci_contains(text, "febootstrap") ||
             (ci_contains(text, "osc ") &&
              (ci_contains(text, " -") && !ci_contains(text, "oscar"))) ||
             ci_contains(text, "doas") ||
             ci_contains(text, "opendoas") || ci_contains(text, "sudo-rs") ||
             ci_contains(text, "beesu") || ci_contains(text, "gksu") ||
             ci_contains(text, "kdesudo") || ci_contains(text, "gtksu") ||
             ci_contains(text, "xdg-su") || ci_contains(text, "lxqt-sudo") ||
             ci_contains(text, "visudo") || ci_contains(text, "grpc_cli") ||
             ci_contains(text, "evans") || ci_contains(text, "bloomrpc") ||
             (ci_contains(text, "newman") && ci_contains(text, " -")) ||
             (ci_contains(text, "hurl") && ci_contains(text, " -")) ||
             ci_contains(text, "curlie") || ci_contains(text, "wscat") ||
             (ci_contains(text, "snc ") && ci_contains(text, " -")) ||
             ci_contains(text, "dubbo-admin") || ci_contains(text, "natscli") ||
             ci_contains(text, "nats-server") || ci_contains(text, "nsqadmin") ||
             ci_contains(text, "rocketmq") || ci_contains(text, "rados") ||
             ci_contains(text, "cephfs") ||
             (ci_contains(text, "lfs ") && ci_contains(text, " -")) ||
             ci_contains(text, "beegfs") || ci_contains(text, "mmfsd") ||
             (ci_contains(text, "rook") && ci_contains(text, " -")) ||
             ci_contains(text, "openebs") || ci_contains(text, "dsconf") ||
             ci_contains(text, "dsadm") || ci_contains(text, "slapacl") ||
             ci_contains(text, "slapauth") ||
             (ci_contains(text, "ucs ") && ci_contains(text, " -")) ||
             ci_contains(text, "zentyal") || ci_contains(text, "remoteit") ||
             ci_contains(text, "s6-supervise") || ci_contains(text, "s6-svctl") ||
             ci_contains(text, "s6-svc") || ci_contains(text, "s6-svwait") ||
             ci_contains(text, "s6-svstat") || ci_contains(text, "dinit") ||
             ci_contains(text, "sysvinit") || ci_contains(text, "sinit") ||
             ci_contains(text, "minit") ||
             (ci_contains(text, "epoch ") && ci_contains(text, " -")) ||
             (ci_contains(text, "finit") && ci_contains(text, " -")) ||
             (ci_contains(text, "perp ") && ci_contains(text, " -")) ||
             ci_contains(text, "supervisord") || ci_contains(text, "circusd") ||
             ci_contains(text, "mergerfs") || ci_contains(text, "unionfs") ||
             ci_contains(text, "aufs ") || ci_contains(text, "bindfs") ||
             ci_contains(text, "gcsfuse") || ci_contains(text, "blobfuse") ||
             ci_contains(text, "juicefs") || ci_contains(text, "goofys") ||
             (ci_contains(text, "hermit") && ci_contains(text, " -")) ||
             ci_contains(text, "devbox") || ci_contains(text, "flox") ||
             ci_contains(text, "pkgx") || ci_contains(text, "aqua-installer") ||
             ci_contains(text, "valgrind") || ci_contains(text, "callgrind") ||
             ci_contains(text, "massif") || ci_contains(text, "helgrind") ||
             ci_contains(text, "gprof") || ci_contains(text, "flamegraph") ||
             ci_contains(text, "cachegrind") || ci_contains(text, "drd") ||
             ci_contains(text, "sgcheck") ||
             (ci_contains(text, "hotspot") && ci_contains(text, " -"))) {
        what = "sandbox/privexec/ipc/broker/storage/dir/overlay/supervision/fuse/profiler primitive";
        } else if (
             /* cycle-265a: alt-shell/term-inject/firmware-tool/eda-fpga/3d-cnc/
                game-engine/wm-input/clipboard-mgr/dialog-spoof/tmux-alt/
                keyring-agent/boot-write primitives */
             ci_contains(text, "xonsh") || ci_contains(text, "nushell") ||
             ci_contains(text, "elvish") || ci_contains(text, "yash ") ||
             ci_contains(text, "mksh") || ci_contains(text, "scsh") ||
             (ci_contains(text, "unbuffer") && !ci_contains(text, "unbuffered")) || ci_contains(text, "botb") ||
             ci_contains(text, "cbfstool") || ci_contains(text, "cbmem") ||
             ci_contains(text, "nvramtool") || ci_contains(text, "superiotool") ||
             ci_contains(text, "ectool") || ci_contains(text, "bios_extract") ||
             ci_contains(text, "intelmetool") || ci_contains(text, "me-cleaner") ||
             ci_contains(text, "kicad-cli") || ci_contains(text, "openscad") ||
             ci_contains(text, "freecadcmd") || ci_contains(text, "nextpnr-ice40") ||
             ci_contains(text, "nextpnr-ecp5") || ci_contains(text, "nextpnr-machxo2") ||
             ci_contains(text, "icestorm") || ci_contains(text, "verilator") ||
             ci_contains(text, "iverilog") || ci_contains(text, "gtkwave") ||
             ci_contains(text, "vivado") || ci_contains(text, "quartus_sh") ||
             (ci_contains(text, "quartus") && ci_contains(text, " -")) ||
             ci_contains(text, "xapp1541") || ci_contains(text, "prusa-slicer") ||
             ci_contains(text, "curaengine") || ci_contains(text, "octoprint") ||
             ci_contains(text, "klipper") || ci_contains(text, "pronsole") ||
             (ci_contains(text, "marlin") && ci_contains(text, " -")) ||
             (ci_contains(text, "godot") && ci_contains(text, " -")) ||
             (ci_contains(text, "blender") && ci_contains(text, " -")) ||
             (ci_contains(text, "unity ") && ci_contains(text, " -")) ||
             ci_contains(text, "unreal-editor") ||
             (ci_contains(text, "riverctl") && !ci_contains(text, "driverctl")) || ci_contains(text, "wlr-randr") ||
             ci_contains(text, "kanshi") || ci_contains(text, "wdisplays") ||
             (ci_contains(text, "cage ") && ci_contains(text, " -")) ||
             ci_contains(text, "clipnotify") || ci_contains(text, "xcmenu") ||
             ci_contains(text, "dunstify") ||
             (ci_contains(text, "yad ") && ci_contains(text, " -")) ||
             (ci_contains(text, "dialog ") && ci_contains(text, " -")) ||
             ci_contains(text, "gxmessage") || ci_contains(text, "xmessage") ||
             ci_contains(text, "zellij") || ci_contains(text, "dvtm") ||
             (ci_contains(text, "byobu") && ci_contains(text, " -")) ||
             ci_contains(text, "keepassxc-proxy") || ci_contains(text, "ssh-askpass") ||
             ci_contains(text, "kwalletd5") || ci_contains(text, "kwalletcli") ||
             ci_contains(text, "gnome-keyring-daemon") || ci_contains(text, "refind-install") ||
             ci_contains(text, "limine") || ci_contains(text, "ukify") ||
             ci_contains(text, "pueue") || (ci_contains(text, "nq ") && !ci_contains(text, "inq")) ||
             ci_contains(text, "task-spooler") ||
             (ci_contains(text, "posh ") && ci_contains(text, " -") && !ci_contains(text, "--help")) ||
             (ci_contains(text, "oil ") && ci_contains(text, " -")) ||
             (ci_contains(text, "osh ") && ci_contains(text, " -") && !ci_contains(text, "gosh") && !ci_contains(text, "kosh") && !ci_contains(text, "posh") && !ci_contains(text, "--help"))) {
        what = "alt-shell/term/firmware/eda/3d/game/wm/clipboard/dialog/tmux/keyring/boot primitive";
        } else if (
             /* cycle-265b: cosmos-iot/hw-telemetry/routing-multicast/passive-sniff/
                pth-impacket/wireless primitives */
             ci_contains(text, "gaiad") || ci_contains(text, "osmosisd") ||
             ci_contains(text, "junod") || ci_contains(text, "celestia") ||
             ci_contains(text, "seid") || ci_contains(text, "evmosd") ||
             ci_contains(text, "platformio") || ci_contains(text, "arduino-cli") ||
             ci_contains(text, "esphome") || ci_contains(text, "kamailio") ||
             ci_contains(text, "xboxdrv") || ci_contains(text, "uinput") ||
             ci_contains(text, "evdev") || ci_contains(text, "joydev") ||
             ci_contains(text, "wiiuse") || ci_contains(text, "sixpair") ||
             ci_contains(text, "gpsd") || ci_contains(text, "gpsctl") ||
             ci_contains(text, "gpsfake") || ci_contains(text, "cgps") ||
             ci_contains(text, "gpsmon") || ci_contains(text, "gpspipe") ||
             ci_contains(text, "lm_sensors") || ci_contains(text, "sensors-detect") ||
             ci_contains(text, "fancontrol") || ci_contains(text, "pwmconfig") ||
             ci_contains(text, "lldpd") || ci_contains(text, "lldpctl") ||
             ci_contains(text, "lldpcli") || ci_contains(text, "ospfclient") ||
             (ci_contains(text, "mroute") && ci_contains(text, " -")) ||
             ci_contains(text, "mrouted") || ci_contains(text, "smcroute") ||
             ci_contains(text, "igmpproxy") || ci_contains(text, "httpry") ||
             ci_contains(text, "ntlmrealyx") || ci_contains(text, "pth-toolkit") ||
             ci_contains(text, "pth-winexe") || ci_contains(text, "pth-smbclient") ||
             ci_contains(text, "multi_relay") ||
             ci_contains(text, "impacket-atexec") || ci_contains(text, "impacket-dcomexec") ||
             ci_contains(text, "impacket-psexec") || ci_contains(text, "impacket-smbexec") ||
             ci_contains(text, "impacket-wmiexec") || ci_contains(text, "kismet_server") ||
             ci_contains(text, "kismet_capture") ||
             (ci_contains(text, "hornet") && ci_contains(text, " -")) ||
             (ci_contains(text, "beelogger") && ci_contains(text, " -"))) {
        what = "cosmos/iot/telemetry/routing/sniff/pth/wireless primitive";
        } else if (
             /* cycle-266a: pipewire/audio-bcast/ham-radio/term-image/rec/tts/
                ddc-monitor/key-remap/gesture primitives */
             ci_contains(text, "pw-cat") || ci_contains(text, "pw-play") ||
             ci_contains(text, "pw-jack") || ci_contains(text, "qpwgraph") ||
             ci_contains(text, "helvum") || ci_contains(text, "darkice") ||
             ci_contains(text, "liquidsoap") || ci_contains(text, "icecast") ||
             (ci_contains(text, "butt") && ci_contains(text, " -")) ||
             ci_contains(text, "mixxx") || ci_contains(text, "fldigi") ||
             ci_contains(text, "wsjtx") || ci_contains(text, "js8call") ||
             ci_contains(text, "chafa") || ci_contains(text, "viu ") ||
             ci_contains(text, "jp2 ") || ci_contains(text, "img2txt") ||
             ci_contains(text, "w3mimgdisplay") || ci_contains(text, "ueberzug") ||
             ci_contains(text, "sixel") || ci_contains(text, "kooha") ||
             (ci_contains(text, "vhs") && ci_contains(text, " -")) ||
             ci_contains(text, "terminalizer") || ci_contains(text, "espeak-ng") ||
             (ci_contains(text, "festival") && ci_contains(text, " -")) ||
             (ci_contains(text, "flite") && ci_contains(text, " -")) ||
             ci_contains(text, "speech-dispatcher") || ci_contains(text, "spd-say") ||
             ci_contains(text, "ddcutil") || ci_contains(text, "ddcci-driver") ||
             ci_contains(text, "interception-tools") || ci_contains(text, "evremap") ||
             ci_contains(text, "xremap") || ci_contains(text, "touchegg") ||
             (ci_contains(text, "fusuma") && ci_contains(text, " -")) ||
             (ci_contains(text, "orca") && ci_contains(text, " -")) ||
             ci_contains(text, "eternalterminal") || ci_contains(text, "s-tui") ||
             ci_contains(text, "powerstat")) {
        what = "pipewire/audiobcast/ham/termimg/rec/tts/ddc/keyremap/gesture primitive";
        } else if (
             /* cycle-266b: bench/dist-compile/re/dbg/ide/repl primitives */
             ci_contains(text, "phoronix-test-suite") || ci_contains(text, "geekbench") ||
             ci_contains(text, "cinebench") || ci_contains(text, "stressapptest") ||
             ci_contains(text, "memtester") || ci_contains(text, "cpuburn") ||
             ci_contains(text, "sccache") || ci_contains(text, "icecc") ||
             (ci_contains(text, "icecream") && ci_contains(text, " -")) ||
             (ci_contains(text, "mold") && ci_contains(text, " -")) ||
             (ci_contains(text, "lld") && ci_contains(text, " -")) ||
             ci_contains(text, "ida64") ||
             (ci_contains(text, "idat") && ci_contains(text, " -")) ||
             ci_contains(text, "rz-bin") || ci_contains(text, "binary-refinery") ||
             (ci_contains(text, "delve") && ci_contains(text, " -")) ||
             ci_contains(text, "pernosco") ||
             ci_contains(text, "code --install-extension") ||
             ci_contains(text, "codium") || (ci_contains(text, "ecode") && !ci_contains(text, "recod")) ||
             ci_contains(text, "lapce") ||
             (ci_contains(text, "zed") && ci_contains(text, " -")) ||
             (ci_contains(text, "hx ") && ci_contains(text, " -")) ||
             (ci_contains(text, "kak ") && ci_contains(text, " -")) ||
             (ci_contains(text, "vis ") && ci_contains(text, " -") &&
              !ci_contains(text, "visit") && !ci_contains(text, "vision") &&
              !ci_contains(text, "visible") && !ci_contains(text, "trav")) ||
             ci_contains(text, "bpython") || ci_contains(text, "ptpython") ||
             ci_contains(text, "jupytext")) {
        what = "bench/distcompile/re/dbg/ide/repl primitive";
        } else if (
             /* cycle-266c: sql-nosql/kv/search/tsdb/bio/molecular/astro/
                p2p-anon/ocr/assistive/doc/raw-img primitives */
             ci_contains(text, "usql") || ci_contains(text, "sqlcl") ||
             ci_contains(text, "orientdb") || ci_contains(text, "fauna-shell") ||
             (ci_contains(text, "surreal") && ci_contains(text, " -")) ||
             ci_contains(text, "edgedb") || ci_contains(text, "weaviate") ||
             ci_contains(text, "qdrant") ||
             (ci_contains(text, "milvus") && ci_contains(text, " -")) ||
             ci_contains(text, "valkey-cli") ||
             (ci_contains(text, "dragonfly") && ci_contains(text, " -")) ||
             ci_contains(text, "keydb-cli") || ci_contains(text, "kvrocks") ||
             ci_contains(text, "opensearch-cli") || ci_contains(text, "meilisearch") ||
             ci_contains(text, "typesense") ||
             (ci_contains(text, "sonic") && ci_contains(text, " -")) ||
             ci_contains(text, "tantivy") ||
             (ci_contains(text, "vespa") && ci_contains(text, " -")) ||
             (ci_contains(text, "vmctl") && ci_contains(text, " -")) ||
             ci_contains(text, "m3dbnode") || ci_contains(text, "questdb") ||
             ci_contains(text, "timescaledb-tune") || ci_contains(text, "promscale") ||
             ci_contains(text, "greptimedb") || ci_contains(text, "bedtools") ||
             ci_contains(text, "bowtie2") ||
             (ci_contains(text, "bwa") && ci_contains(text, " -")) ||
             ci_contains(text, "gatk") ||
             (ci_contains(text, "picard") && ci_contains(text, " -")) ||
             ci_contains(text, "pymol") ||
             (ci_contains(text, "vmd") && ci_contains(text, " -")) ||
             ci_contains(text, "lammps") || ci_contains(text, "gromacs") ||
             ci_contains(text, "ds9") ||
             (ci_contains(text, "xpa") && ci_contains(text, " -")) ||
             ci_contains(text, "astrometry") || ci_contains(text, "sextractor") ||
             ci_contains(text, "i2pd") || ci_contains(text, "hyphanet") ||
             ci_contains(text, "retroshare") ||
             (ci_contains(text, "sia") && ci_contains(text, " -") && !ci_contains(text, "scsi")) ||
             ci_contains(text, "storj") || ci_contains(text, "arweave") ||
             ci_contains(text, "hypercore") ||
             (ci_contains(text, "dat") && ci_contains(text, " -") &&
              !ci_contains(text, "data") && !ci_contains(text, "update")) ||
             (ci_contains(text, "cuneiform") && ci_contains(text, " -")) ||
             ci_contains(text, "ocrad") || ci_contains(text, "at-spi") ||
             ci_contains(text, "abiword") || ci_contains(text, "calligra") ||
             ci_contains(text, "onlyoffice") || ci_contains(text, "dcraw") ||
             ci_contains(text, "ufraw") || ci_contains(text, "enfuse") ||
             ci_contains(text, "luminance-hdr")) {
        what = "sqlnosql/kv/search/tsdb/bio/molecular/astro/p2p/ocr/doc/rawimg primitive";
        } else if (
             /* cycle-267a: de-config/panels/compositors/lock/idle/launchers/
                notif/term-exec/filemgr/chatc2/voip primitives */
             ci_contains(text, "xfconf-query") || ci_contains(text, "kwriteconfig") ||
             ci_contains(text, "kreadconfig") || ci_contains(text, "plasmashell") ||
             ci_contains(text, "tint2") || ci_contains(text, "polybar") ||
             ci_contains(text, "waybar") || ci_contains(text, "lemonbar") ||
             ci_contains(text, "xmobar") || ci_contains(text, "dzen2") ||
             (ci_contains(text, "plank") && ci_contains(text, " -")) ||
             ci_contains(text, "latte-dock") || ci_contains(text, "cairo-dock") ||
             ci_contains(text, "picom") ||
             (ci_contains(text, "compton") && ci_contains(text, " -")) ||
             ci_contains(text, "xcompmgr") || ci_contains(text, "swaybg") ||
             ci_contains(text, "hyprpaper") || ci_contains(text, "wpaperd") ||
             ci_contains(text, "swww") || ci_contains(text, "i3lock") ||
             ci_contains(text, "betterlockscreen") || ci_contains(text, "xsecurelock") ||
             ci_contains(text, "xidlehook") || ci_contains(text, "hypridle") ||
             (ci_contains(text, "rofi") && !ci_contains(text, "profi")) || ci_contains(text, "wofi") ||
             ci_contains(text, "bemenu") || ci_contains(text, "dmenu") ||
             ci_contains(text, "fuzzel") || ci_contains(text, "tofi") ||
             (ci_contains(text, "walker") && ci_contains(text, " -")) ||
             (ci_contains(text, "mako") && ci_contains(text, " -")) ||
             (ci_contains(text, "wired") && ci_contains(text, " -")) ||
             ci_contains(text, "fnott") || ci_contains(text, "ghostty") ||
             (ci_contains(text, "nnn") && ci_contains(text, " -")) ||
             (ci_contains(text, "ranger") && ci_contains(text, " -")) ||
             ci_contains(text, "vifm") || ci_contains(text, "yazi") ||
             ci_contains(text, "broot") || ci_contains(text, "xplr") ||
             ci_contains(text, "konversation") || ci_contains(text, "quassel") ||
             ci_contains(text, "matrix-commander") ||
             (ci_contains(text, "toxic") && ci_contains(text, " -")) ||
             ci_contains(text, "qtox") || ci_contains(text, "ratox") ||
             ci_contains(text, "jami") || ci_contains(text, "linphone") ||
             ci_contains(text, "ekiga") ||
             (ci_contains(text, "twinkle") && ci_contains(text, " -"))) {
        what = "de/panel/compositor/lock/idle/launcher/notif/termexec/filemgr/chat/voip primitive";
        } else if (
             /* cycle-267b: media/dl/torrent/arr/mediav/home-auto/finance/
                gis/pim/notes primitives */
             (ci_contains(text, "celluloid") && ci_contains(text, " -") && !ci_contains(text, "--help")) ||
             (ci_contains(text, "parole") && ci_contains(text, " -") && !ci_contains(text, "--help")) ||
             (ci_contains(text, "totem") && ci_contains(text, " -")) ||
             ci_contains(text, "kodi-send") || ci_contains(text, "pyload") ||
             (ci_contains(text, "persepolis") && ci_contains(text, " -")) ||
             (ci_contains(text, "uget") && !ci_contains(text, "nuget")) || ci_contains(text, "mldonkey") ||
             ci_contains(text, "amule") || ci_contains(text, "vuze") ||
             ci_contains(text, "biglybt") ||
             (ci_contains(text, "flood") && ci_contains(text, " -")) ||
             ci_contains(text, "autobrr") || ci_contains(text, "cross-seed") ||
             ci_contains(text, "nzbget") || ci_contains(text, "sabnzbd") ||
             ci_contains(text, "sabnzbdplus") || ci_contains(text, "nzbhydra") ||
             ci_contains(text, "sonarr") || ci_contains(text, "radarr") ||
             ci_contains(text, "lidarr") || ci_contains(text, "readarr") ||
             ci_contains(text, "prowlarr") || ci_contains(text, "jackett") ||
             ci_contains(text, "bazarr") || ci_contains(text, "overseerr") ||
             ci_contains(text, "tautulli") || ci_contains(text, "ombi") ||
             ci_contains(text, "jellyfin") || ci_contains(text, "emby") ||
             ci_contains(text, "navidrome") || ci_contains(text, "airsonic") ||
             ci_contains(text, "ampache") || ci_contains(text, "funkwhale") ||
             ci_contains(text, "mstream") || ci_contains(text, "hass-cli") ||
             ci_contains(text, "openhab") || ci_contains(text, "domoticz") ||
             ci_contains(text, "iobroker") || ci_contains(text, "node-red-admin") ||
             ci_contains(text, "zigbee2mqtt") || ci_contains(text, "zwavejs") ||
             ci_contains(text, "tasmota") || ci_contains(text, "wled") ||
             ci_contains(text, "rhasspy") ||
             (ci_contains(text, "piper") && ci_contains(text, " -")) ||
             ci_contains(text, "openwakeword") ||
             ci_contains(text, "ledger-cli") || ci_contains(text, "hledger") ||
             (ci_contains(text, "beancount") && ci_contains(text, " -")) ||
             (ci_contains(text, "fava") && ci_contains(text, " -")) ||
             ci_contains(text, "gnucash-cli") || ci_contains(text, "firefly-iii") ||
             ci_contains(text, "qgis") ||
             (ci_contains(text, "grass") && ci_contains(text, " -")) ||
             ci_contains(text, "saga_cmd") || ci_contains(text, "tippecanoe") ||
             ci_contains(text, "tilemaker") || ci_contains(text, "osmium") ||
             ci_contains(text, "osmconvert") ||
             (ci_contains(text, "osmosis") && ci_contains(text, " -")) ||
             ci_contains(text, "nominatim") ||
             (ci_contains(text, "martin") && ci_contains(text, " -")) ||
             ci_contains(text, "tileserver") || ci_contains(text, "pg_tileserv") ||
             ci_contains(text, "khard") ||
             (ci_contains(text, "khal") && ci_contains(text, " -")) ||
             ci_contains(text, "todoman") || ci_contains(text, "vdirsyncer") ||
             ci_contains(text, "calcurse") ||
             (ci_contains(text, "nb") && ci_contains(text, " -") && !ci_contains(text, "nbt") && !ci_contains(text, "bound")) ||
             ci_contains(text, "jrnl") ||
             (ci_contains(text, "zk") && ci_contains(text, " -")) ||
             (ci_contains(text, "trilium") && ci_contains(text, " -")) ||
             ci_contains(text, "logseq")) {
        what = "media/dl/torrent/arr/mediav/homeauto/finance/gis/pim/notes primitive";
        } else if (
             /* cycle-268a: backup-sync/cloudexfil/encfs/archive/pkg-internals/
                boot primitives */
             (ci_contains(text, "rustic") && ci_contains(text, " -")) ||
             ci_contains(text, "duplicacy") || ci_contains(text, "duplicati") ||
             ci_contains(text, "obnam") || ci_contains(text, "bupstash") ||
             ci_contains(text, "zpaq") || ci_contains(text, "backintime") ||
             ci_contains(text, "zfsnap2") ||
             (ci_contains(text, "unison") && ci_contains(text, " -")) ||
             ci_contains(text, "csync2") || ci_contains(text, "osync") ||
             (ci_contains(text, "mutagen") && ci_contains(text, " -")) ||
             ci_contains(text, "seafile-cli") || ci_contains(text, "megacmd") ||
             ci_contains(text, "icloudpd") || ci_contains(text, "gphotos-sync") ||
             ci_contains(text, "boxcli") || ci_contains(text, "ydisk") ||
             ci_contains(text, "securefs") || ci_contains(text, "ecryptfs-utils") ||
             ci_contains(text, "cryptmount") || ci_contains(text, "atool") ||
             ci_contains(text, "dtrx") || ci_contains(text, "unp ") ||
             ci_contains(text, "patool") || ci_contains(text, "unar") ||
             ci_contains(text, "lsar") || ci_contains(text, "unace") ||
             ci_contains(text, "unlzh") || ci_contains(text, "dmg2img") ||
             ci_contains(text, "isoinfo") || ci_contains(text, "isomd5sum") ||
             ci_contains(text, "ccd2iso") || ci_contains(text, "nrg2iso") ||
             ci_contains(text, "mdf2iso") || ci_contains(text, "b5i2iso") ||
             (ci_contains(text, "iat") && ci_contains(text, " -")) ||
             ci_contains(text, "dpkg-deb") || ci_contains(text, "lintian") ||
             ci_contains(text, "piuparts") || ci_contains(text, "reprepro") ||
             (ci_contains(text, "aptly") && ci_contains(text, " -")) ||
             (ci_contains(text, "freight") && ci_contains(text, " -")) ||
             ci_contains(text, "dpkg-sig") || ci_contains(text, "debsign") ||
             ci_contains(text, "debsigs") || ci_contains(text, "rpm-sign") ||
             ci_contains(text, "createrepo_c") || ci_contains(text, "mergerepo") ||
             ci_contains(text, "modifyrepo") || ci_contains(text, "repoclosure") ||
             ci_contains(text, "repomanage") || ci_contains(text, "repotrack") ||
             ci_contains(text, "verifytree") || ci_contains(text, "initramfs-tools") ||
             (ci_contains(text, "booster") && ci_contains(text, " -")) ||
             ci_contains(text, "syslinux") || ci_contains(text, "isolinux") ||
             ci_contains(text, "extlinux") || ci_contains(text, "pxelinux") ||
             ci_contains(text, "memdisk") || ci_contains(text, "ipxe") ||
             ci_contains(text, "wimboot")) {
        what = "backupsync/cloudexfil/encfs/archive/pkg/boot primitive";
        } else if (
             /* cycle-268b: serial-fax/docgen/spec/mock/load/api/mobile/
                android/ios/emu/console/retro/mediapk primitives */
             ci_contains(text, "remserial") || ci_contains(text, "ttynvt") ||
             ci_contains(text, "microcom") ||
             (ci_contains(text, "sx") && ci_contains(text, " -") &&
              !ci_contains(text, "lsx") && !ci_contains(text, "osx")) ||
             (ci_contains(text, "sb ") && ci_contains(text, " -") && !ci_contains(text, "usb") && !ci_contains(text, "lsb")) ||
             (ci_contains(text, "sz") && ci_contains(text, " -") &&
              !ci_contains(text, "lsz")) ||
             ci_contains(text, "ckermit") || ci_contains(text, "hylafax") ||
             ci_contains(text, "faxq") || ci_contains(text, "efax") ||
             ci_contains(text, "t38modem") || ci_contains(text, "gotenberg") ||
             ci_contains(text, "stirling-pdf") ||
             (ci_contains(text, "mayan") && ci_contains(text, " -")) ||
             ci_contains(text, "docspell") || ci_contains(text, "mdbook") ||
             ci_contains(text, "sphinx-build") || ci_contains(text, "naturaldocs") ||
             ci_contains(text, "pdoc") || ci_contains(text, "jsdoc") ||
             ci_contains(text, "typedoc") || ci_contains(text, "phpdoc") ||
             (ci_contains(text, "yard") && ci_contains(text, " -")) ||
             ci_contains(text, "rdoc") || ci_contains(text, "openapi-generator") ||
             ci_contains(text, "swagger-codegen") || ci_contains(text, "oapi-codegen") ||
             ci_contains(text, "graphql-codegen") || ci_contains(text, "sqlc") ||
             (ci_contains(text, "atlas") && ci_contains(text, " -")) ||
             (ci_contains(text, "goose") && ci_contains(text, " -")) ||
             ci_contains(text, "dbmate") || ci_contains(text, "sqitch") ||
             ci_contains(text, "wiremock") || ci_contains(text, "mountebank") ||
             ci_contains(text, "hoverfly") || ci_contains(text, "json-server") ||
             ci_contains(text, "mockoon") ||
             (ci_contains(text, "prism") && ci_contains(text, " -") &&
              !ci_contains(text, "prisma")) ||
             ci_contains(text, "imposter") || ci_contains(text, "mockserver") ||
             ci_contains(text, "selenium-side-runner") || ci_contains(text, "chromedp") ||
             (ci_contains(text, "rod") && ci_contains(text, " -")) ||
             ci_contains(text, "gatling") || ci_contains(text, "bombardier") ||
             (ci_contains(text, "cassowary") && ci_contains(text, " -")) ||
             (ci_contains(text, "plow") && ci_contains(text, " -")) ||
             (ci_contains(text, "oha") && ci_contains(text, " -")) ||
             ci_contains(text, "h2load") || ci_contains(text, "wrk2") ||
             ci_contains(text, "rewrk") ||
             (ci_contains(text, "ali") && ci_contains(text, " -")) ||
             ci_contains(text, "fortio") || ci_contains(text, "toxiproxy") ||
             (ci_contains(text, "comcast") && ci_contains(text, " -")) ||
             (ci_contains(text, "clumsy") && ci_contains(text, " -")) ||
             ci_contains(text, "hoppscotch") ||
             (ci_contains(text, "bruno") && ci_contains(text, " -")) ||
             ci_contains(text, "postman-cli") || ci_contains(text, "appcenter-cli") ||
             ci_contains(text, "expo-cli") || ci_contains(text, "eas-cli") ||
             (ci_contains(text, "capacitor") && ci_contains(text, " -")) ||
             (ci_contains(text, "ionic") && ci_contains(text, " -") && !ci_contains(text, "ionice")) ||
             ci_contains(text, "nativescript") || ci_contains(text, "xcodegen") ||
             ci_contains(text, "tuist") || ci_contains(text, "swiftlint") ||
             ci_contains(text, "swiftformat") ||
             (ci_contains(text, "mint") && ci_contains(text, " -") &&
              !ci_contains(text, "mint-" ) && !ci_contains(text, "xinit")) ||
             (ci_contains(text, "periphery") && ci_contains(text, " -")) ||
             ci_contains(text, "xcbeautify") || ci_contains(text, "xcpretty") ||
             ci_contains(text, "zipalign") || ci_contains(text, "bundletool") ||
             ci_contains(text, "apkanalyzer") || ci_contains(text, "aapt2") ||
             ci_contains(text, "idevice_id") || ci_contains(text, "idevicebackup2") ||
             ci_contains(text, "idevicecrashreport") || ci_contains(text, "ideviceprovision") ||
             ci_contains(text, "xcdevice") || ci_contains(text, "cfgutil") ||
             ci_contains(text, "libimobiledevice") || ci_contains(text, "avdmanager") ||
             ci_contains(text, "sdkmanager") || ci_contains(text, "devkitpro") ||
             ci_contains(text, "vitasdk") || ci_contains(text, "pspdev") ||
             ci_contains(text, "hbmenu") ||
             (ci_contains(text, "goldleaf") && ci_contains(text, " -")) ||
             (ci_contains(text, "tinfoil") && ci_contains(text, " -")) ||
             (ci_contains(text, "dbi") && ci_contains(text, " -")) ||
             ci_contains(text, "hekate") || ci_contains(text, "lockpick_rcm") ||
             ci_contains(text, "retroarch") || ci_contains(text, "emulationstation") ||
             ci_contains(text, "shaka-packager") || ci_contains(text, "mp4box") ||
             ci_contains(text, "gpac") || ci_contains(text, "bento4") ||
             ci_contains(text, "mp4split") || ci_contains(text, "mp4fragment") ||
             (ci_contains(text, "love") && ci_contains(text, " -")) ||
             ci_contains(text, "tic80")) {
        what = "serial/fax/docgen/spec/mock/load/api/mobile/android/ios/emu/console/retro/mediapk primitive";
        } else if (
             /* cycle-269a: ci-runner/registry/gateway/feature-flag/secret-broker/
                idp/ldap/analytics/uptime/apm/incident primitives */
             (ci_contains(text, "woodpecker") && ci_contains(text, " -")) ||
             ci_contains(text, "gitea-act-runner") || ci_contains(text, "appveyor") ||
             ci_contains(text, "teamcity") || ci_contains(text, "octopus-deploy") ||
             (ci_contains(text, "octo") && ci_contains(text, " -") &&
              !ci_contains(text, "octopus")) ||
             (ci_contains(text, "zot") && ci_contains(text, " -")) ||
             ci_contains(text, "verdaccio") || ci_contains(text, "devpi") ||
             ci_contains(text, "pypiserver") || ci_contains(text, "gemfury") ||
             ci_contains(text, "packagecloud") || ci_contains(text, "cloudsmith") ||
             ci_contains(text, "buildkit") || ci_contains(text, "apisix") ||
             (ci_contains(text, "tyk") && ci_contains(text, " -")) ||
             ci_contains(text, "gravitee") ||
             (ci_contains(text, "unleash") && ci_contains(text, " -")) ||
             ci_contains(text, "flagsmith") || ci_contains(text, "growthbook") ||
             ci_contains(text, "openfeature") ||
             (ci_contains(text, "flipt") && ci_contains(text, " -")) ||
             ci_contains(text, "ldcli") ||
             (ci_contains(text, "phase") && ci_contains(text, " -")) ||
             (ci_contains(text, "hatch") && ci_contains(text, " -")) ||
             ci_contains(text, "secretless") || ci_contains(text, "authentik") ||
             ci_contains(text, "zitadel") || ci_contains(text, "casdoor") ||
             (ci_contains(text, "logto") && ci_contains(text, " -")) ||
             ci_contains(text, "supertokens") || ci_contains(text, "fusionauth") ||
             ci_contains(text, "fusiondirectory") || ci_contains(text, "ldapvi") ||
             (ci_contains(text, "luma") && ci_contains(text, " -")) ||
             ci_contains(text, "shelldap") || ci_contains(text, "phpldapadmin") ||
             (ci_contains(text, "matomo") && ci_contains(text, " -")) ||
             (ci_contains(text, "plausible") && ci_contains(text, " -")) ||
             (ci_contains(text, "umami") && ci_contains(text, " -")) ||
             ci_contains(text, "goatcounter") ||
             (ci_contains(text, "ackee") && ci_contains(text, " -")) ||
             ci_contains(text, "uptime-kuma") || ci_contains(text, "statping") ||
             (ci_contains(text, "cachet") && ci_contains(text, " -")) ||
             ci_contains(text, "kener") ||
             (ci_contains(text, "gatus") && ci_contains(text, " -")) ||
             ci_contains(text, "signoz") || ci_contains(text, "uptrace") ||
             ci_contains(text, "hyperdx") || ci_contains(text, "otelcol") ||
             ci_contains(text, "otel-cli") || ci_contains(text, "grafana-oncall") ||
             ci_contains(text, "opsgenie") || ci_contains(text, "victorops") ||
             ci_contains(text, "xmatters") || ci_contains(text, "ilert")) {
        what = "cirunner/registry/gateway/fflag/secretbroker/idp/ldap/analytics/uptime/apm/incident primitive";
        } else if (
             /* cycle-269b: sbom-sign/posture/bastion/automation-fabric/workflow/
                taskrun/scheduler/mqtt/graphdb/vecdb primitives */
             ci_contains(text, "sbom-tool") || ci_contains(text, "sbomqs") ||
             ci_contains(text, "spdx-sbom-generator") || ci_contains(text, "cdxgen") ||
             ci_contains(text, "cyclonedx-cli") ||
             (ci_contains(text, "tern") && ci_contains(text, " -") &&
              !ci_contains(text, "intern") && !ci_contains(text, "altern")) ||
             (ci_contains(text, "ort") && ci_contains(text, " -") && !ci_contains(text, "port")) ||
             ci_contains(text, "cloudsploit") ||
             (ci_contains(text, "cartography") && ci_contains(text, " -")) ||
             ci_contains(text, "awspx") || ci_contains(text, "bastillion") ||
             ci_contains(text, "sshportal") || ci_contains(text, "warpgate") ||
             (ci_contains(text, "rex") && ci_contains(text, " -")) ||
             (ci_contains(text, "func") && ci_contains(text, " -")) ||
             ci_contains(text, "ansible-runner") || ci_contains(text, "stackstorm") ||
             (ci_contains(text, "st2") && ci_contains(text, " -")) ||
             ci_contains(text, "dramatiq") ||
             (ci_contains(text, "huey") && ci_contains(text, " -")) ||
             ci_contains(text, "n8n") || ci_contains(text, "activepieces") ||
             (ci_contains(text, "windmill") && ci_contains(text, " -")) ||
             (ci_contains(text, "kestra") && ci_contains(text, " -")) ||
             (ci_contains(text, "dask") && ci_contains(text, " -")) ||
             (ci_contains(text, "ray") && ci_contains(text, " -") && !ci_contains(text, "xray") && !ci_contains(text, "array") && !ci_contains(text, "gray") && !ci_contains(text, "pray")) ||
             (ci_contains(text, "poe") && ci_contains(text, " -") &&
              !ci_contains(text, "poet")) ||
             ci_contains(text, "poethepoet") ||
             (ci_contains(text, "doit") && ci_contains(text, " -")) ||
             ci_contains(text, "pypyr") || ci_contains(text, "cronicle") ||
             (ci_contains(text, "ofelia") && ci_contains(text, " -")) ||
             ci_contains(text, "mcron") || ci_contains(text, "yacron") ||
             ci_contains(text, "nanomq") || ci_contains(text, "gmqtt") ||
             ci_contains(text, "memgraph") || ci_contains(text, "tugraph") ||
             ci_contains(text, "agensgraph") ||
             (ci_contains(text, "marqo") && ci_contains(text, " -")) ||
             ci_contains(text, "lancedb") || ci_contains(text, "pgvector") ||
             (ci_contains(text, "chroma") && ci_contains(text, " -"))) {
        what = "sbom/posture/bastion/automation/workflow/taskrun/sched/mqtt/graphdb/vecdb primitive";
        } else if (
             /* cycle-270a: uav/robotics/ot-ics/energy/aviation/marine/weather
                primitives */
             ci_contains(text, "ardupilot") || ci_contains(text, "qgroundcontrol") ||
             ci_contains(text, "mission-planner") ||
             (ci_contains(text, "px4") && ci_contains(text, " -")) ||
             (ci_contains(text, "ros2") && ci_contains(text, " -")) ||
             ci_contains(text, "rosbag") ||
             (ci_contains(text, "rviz") && ci_contains(text, " -")) ||
             (ci_contains(text, "gazebo") && ci_contains(text, " -")) ||
             (ci_contains(text, "moveit") && ci_contains(text, " -")) ||
             ci_contains(text, "eibd") || ci_contains(text, "linknx") ||
             ci_contains(text, "eibnetmux") || ci_contains(text, "openems") ||
             ci_contains(text, "victron") || ci_contains(text, "solaredge") ||
             ci_contains(text, "fronius") || ci_contains(text, "enphase") ||
             (ci_contains(text, "evcc") && ci_contains(text, " -")) ||
             (ci_contains(text, "ocpp") && ci_contains(text, " -")) ||
             ci_contains(text, "readsb") || ci_contains(text, "tar1090") ||
             ci_contains(text, "acarsdec") || ci_contains(text, "vdlm2dec") ||
             ci_contains(text, "opencpn") || ci_contains(text, "signalk") ||
             ci_contains(text, "canboat") || ci_contains(text, "weewx") ||
             (ci_contains(text, "cumulus") && ci_contains(text, " -")) ||
             ci_contains(text, "pywws")) {
        what = "uav/robotics/ot-ics/energy/aviation/marine/weather primitive";
        } else if (
             /* cycle-270b: miner-alt/wallet-alt/mev/validator/l2/bridge/
                oracle/indexer/cosmos/mixer/privacy/signing primitives */
             ci_contains(text, "bminer") || ci_contains(text, "dogecoin-cli") ||
             ci_contains(text, "wownero") ||
             (ci_contains(text, "grin") && ci_contains(text, " -")) ||
             ci_contains(text, "beam-wallet") || ci_contains(text, "ravencoin-cli") ||
             ci_contains(text, "mev-boost") || ci_contains(text, "flashbots") ||
             ci_contains(text, "ethdo") || ci_contains(text, "ssv-network") ||
             (ci_contains(text, "diva") && ci_contains(text, " -")) ||
             (ci_contains(text, "obol") && ci_contains(text, " -")) ||
             ci_contains(text, "lodestar") || ci_contains(text, "grandine") ||
             ci_contains(text, "nethermind") ||
             (ci_contains(text, "reth") && ci_contains(text, " -")) ||
             (ci_contains(text, "helios") && ci_contains(text, " -")) ||
             ci_contains(text, "erigon") || ci_contains(text, "op-node") ||
             ci_contains(text, "op-geth") ||
             (ci_contains(text, "nitro") && ci_contains(text, " -")) ||
             ci_contains(text, "zksync") ||
             (ci_contains(text, "bor") && ci_contains(text, " -")) ||
             ci_contains(text, "axelard") || ci_contains(text, "gravity-bridge") ||
             (ci_contains(text, "connext") && ci_contains(text, " -")) ||
             ci_contains(text, "chainlink") ||
             (ci_contains(text, "pyth") && ci_contains(text, " -") && !ci_contains(text, "pytho")) ||
             (ci_contains(text, "api3") && ci_contains(text, " -")) ||
             (ci_contains(text, "tellor") && ci_contains(text, " -")) ||
             (ci_contains(text, "dia") && ci_contains(text, " -") &&
              !ci_contains(text, "dia-") && !ci_contains(text, "india")) ||
             ci_contains(text, "graph-node") || ci_contains(text, "graph-cli") ||
             ci_contains(text, "subsquid") ||
             (ci_contains(text, "ponder") && ci_contains(text, " -")) ||
             (ci_contains(text, "envio") && ci_contains(text, " -")) ||
             ci_contains(text, "goldsky") || ci_contains(text, "binance-chain") ||
             ci_contains(text, "bnbcli") ||
             (ci_contains(text, "terrad") && ci_contains(text, " -")) ||
             ci_contains(text, "dymension") || ci_contains(text, "kujira") ||
             (ci_contains(text, "neutron") && ci_contains(text, " -")) ||
             (ci_contains(text, "stride") && ci_contains(text, " -")) ||
             ci_contains(text, "akash-provider") ||
             (ci_contains(text, "fetchd") && ci_contains(text, " -")) ||
             (ci_contains(text, "regen") && ci_contains(text, " -")) ||
             (ci_contains(text, "chihuahua") && ci_contains(text, " -")) ||
             ci_contains(text, "comdex") || ci_contains(text, "omniflix") ||
             (ci_contains(text, "quicksilver") && ci_contains(text, " -")) ||
             (ci_contains(text, "umee") && ci_contains(text, " -")) ||
             (ci_contains(text, "stargaze") && ci_contains(text, " -")) ||
             ci_contains(text, "agoric") ||
             (ci_contains(text, "crescent") && ci_contains(text, " -")) ||
             ci_contains(text, "secretcli") ||
             (ci_contains(text, "wasabi") && ci_contains(text, " -")) ||
             (ci_contains(text, "whirlpool") && ci_contains(text, " -")) ||
             (ci_contains(text, "samourai") && ci_contains(text, " -")) ||
             ci_contains(text, "joinmarket") || ci_contains(text, "coinjoin") ||
             (ci_contains(text, "zano") && ci_contains(text, " -")) ||
             (ci_contains(text, "firo") && ci_contains(text, " -")) ||
             ci_contains(text, "mobilecoin") || ci_contains(text, "bee-clef") ||
             ci_contains(text, "horcrux") || ci_contains(text, "tmkms") ||
             ci_contains(text, "cosmovisor")) {
        what = "miner/wallet/mev/validator/l2/bridge/oracle/indexer/cosmos/mixer/privacy/signing primitive";
        } else if (
             /* cycle-271a: mesh/lora/sdr-radio/sip/usenet/smallnet/anon/overlay/
                userspace-net primitives */
             (ci_contains(text, "rnode") && !ci_contains(text, "supernode")) ||
             (ci_contains(text, "rns") && ci_contains(text, " -")) ||
             ci_contains(text, "meshcore") || ci_contains(text, "xastir") ||
             ci_contains(text, "qsstv") || ci_contains(text, "freedv") ||
             ci_contains(text, "codec2") || ci_contains(text, "cubicsdr") ||
             ci_contains(text, "nntpcache") || ci_contains(text, "leafnode") ||
             (ci_contains(text, "tin ") && ci_contains(text, " -") &&
              !ci_contains(text, "latin ") && !ci_contains(text, "artin ") &&
              !ci_contains(text, "stin ")) ||
             (ci_contains(text, "slrn") && ci_contains(text, " -")) ||
             (ci_contains(text, "pan") && ci_contains(text, " -") &&
              !ci_contains(text, "apan") && !ci_contains(text, "pan-") &&
              !ci_contains(text, "expan") && !ci_contains(text, "japan") &&
              !ci_contains(text, "span") && !ci_contains(text, "cpan") &&
              !ci_contains(text, "pand") && !ci_contains(text, "pant")) ||
             ci_contains(text, "hellanzb") ||
             (ci_contains(text, "sacc") && ci_contains(text, " -")) ||
             (ci_contains(text, "lagrange") && ci_contains(text, " -")) ||
             (ci_contains(text, "amfora") && ci_contains(text, " -")) ||
             (ci_contains(text, "bombadillo") && ci_contains(text, " -")) ||
             (ci_contains(text, "offpunk") && ci_contains(text, " -")) ||
             (ci_contains(text, "gmni") && ci_contains(text, " -")) ||
             (ci_contains(text, "gtl") && ci_contains(text, " -")) ||
             (ci_contains(text, "ddgr") && ci_contains(text, " -")) ||
             (ci_contains(text, "googler") && ci_contains(text, " -")) ||
             ci_contains(text, "obfs4") || ci_contains(text, "obfsproxy") ||
             ci_contains(text, "dnscrypt") || ci_contains(text, "wireguard-go") ||
             ci_contains(text, "boringtun") ||
             (ci_contains(text, "vde2") && ci_contains(text, " -")) ||
             (ci_contains(text, "slirp") && ci_contains(text, " -") &&
              !ci_contains(text, "slurp")) ||
             ci_contains(text, "slirp4netns") ||
             (ci_contains(text, "pasta") && ci_contains(text, " -")) ||
             ci_contains(text, "gvisor-tap-vsock") ||
             (ci_contains(text, "arpd") && ci_contains(text, " -") &&
              !ci_contains(text, "warpd")) ||
             ci_contains(text, "netdiscover") || ci_contains(text, "bgpq3") ||
             ci_contains(text, "bgpq4") ||
             (ci_contains(text, "rpsl") && ci_contains(text, " -")) ||
             ci_contains(text, "peeringdb") || ci_contains(text, "routeview")) {
        what = "mesh/lora/sdr-radio/usenet/smallnet/anon/overlay/userspace-net primitive";
        } else if (
             /* cycle-271b: dnsdist/osint/sandbox/forensics/memory/disk/log/
                ir/malware-analysis/bindiff/firmware/container/k8s-extra/
                serverless/faas primitives */
             ci_contains(text, "dnsdist") || ci_contains(text, "socialscan") ||
             (ci_contains(text, "cape") && ci_contains(text, " -") &&
              !ci_contains(text, "cape-") && !ci_contains(text, "scape") &&
              !ci_contains(text, "escape") && !ci_contains(text, "landscap")) ||
             ci_contains(text, "vt-cli") || ci_contains(text, "malwoverview") ||
             ci_contains(text, "msoffcrypto") ||
             (ci_contains(text, "ils") && ci_contains(text, " -") &&
              !ci_contains(text, "ails") && !ci_contains(text, "tails") &&
              !ci_contains(text, "mails") && !ci_contains(text, "sails")) ||
             (ci_contains(text, "blkls") && ci_contains(text, " -")) ||
             ci_contains(text, "tsk_recover") || ci_contains(text, "tsk_loaddb") ||
             ci_contains(text, "ewfacquire") || ci_contains(text, "ewfinfo") ||
             ci_contains(text, "ewfmount") || ci_contains(text, "affacquire") ||
             ci_contains(text, "affinfo") || ci_contains(text, "affmount") ||
             ci_contains(text, "qphotorec") ||
             (ci_contains(text, "lnav") && ci_contains(text, " -")) ||
             ci_contains(text, "goaccess") ||
             (ci_contains(text, "multitail") && ci_contains(text, " -")) ||
             ci_contains(text, "sigma-cli") || ci_contains(text, "log2timeline") ||
             (ci_contains(text, "plaso") && ci_contains(text, " -")) ||
             ci_contains(text, "timesketch") ||
             (ci_contains(text, "kape") && ci_contains(text, " -")) ||
             (ci_contains(text, "kansa") && ci_contains(text, " -")) ||
             ci_contains(text, "ghidra-headless") ||
             (ci_contains(text, "angr") && ci_contains(text, " -") &&
              !ci_contains(text, "angry")) ||
             (ci_contains(text, "miasm") && ci_contains(text, " -")) ||
             (ci_contains(text, "quark") && ci_contains(text, " -") &&
              !ci_contains(text, "quark-") && !ci_contains(text, "square")) ||
             ci_contains(text, "yara-x") || ci_contains(text, "bindiff") ||
             (ci_contains(text, "diaphora") && ci_contains(text, " -")) ||
             (ci_contains(text, "jdiff") && ci_contains(text, " -")) ||
             (ci_contains(text, "bsdiff") && ci_contains(text, " -")) ||
             (ci_contains(text, "courgette") && ci_contains(text, " -")) ||
             ci_contains(text, "zydis") || ci_contains(text, "srec_cat") ||
             (ci_contains(text, "srecord") && ci_contains(text, " -")) ||
             ci_contains(text, "unblob") || ci_contains(text, "yaffshiv") ||
             (ci_contains(text, "dive") && ci_contains(text, " -") &&
              !ci_contains(text, "diver") && !ci_contains(text, "endive")) ||
             (ci_contains(text, "dockle") && ci_contains(text, " -")) ||
             ci_contains(text, "hadolint") || ci_contains(text, "rootlesskit") ||
             ci_contains(text, "ksniff") || ci_contains(text, "kubefwd") ||
             ci_contains(text, "kubent") ||
             (ci_contains(text, "fairwinds") && ci_contains(text, " -")) ||
             (ci_contains(text, "datree") && ci_contains(text, " -")) ||
             (ci_contains(text, "digger") && ci_contains(text, " -") &&
              !ci_contains(text, "digger-")) ||
             ci_contains(text, "meshctl") ||
             (ci_contains(text, "claudia") && ci_contains(text, " -")) ||
             (ci_contains(text, "apex") && ci_contains(text, " -") &&
              !ci_contains(text, "apex-") && !ci_contains(text, "tapex")) ||
             ci_contains(text, "kubeless") || ci_contains(text, "faasd") ||
             ci_contains(text, "openfaas-cli")) {
        what = "dnsdist/osint/sandbox/forensics/memory/disk/log/ir/malware-analysis/bindiff/firmware/container/k8s/serverless/faas primitive";
        } else if (
             /* cycle-272a: git-extra/convert/mail-infra/spam-filter/lists/
                caldav/irc/xmpp/matrix/voip-server primitives */
             ci_contains(text, "jujutsu") || ci_contains(text, "git-branchless") ||
             ci_contains(text, "git-secret") || ci_contains(text, "git-secrets") ||
             ci_contains(text, "git-quick-stats") || ci_contains(text, "git-extras") ||
             ci_contains(text, "gitui") || ci_contains(text, "gitbutler") ||
             ci_contains(text, "git-cliff") ||
             (ci_contains(text, "convco") && ci_contains(text, " -")) ||
             ci_contains(text, "cz-cli") || ci_contains(text, "semantic-release") ||
             ci_contains(text, "release-please") ||
             (ci_contains(text, "quilt") && ci_contains(text, " -")) ||
             (ci_contains(text, "wiggle") && ci_contains(text, " -")) ||
             (ci_contains(text, "recode") && ci_contains(text, " -")) ||
             (ci_contains(text, "uconv") && ci_contains(text, " -")) ||
             (ci_contains(text, "convmv") && ci_contains(text, " -")) ||
             (ci_contains(text, "detex") && ci_contains(text, " -")) ||
             (ci_contains(text, "untex") && ci_contains(text, " -")) ||
             ci_contains(text, "catdoc") || ci_contains(text, "docx2txt") ||
             (ci_contains(text, "unrtf") && ci_contains(text, " -")) ||
             ci_contains(text, "antiword") ||
             (ci_contains(text, "wvtext") && ci_contains(text, " -")) ||
             (ci_contains(text, "dma") && ci_contains(text, " -") &&
              !ci_contains(text, "dma-") && !ci_contains(text, "sendma") &&
              !ci_contains(text, "grandm")) ||
             (ci_contains(text, "maddy") && ci_contains(text, " -")) ||
             ci_contains(text, "stalwart-mail") || ci_contains(text, "zone-mta") ||
             ci_contains(text, "rspamd") || ci_contains(text, "mimedefang") ||
             (ci_contains(text, "amavis") && ci_contains(text, " -")) ||
             (ci_contains(text, "dcc") && ci_contains(text, " -")) ||
             ci_contains(text, "listmonk") || ci_contains(text, "mlmmj") ||
             ci_contains(text, "schleuder") ||
             (ci_contains(text, "dada") && ci_contains(text, " -")) ||
             ci_contains(text, "imapsync") || ci_contains(text, "radicale") ||
             ci_contains(text, "baikal") || ci_contains(text, "davical") ||
             (ci_contains(text, "sogo") && ci_contains(text, " -")) ||
             ci_contains(text, "xandikos") || ci_contains(text, "ircd-hybrid") ||
             ci_contains(text, "miniircd") || ci_contains(text, "openfire") ||
             (ci_contains(text, "conduit") && ci_contains(text, " -")) ||
             ci_contains(text, "conduwuit") || ci_contains(text, "matrix-appservice-irc") ||
             ci_contains(text, "matrix-hookshot") || ci_contains(text, "heisenbridge") ||
             ci_contains(text, "mx-puppet") ||
             (ci_contains(text, "murmur") && ci_contains(text, " -")) ||
             ci_contains(text, "umurmur") ||
             (ci_contains(text, "revolt") && ci_contains(text, " -"))) {
        what = "git-extra/convert/mail-infra/spam-filter/lists/caldav/irc/xmpp/matrix/voip-server primitive";
        } else if (
             /* cycle-272b: fediverse/pastebin/urlshort/bookmark/docsrv/fileshare/
                gallery/kanban/cms/ecomm/crm primitives */
             ci_contains(text, "misskey") || ci_contains(text, "akkoma") ||
             ci_contains(text, "pleroma") || ci_contains(text, "gotosocial") ||
             ci_contains(text, "pixelfed") || ci_contains(text, "owncast") ||
             ci_contains(text, "mastodon-tootctl") || ci_contains(text, "privatebin") ||
             (ci_contains(text, "fiche") && ci_contains(text, " -")) ||
             ci_contains(text, "pastebinit") ||
             (ci_contains(text, "shlink") && ci_contains(text, " -")) ||
             (ci_contains(text, "yourls") && ci_contains(text, " -")) ||
             (ci_contains(text, "kutt") && ci_contains(text, " -")) ||
             (ci_contains(text, "polr") && ci_contains(text, " -")) ||
             ci_contains(text, "wallabag") ||
             (ci_contains(text, "shaarli") && ci_contains(text, " -")) ||
             ci_contains(text, "linkding") || ci_contains(text, "linkwarden") ||
             ci_contains(text, "archivebox") || ci_contains(text, "hedgedoc") ||
             ci_contains(text, "joplin-server") ||
             (ci_contains(text, "memos") && ci_contains(text, " -")) ||
             ci_contains(text, "flatnotes") || ci_contains(text, "silverbullet") ||
             ci_contains(text, "bookstack") || ci_contains(text, "snapdrop") ||
             ci_contains(text, "localsend") || ci_contains(text, "psitransfer") ||
             ci_contains(text, "lychee") || ci_contains(text, "piwigo") ||
             ci_contains(text, "librephotos") || ci_contains(text, "immich") ||
             ci_contains(text, "stagit") ||
             (ci_contains(text, "gitiles") && ci_contains(text, " -")) ||
             (ci_contains(text, "gitweb") && ci_contains(text, " -")) ||
             ci_contains(text, "forgejo") ||
             (ci_contains(text, "taskd") && ci_contains(text, " -")) ||
             (ci_contains(text, "planka") && ci_contains(text, " -")) ||
             ci_contains(text, "wekan") || ci_contains(text, "focalboard") ||
             ci_contains(text, "kanboard") ||
             (ci_contains(text, "taiga") && ci_contains(text, " -")) ||
             ci_contains(text, "directus") || ci_contains(text, "strapi") ||
             ci_contains(text, "sanity-cli") || ci_contains(text, "contentful-cli") ||
             ci_contains(text, "saleor") || ci_contains(text, "vendure") ||
             ci_contains(text, "shopify-cli") || ci_contains(text, "square-cli") ||
             (ci_contains(text, "monica") && ci_contains(text, " -")) ||
             (ci_contains(text, "twenty") && ci_contains(text, " -"))) {
        what = "fediverse/pastebin/urlshort/bookmark/docsrv/fileshare/gallery/kanban/cms/ecomm/crm primitive";
        } else if (
             /* cycle-273a: canbus/plc/cnc/laser/pcb/rf/rfid/smartcard/hsm-tpm/
                fido/barcode/label/pos primitives */
             ci_contains(text, "socketcand") ||
             (ci_contains(text, "kayak") && ci_contains(text, " -")) ||
             ci_contains(text, "cantoolz") || ci_contains(text, "caringcaribou") ||
             ci_contains(text, "udsim") ||
             (ci_contains(text, "icom") && ci_contains(text, " -")) ||
             ci_contains(text, "savvycan") || ci_contains(text, "openplc") ||
             ci_contains(text, "matiec") || ci_contains(text, "beremiz") ||
             ci_contains(text, "linuxcnc") || ci_contains(text, "grbl") ||
             ci_contains(text, "fluidnc") || ci_contains(text, "bcnc") ||
             ci_contains(text, "cncjs") ||
             (ci_contains(text, "ugs") && ci_contains(text, " -") &&
              !ci_contains(text, "bugs") && !ci_contains(text, "pugs") &&
              !ci_contains(text, "plugs")) ||
             ci_contains(text, "chilipeppr") || ci_contains(text, "laserweb") ||
             ci_contains(text, "visicut") ||
             (ci_contains(text, "inkcut") && ci_contains(text, " -")) ||
             ci_contains(text, "pcb2gcode") || ci_contains(text, "flatcam") ||
             ci_contains(text, "qspectrumanalyzer") ||
             (ci_contains(text, "rfcat") && ci_contains(text, " -")) ||
             (ci_contains(text, "rflib") && ci_contains(text, " -")) ||
             ci_contains(text, "libnfc") || ci_contains(text, "nfc-tools") ||
             ci_contains(text, "pcsc-tools") ||
             (ci_contains(text, "ccid") && ci_contains(text, " -")) ||
             ci_contains(text, "pkcs15-tool") || ci_contains(text, "opencryptoki") ||
             ci_contains(text, "tpm2-tss") || ci_contains(text, "tpm2-abrmd") ||
             (ci_contains(text, "tang") && ci_contains(text, " -") &&
              !ci_contains(text, "mustang") && !ci_contains(text, "tang-")) ||
             ci_contains(text, "fido2luks") || ci_contains(text, "pam-u2f") ||
             ci_contains(text, "solo1-cli") ||
             (ci_contains(text, "zint") && ci_contains(text, " -")) ||
             ci_contains(text, "brother_ql") || ci_contains(text, "ptouch") ||
             ci_contains(text, "dymoprint") ||
             (ci_contains(text, "escpos") && ci_contains(text, " -"))) {
        what = "canbus/plc/cnc/laser/pcb/rf/rfid/smartcard/hsm-tpm/fido/barcode/label/pos primitive";
        } else if (
             /* cycle-273b: asset/cmdb/dcim/ipam/aaa/dot1x/vpn/wg/portknock +
                sms/sim/cellular/ais/seismic/geophysics/physics/astro primitives */
             ci_contains(text, "snipeit") ||
             (ci_contains(text, "glpi") && ci_contains(text, " -")) ||
             ci_contains(text, "fusioninventory") || ci_contains(text, "racktables") ||
             ci_contains(text, "i-doit") || ci_contains(text, "cmdbuild") ||
             (ci_contains(text, "ralph") && ci_contains(text, " -")) ||
             ci_contains(text, "phpipam") || ci_contains(text, "nipap") ||
             ci_contains(text, "teemip") || ci_contains(text, "daloradius") ||
             ci_contains(text, "packetfence") || ci_contains(text, "tacacs-ng") ||
             ci_contains(text, "xsupplicant") || ci_contains(text, "softether") ||
             ci_contains(text, "dsvpn") || ci_contains(text, "vtund") ||
             ci_contains(text, "wgcf") || ci_contains(text, "onetun") ||
             ci_contains(text, "knockd") ||
             (ci_contains(text, "knock") && ci_contains(text, " -") &&
              !ci_contains(text, "knock-")) ||
             ci_contains(text, "fwknop") || ci_contains(text, "playsms") ||
             ci_contains(text, "jasmin-sms") ||
             (ci_contains(text, "lpac") && ci_contains(text, " -") &&
              !ci_contains(text, "elpac")) ||
             ci_contains(text, "sysmo-usim-tool") || ci_contains(text, "osmo-bsc") ||
             ci_contains(text, "osmo-hlr") || ci_contains(text, "osmo-msc") ||
             ci_contains(text, "osmo-sgsn") || ci_contains(text, "osmo-ggsn") ||
             ci_contains(text, "osmo-pcu") || ci_contains(text, "osmo-cbc") ||
             ci_contains(text, "gnuais") || ci_contains(text, "aisutils") ||
             ci_contains(text, "seedlink") || ci_contains(text, "seiscomp") ||
             ci_contains(text, "slinktool") || ci_contains(text, "dataselect") ||
             ci_contains(text, "obspy") ||
             (ci_contains(text, "gmt") && ci_contains(text, " -") &&
              !ci_contains(text, "gmt-")) ||
             (ci_contains(text, "madagascar") && ci_contains(text, " -")) ||
             ci_contains(text, "seismic-unix") || ci_contains(text, "openmc") ||
             ci_contains(text, "geant4") || ci_contains(text, "cernlib") ||
             (ci_contains(text, "herwig") && ci_contains(text, " -")) ||
             (ci_contains(text, "sherpa") && ci_contains(text, " -")) ||
             ci_contains(text, "madgraph") ||
             (ci_contains(text, "gildas") && ci_contains(text, " -")) ||
             (ci_contains(text, "aips") && ci_contains(text, " -") &&
              !ci_contains(text, "naips")) ||
             (ci_contains(text, "casa") && ci_contains(text, " -") &&
              !ci_contains(text, "casa-") && !ci_contains(text, "showcase")) ||
             (ci_contains(text, "miriad") && ci_contains(text, " -")) ||
             (ci_contains(text, "iraf") && ci_contains(text, " -") &&
              !ci_contains(text, "giraf")) ||
             ci_contains(text, "orekit") ||
             (ci_contains(text, "gmat") && ci_contains(text, " -"))) {
        what = "asset/cmdb/dcim/ipam/aaa/dot1x/vpn/wg/portknock/sms/sim/cellular/ais/seismic/geophysics/physics/astro primitive";
        } else if (
             /* cycle-274a: llm/tts/imagegen/mlops primitives */
             ci_contains(text, "llama-cli") || ci_contains(text, "koboldcpp") ||
             ci_contains(text, "gpt4all") ||
             (ci_contains(text, "tgi") && ci_contains(text, " -")) ||
             (ci_contains(text, "jan") && ci_contains(text, " -") &&
              !ci_contains(text, "jan-")) ||
             ci_contains(text, "gptme") ||
             (ci_contains(text, "tabby") && ci_contains(text, " -")) ||
             (ci_contains(text, "mentat") && ci_contains(text, " -")) ||
             ci_contains(text, "open-interpreter") ||
             (ci_contains(text, "interpreter") && ci_contains(text, " -")) ||
             ci_contains(text, "whisper-cli") || ci_contains(text, "whisperx") ||
             ci_contains(text, "stable-ts") || ci_contains(text, "faster-whisper") ||
             (ci_contains(text, "bark") && ci_contains(text, " -") &&
              !ci_contains(text, "embark") && !ci_contains(text, "bark-")) ||
             (ci_contains(text, "tts") && ci_contains(text, " -") &&
              !ci_contains(text, "otts") && !ci_contains(text, "atts")) ||
             (ci_contains(text, "coqui") && ci_contains(text, " -")) ||
             (ci_contains(text, "xtts") && ci_contains(text, " -")) ||
             (ci_contains(text, "rvc") && ci_contains(text, " -")) ||
             ci_contains(text, "audiocraft") || ci_contains(text, "comfy-cli") ||
             ci_contains(text, "fooocus") || ci_contains(text, "a1111") ||
             ci_contains(text, "automatic1111") ||
             (ci_contains(text, "cog") && ci_contains(text, " -") &&
              !ci_contains(text, "cog-") && !ci_contains(text, "incog")) ||
             ci_contains(text, "bentoml") || ci_contains(text, "tritonserver") ||
             ci_contains(text, "seldon") || ci_contains(text, "kserve") ||
             ci_contains(text, "polyaxon")) {
        what = "llm/tts/imagegen/mlops primitive";
        } else if (
             /* cycle-274b: notebook/data-eng/db-client/data-quality/cdc/bi/
                spreadsheet/forms/diagram/rss/podcast/audiobook/ebook/comics/
                recipe/finance/library/genealogy primitives */
             (ci_contains(text, "nteract") && !ci_contains(text, "interact")) || ci_contains(text, "streamlit") ||
             ci_contains(text, "gradio") ||
             (ci_contains(text, "voila") && ci_contains(text, " -")) ||
             ci_contains(text, "nicegui") || ci_contains(text, "marimo") ||
             ci_contains(text, "papermill") || ci_contains(text, "nbconvert") ||
             ci_contains(text, "nbdime") || ci_contains(text, "nbstripout") ||
             ci_contains(text, "sqlmesh") || ci_contains(text, "datahub") ||
             ci_contains(text, "openmetadata") ||
             (ci_contains(text, "marquez") && ci_contains(text, " -")) ||
             ci_contains(text, "lazysql") ||
             (ci_contains(text, "harlequin") && ci_contains(text, " -")) ||
             ci_contains(text, "dbgate") || ci_contains(text, "great-expectations") ||
             (ci_contains(text, "elementary") && ci_contains(text, " -")) ||
             ci_contains(text, "debezium-server") || ci_contains(text, "peerdb") ||
             (ci_contains(text, "sequin") && ci_contains(text, " -")) ||
             ci_contains(text, "superset-cli") || ci_contains(text, "redash") ||
             ci_contains(text, "lightdash") ||
             (ci_contains(text, "cube") && ci_contains(text, " -") &&
              !ci_contains(text, "cube-") && !ci_contains(text, "icecube")) ||
             ci_contains(text, "dremio") ||
             (ci_contains(text, "grist") && ci_contains(text, " -")) ||
             ci_contains(text, "baserow") || ci_contains(text, "nocodb") ||
             ci_contains(text, "rowy") || ci_contains(text, "teable") ||
             ci_contains(text, "apitable") || ci_contains(text, "undb") ||
             ci_contains(text, "formbricks") ||
             (ci_contains(text, "d2") && ci_contains(text, " -") &&
              !ci_contains(text, "d2-")) ||
             ci_contains(text, "svgbob") || ci_contains(text, "freshrss") ||
             ci_contains(text, "tt-rss") || ci_contains(text, "miniflux") ||
             ci_contains(text, "selfoss") || ci_contains(text, "commafeed") ||
             ci_contains(text, "rssguard") || ci_contains(text, "fluent-reader") ||
             ci_contains(text, "rss2email") || ci_contains(text, "castget") ||
             ci_contains(text, "podget") || ci_contains(text, "podcast-dl") ||
             (ci_contains(text, "gpo") && ci_contains(text, " -")) ||
             ci_contains(text, "audiobookshelf") || ci_contains(text, "lazylibrarian") ||
             ci_contains(text, "koreader") || ci_contains(text, "epubcheck") ||
             ci_contains(text, "kepubify") || ci_contains(text, "kindlegen") ||
             (ci_contains(text, "sigil") && ci_contains(text, " -")) ||
             ci_contains(text, "komga") || ci_contains(text, "kavita") ||
             ci_contains(text, "mcomix") || ci_contains(text, "mealie") ||
             ci_contains(text, "tandoor") || ci_contains(text, "grocy") ||
             ci_contains(text, "actual-server") || ci_contains(text, "ghostfolio") ||
             ci_contains(text, "koha") || ci_contains(text, "biblioteq") ||
             (ci_contains(text, "gramps") && ci_contains(text, " -")) ||
             ci_contains(text, "webtrees")) {
        what = "notebook/data-eng/db-client/data-quality/cdc/bi/spreadsheet/forms/diagram/rss/podcast/ebook/comics/recipe/finance/library/genealogy primitive";
        } else if (
             /* cycle-275a: nvr-surveillance/iptv/playout/webrtc-sfu/edu
                primitives */
             (ci_contains(text, "frigate") && ci_contains(text, " -")) ||
             ci_contains(text, "viseron") || ci_contains(text, "kerberos-agent") ||
             ci_contains(text, "bluecherry") || ci_contains(text, "shinobi") ||
             ci_contains(text, "scrypted") || ci_contains(text, "tvheadend") ||
             (ci_contains(text, "vdr") && ci_contains(text, " -") &&
              !ci_contains(text, "vdr-")) ||
             ci_contains(text, "mythbackend") || ci_contains(text, "nextpvr") ||
             ci_contains(text, "dvbscan") || ci_contains(text, "w_scan") ||
             ci_contains(text, "casparcg") || ci_contains(text, "red5") ||
             ci_contains(text, "mistserver") || ci_contains(text, "antmedia") ||
             ci_contains(text, "livekit-server") || ci_contains(text, "mediasoup") ||
             ci_contains(text, "janus-gateway") || ci_contains(text, "ion-sfu") ||
             ci_contains(text, "openvidu") ||
             (ci_contains(text, "galene") && ci_contains(text, " -")) ||
             ci_contains(text, "jitsi-videobridge") || ci_contains(text, "jicofo") ||
             ci_contains(text, "jigasi") || ci_contains(text, "chamilo") ||
             (ci_contains(text, "ilias") && ci_contains(text, " -"))) {
        what = "nvr-surveillance/iptv/playout/webrtc-sfu/edu primitive";
        } else if (
             /* cycle-275b: video-encode/subtitle/music-prod/tracker/
                audio-analysis/asr/diarize/voice-clone/noise primitives */
             ci_contains(text, "kdenlive-render") || ci_contains(text, "lossless-cut") ||
             ci_contains(text, "ab-av1") || ci_contains(text, "svt-av1") ||
             ci_contains(text, "rav1e") || ci_contains(text, "x264") ||
             ci_contains(text, "x265") || ci_contains(text, "kvazaar") ||
             ci_contains(text, "vvenc") || ci_contains(text, "av1an") ||
             ci_contains(text, "vmaf") ||
             (ci_contains(text, "gaupol") && ci_contains(text, " -")) ||
             ci_contains(text, "subtitlecomposer") || ci_contains(text, "ccextractor") ||
             ci_contains(text, "ffsubsync") ||
             (ci_contains(text, "alass") && ci_contains(text, " -")) ||
             ci_contains(text, "lmms") ||
             (ci_contains(text, "ardour") && ci_contains(text, " -")) ||
             (ci_contains(text, "hydrogen") && ci_contains(text, " -") &&
              !ci_contains(text, "hydrogen-")) ||
             ci_contains(text, "zrythm") ||
             (ci_contains(text, "carla") && ci_contains(text, " -")) ||
             (ci_contains(text, "cadence") && ci_contains(text, " -")) ||
             ci_contains(text, "non-sequencer") || ci_contains(text, "rosegarden") ||
             ci_contains(text, "musescore") ||
             (ci_contains(text, "denemo") && ci_contains(text, " -")) ||
             ci_contains(text, "lilypond") ||
             (ci_contains(text, "frescobaldi") && ci_contains(text, " -")) ||
             ci_contains(text, "pt2-clone") || ci_contains(text, "ft2-clone") ||
             (ci_contains(text, "furnace") && ci_contains(text, " -")) ||
             ci_contains(text, "0cc-famitracker") || ci_contains(text, "hivelytracker") ||
             ci_contains(text, "sonic-annotator") || ci_contains(text, "aubio") ||
             ci_contains(text, "yaafe") || ci_contains(text, "bextract") ||
             ci_contains(text, "deepspeech") || ci_contains(text, "pocketsphinx") ||
             (ci_contains(text, "kaldi") && ci_contains(text, " -")) ||
             (ci_contains(text, "julius") && ci_contains(text, " -")) ||
             ci_contains(text, "pyannote") || ci_contains(text, "resemblyzer") ||
             ci_contains(text, "so-vits-svc") || ci_contains(text, "tortoise-tts") ||
             ci_contains(text, "rnnoise") || ci_contains(text, "deepfilternet")) {
        what = "video-encode/subtitle/music-prod/tracker/audio-analysis/asr/diarize/voice-clone/noise primitive";
        } else if (
             /* cycle-275c: emulation/game-port/vintage-sim/mcu-sim/ebpf/
                crashdump/boot-trace/secureboot primitives */
             ci_contains(text, "dosbox-x") || ci_contains(text, "dosbox-staging") ||
             ci_contains(text, "fuse-emu") ||
             (ci_contains(text, "vice") && ci_contains(text, " -") &&
              !ci_contains(text, "vice-") && !ci_contains(text, "service") &&
              !ci_contains(text, "advice") && !ci_contains(text, "device")) ||
             ci_contains(text, "fs-uae") || ci_contains(text, "hatari") ||
             (ci_contains(text, "stella") && ci_contains(text, " -")) ||
             (ci_contains(text, "mess") && ci_contains(text, " -") &&
              !ci_contains(text, "messag")) ||
             ci_contains(text, "desmume") || ci_contains(text, "melonds") ||
             (ci_contains(text, "citra") && ci_contains(text, " -")) ||
             (ci_contains(text, "yuzu") && ci_contains(text, " -")) ||
             ci_contains(text, "ryujinx") ||
             (ci_contains(text, "cemu") && ci_contains(text, " -")) ||
             ci_contains(text, "rpcs3") ||
             (ci_contains(text, "xemu") && ci_contains(text, " -")) ||
             ci_contains(text, "duckstation") || ci_contains(text, "flycast") ||
             ci_contains(text, "redream") ||
             (ci_contains(text, "higan") && ci_contains(text, " -")) ||
             ci_contains(text, "bsnes") || ci_contains(text, "snes9x") ||
             ci_contains(text, "zsnes") || ci_contains(text, "fceux") ||
             ci_contains(text, "nestopia") || ci_contains(text, "gambatte") ||
             ci_contains(text, "mgba") ||
             (ci_contains(text, "vbam") && ci_contains(text, " -")) ||
             ci_contains(text, "ppsspp") ||
             (ci_contains(text, "jpcsp") && ci_contains(text, " -")) ||
             ci_contains(text, "openemu") || ci_contains(text, "openxcom") ||
             ci_contains(text, "ufoai") || ci_contains(text, "openmw") ||
             ci_contains(text, "openra") || ci_contains(text, "openage") ||
             ci_contains(text, "wesnoth") || ci_contains(text, "openttd") ||
             ci_contains(text, "simutrans") || ci_contains(text, "openrct2") ||
             ci_contains(text, "openloco") || ci_contains(text, "corsixth") ||
             ci_contains(text, "openbve") || ci_contains(text, "flightgear") ||
             ci_contains(text, "vdrift") || ci_contains(text, "speed-dreams") ||
             (ci_contains(text, "torcs") && ci_contains(text, " -")) ||
             ci_contains(text, "supertuxkart") || ci_contains(text, "tuxpaint") ||
             ci_contains(text, "dosemu") || ci_contains(text, "dosemu2") ||
             ci_contains(text, "basilisk2") || ci_contains(text, "sheepshaver") ||
             (ci_contains(text, "simh") && ci_contains(text, " -")) ||
             (ci_contains(text, "klh10") && ci_contains(text, " -")) ||
             ci_contains(text, "hercules-390") || ci_contains(text, "s390-tools") ||
             ci_contains(text, "open-simh") || ci_contains(text, "cool-retro-term") ||
             ci_contains(text, "simavr") || ci_contains(text, "simulide") ||
             ci_contains(text, "gpsim") || ci_contains(text, "simulavr") ||
             ci_contains(text, "skyeye") ||
             (ci_contains(text, "drgn") && ci_contains(text, " -")) ||
             ci_contains(text, "bpfmenu") || ci_contains(text, "xdpdump") ||
             ci_contains(text, "pcapplusplus") || ci_contains(text, "kubectl-trace") ||
             (ci_contains(text, "pstack") && ci_contains(text, " -")) ||
             ci_contains(text, "bootchart") || ci_contains(text, "bootchart2") ||
             ci_contains(text, "systemd-bootchart") ||
             (ci_contains(text, "fwts") && ci_contains(text, " -")) ||
             ci_contains(text, "sbsigntool") || ci_contains(text, "sbverify")) {
        what = "emulation/game-port/vintage-sim/mcu-sim/ebpf/crashdump/boot-trace/secureboot primitive";
        } else if (
             /* cycle-276a: chatbot/messaging-cli/web-archive/kiwix/maps/gdal/
                lidar/photogrammetry/3d-tool primitives */
             ci_contains(text, "hubot") || ci_contains(text, "opsdroid") ||
             ci_contains(text, "matterbot") ||
             (ci_contains(text, "rasa") && ci_contains(text, " -")) ||
             (ci_contains(text, "tg") && ci_contains(text, " -") &&
              !ci_contains(text, "tg-") && !ci_contains(text, "tg_") &&
              !ci_contains(text, "itg") && !ci_contains(text, "etg")) ||
             (ci_contains(text, "tdl") && ci_contains(text, " -")) ||
             ci_contains(text, "tdlib") || ci_contains(text, "slack-term") ||
             ci_contains(text, "wee-slack") || ci_contains(text, "chat-downloader") ||
             ci_contains(text, "twitch-dl") || ci_contains(text, "warcio") ||
             ci_contains(text, "warcit") || ci_contains(text, "browsertrix") ||
             ci_contains(text, "pywb") || ci_contains(text, "heritrix") ||
             ci_contains(text, "webarchiveplayer") || ci_contains(text, "kiwix-serve") ||
             ci_contains(text, "kiwix-manage") || ci_contains(text, "zimdump") ||
             ci_contains(text, "tile38") || ci_contains(text, "tileserver-gl") ||
             ci_contains(text, "osm2pgsql") || ci_contains(text, "pelias") ||
             ci_contains(text, "osmctools") || ci_contains(text, "gdal_translate") ||
             ci_contains(text, "gdalwarp") || ci_contains(text, "gdalinfo") ||
             ci_contains(text, "gdal_merge") || ci_contains(text, "gdalbuildvrt") ||
             ci_contains(text, "gdaldem") || ci_contains(text, "gdal_rasterize") ||
             ci_contains(text, "ogr2ogr") || ci_contains(text, "ogrinfo") ||
             (ci_contains(text, "rio") && ci_contains(text, " -")) ||
             ci_contains(text, "pdal") || ci_contains(text, "las2las") ||
             ci_contains(text, "laszip") || ci_contains(text, "lasinfo") ||
             ci_contains(text, "cloudcompare") ||
             (ci_contains(text, "odm") && ci_contains(text, " -")) ||
             ci_contains(text, "micmac") || ci_contains(text, "openmvg") ||
             ci_contains(text, "opensfm") || ci_contains(text, "colmap") ||
             ci_contains(text, "alicevision") ||
             (ci_contains(text, "mve") && ci_contains(text, " -")) ||
             ci_contains(text, "meshlabserver") || ci_contains(text, "pcl_viewer") ||
             ci_contains(text, "assimp") || ci_contains(text, "meshconv") ||
             ci_contains(text, "obj2gltf") || ci_contains(text, "gltf-pipeline") ||
             ci_contains(text, "gltf-transform")) {
        what = "chatbot/messaging-cli/web-archive/kiwix/maps/gdal/lidar/photogrammetry/3d-tool primitive";
        } else if (
             /* cycle-276b: netsim/sdn/p4/dpdk/telecom + proj/routing/iot/
                coap/lorawan/building/grid/meter/geocode primitives */
             ci_contains(text, "ns-3") || ci_contains(text, "ns3 ") ||
             ci_contains(text, "omnetpp") || ci_contains(text, "mininet-wifi") ||
             ci_contains(text, "coreemu") || ci_contains(text, "imunes") ||
             (ci_contains(text, "pox") && ci_contains(text, " -")) ||
             (ci_contains(text, "floodlight") && ci_contains(text, " -")) ||
             (ci_contains(text, "trema") && ci_contains(text, " -")) ||
             ci_contains(text, "p4c") || ci_contains(text, "behavioral-model") ||
             ci_contains(text, "p4runtime") || ci_contains(text, "dpdk-testpmd") ||
             ci_contains(text, "pktgen-dpdk") || ci_contains(text, "libmoon") ||
             ci_contains(text, "ueransim") ||
             (ci_contains(text, "seagull") && ci_contains(text, " -")) ||
             ci_contains(text, "jss7") || ci_contains(text, "sigtran") ||
             ci_contains(text, "cs2cs") ||
             (ci_contains(text, "geod") && ci_contains(text, " -")) ||
             (ci_contains(text, "cct") && ci_contains(text, " -") &&
              !ci_contains(text, "acct")) ||
             (ci_contains(text, "gie") && ci_contains(text, " -")) ||
             ci_contains(text, "spatialite") || ci_contains(text, "osrm-backend") ||
             ci_contains(text, "graphhopper") ||
             (ci_contains(text, "motis") && ci_contains(text, " -")) ||
             ci_contains(text, "mainflux") || ci_contains(text, "kubeedge") ||
             (ci_contains(text, "akri") && ci_contains(text, " -")) ||
             ci_contains(text, "libcoap") || ci_contains(text, "aiocoap") ||
             ci_contains(text, "chirpstack") || ci_contains(text, "ttn-cli") ||
             ci_contains(text, "lora-gateway") || ci_contains(text, "volttron") ||
             (ci_contains(text, "haystack") && ci_contains(text, " -")) ||
             ci_contains(text, "nhaystack") || ci_contains(text, "gridlabd") ||
             ci_contains(text, "matpower") || ci_contains(text, "pypower") ||
             ci_contains(text, "powsybl") || ci_contains(text, "iec62056") ||
             ci_contains(text, "guruux") || ci_contains(text, "libpostal") ||
             ci_contains(text, "pelias-schema")) {
        what = "netsim/sdn/p4/dpdk/telecom/proj/routing/iot/coap/lorawan/building/grid/meter/geocode primitive";
        } else if (
             /* cycle-277a: wasm/sandbox/unikernel/virt-guest/k8s-dist primitives */
             ci_contains(text, "wasm-bindgen") || ci_contains(text, "emcc") ||
             ci_contains(text, "emmake") || ci_contains(text, "emconfigure") ||
             ci_contains(text, "wasm-opt") || ci_contains(text, "wasm2wat") ||
             ci_contains(text, "wat2wasm") || ci_contains(text, "wasm-ld") ||
             ci_contains(text, "twiggy") || ci_contains(text, "wasm-snip") ||
             ci_contains(text, "sandbox2") || ci_contains(text, "unikraft") ||
             (ci_contains(text, "nanos") && ci_contains(text, " -")) ||
             (ci_contains(text, "osv") && ci_contains(text, " -")) ||
             (ci_contains(text, "mirage") && ci_contains(text, " -")) ||
             ci_contains(text, "solo5") || ci_contains(text, "virt-p2v") ||
             ci_contains(text, "kustomize") ||
             (ci_contains(text, "redpanda") && ci_contains(text, " -")) ||
             (ci_contains(text, "aeron") && ci_contains(text, " -")) ||
             ci_contains(text, "opensearch") ||
             (ci_contains(text, "manticore") && ci_contains(text, " -")) ||
             ci_contains(text, "parquet-tools") || ci_contains(text, "avro-tools") ||
             ci_contains(text, "orc-tools") || ci_contains(text, "victoriametrics") ||
             ci_contains(text, "vmutils") || ci_contains(text, "m3db") ||
             ci_contains(text, "valkey") || ci_contains(text, "keydb") ||
             (ci_contains(text, "garnet") && ci_contains(text, " -")) ||
             ci_contains(text, "rethinkdb") || ci_contains(text, "surrealdb") ||
             ci_contains(text, "ysqlsh") || ci_contains(text, "ycqlsh") ||
             ci_contains(text, "yb-admin") || ci_contains(text, "tidb") ||
             ci_contains(text, "vitess") || ci_contains(text, "immudb") ||
             ci_contains(text, "nostrcli") ||
             (ci_contains(text, "iris") && ci_contains(text, " -")) ||
             (ci_contains(text, "damus") && ci_contains(text, " -"))) {
        what = "wasm/sandbox/unikernel/virt-guest/k8s-dist/mq/search/columnar/tsdb/kv/docdb/newsql/nostr primitive";
        } else if (
             /* cycle-277b: formatter/linter/env-mgr/build-sys primitives */
             (ci_contains(text, "black") && ci_contains(text, " -") &&
              !ci_contains(text, "blackb")) ||
             (ci_contains(text, "isort") && ci_contains(text, " -")) ||
             ci_contains(text, "flake8") ||
             (ci_contains(text, "pylint") && ci_contains(text, " -")) ||
             ci_contains(text, "mypy") ||
             (ci_contains(text, "ruff") && ci_contains(text, " -")) ||
             ci_contains(text, "eslint") ||
             (ci_contains(text, "prettier") && ci_contains(text, " -")) ||
             ci_contains(text, "stylelint") || ci_contains(text, "php-cs-fixer") ||
             ci_contains(text, "gofumpt") || ci_contains(text, "goimports") ||
             ci_contains(text, "clang-format") || ci_contains(text, "rustfmt") ||
             (ci_contains(text, "brakeman") && ci_contains(text, " -")) ||
             (ci_contains(text, "gosec") && ci_contains(text, " -")) ||
             (ci_contains(text, "spack") && ci_contains(text, " -")) ||
             ci_contains(text, "micromamba") || ci_contains(text, "virtualenv") ||
             ci_contains(text, "pipenv") ||
             (ci_contains(text, "volta") && ci_contains(text, " -")) ||
             (ci_contains(text, "xmake") && ci_contains(text, " -")) ||
             (ci_contains(text, "plz") && ci_contains(text, " -"))) {
        what = "formatter/linter/env-mgr/build-sys primitive";
        } else if (
             /* cycle-277c: license/radare2/honeypot/wifi/pwattack/stego/tunnel primitives */
             ci_contains(text, "scancode-toolkit") ||
             (ci_contains(text, "reuse") && ci_contains(text, " -")) ||
             (ci_contains(text, "fossa") && ci_contains(text, " -")) ||
             ci_contains(text, "license-checker") || ci_contains(text, "ragg2") ||
             ci_contains(text, "rax2") || ci_contains(text, "rafind2") ||
             ci_contains(text, "rahash2") || ci_contains(text, "rarun2") ||
             ci_contains(text, "rasign2") || ci_contains(text, "cowrie") ||
             ci_contains(text, "honeyd") || ci_contains(text, "kippo") ||
             ci_contains(text, "airodump-ng") || ci_contains(text, "hcxtools") ||
             ci_contains(text, "hashcat-utils") || ci_contains(text, "kwprocessor") ||
             ci_contains(text, "princeprocessor") || ci_contains(text, "hashid") ||
             ci_contains(text, "name-that-hash") ||
             (ci_contains(text, "cupp") && ci_contains(text, " -")) ||
             ci_contains(text, "ligolo-ng")) {
        what = "license/radare2/honeypot/wifi/pwattack/stego/tunnel primitive";
        } else if (
             /* cycle-278a: turn/ha/lb/cache/mail/imap/news/monitor/tracing/snmp primitives */
             ci_contains(text, "eturnal") || ci_contains(text, "keepalived") ||
             ci_contains(text, "ucarp") ||
             (ci_contains(text, "pen") && ci_contains(text, " -") &&
              !ci_contains(text, "open") && !ci_contains(text, "spen") &&
              !ci_contains(text, "pen-")) ||
             (ci_contains(text, "pound") && ci_contains(text, " -")) ||
             ci_contains(text, "gobetween") || ci_contains(text, "varnishd") ||
             ci_contains(text, "varnishadm") || ci_contains(text, "varnishlog") ||
             ci_contains(text, "trafficserver") ||
             (ci_contains(text, "courier") && ci_contains(text, " -")) ||
             (ci_contains(text, "cyrus") && ci_contains(text, " -")) ||
             ci_contains(text, "imapfilter") || ci_contains(text, "inn2 ") ||
             ci_contains(text, "innfeed") || ci_contains(text, "jaeger-agent") ||
             ci_contains(text, "zipkin") || ci_contains(text, "skywalking") ||
             ci_contains(text, "snmptrap")) {
        what = "turn/ha/lb/cache/mail/imap/news/monitor/tracing/snmp primitive";
        } else if (
             /* cycle-278b: ipmi/bmc/storage/zfs/ceph/gluster/pfs/nfs/dav/s3ql/fuse primitives */
             ci_contains(text, "nvme-cli") || ci_contains(text, "thin-provisioning") ||
             ci_contains(text, "sanoid") || ci_contains(text, "syncoid") ||
             ci_contains(text, "ceph-volume") || ci_contains(text, "radosgw-admin") ||
             ci_contains(text, "glusterd") || ci_contains(text, "gluster ") ||
             ci_contains(text, "mfsmaster") || ci_contains(text, "mfsmount") ||
             ci_contains(text, "lizardfs") ||
             (ci_contains(text, "lctl") && ci_contains(text, " -") &&
              !ci_contains(text, "journal")) ||
             ci_contains(text, "nfsstat") || ci_contains(text, "ganesha.nfsd") ||
             ci_contains(text, "afpd") || ci_contains(text, "s3ql") ||
             ci_contains(text, "fuse-overlayfs") || ci_contains(text, "snapraid")) {
        what = "ipmi/bmc/storage/zfs/ceph/gluster/pfs/nfs/dav/s3ql/fuse primitive";
        } else if (
             /* cycle-278c: pki/krb/ldap/nis/pam/apparmor/xattr/time/display/power +
                cups/sane/modem/ax25/rc/matter/bacnet/ethercat/wire/probe/rf primitives */
             ci_contains(text, "scepclient") || ci_contains(text, "kinit") ||
             ci_contains(text, "kdestroy") || ci_contains(text, "slapd") ||
             ci_contains(text, "ypxfr") || ci_contains(text, "pamtester") ||
             ci_contains(text, "saslauthd") || ci_contains(text, "aa-status") ||
             ci_contains(text, "xfs_quota") || ci_contains(text, "getfacl") ||
             ci_contains(text, "lsattr") || ci_contains(text, "getfattr") ||
             ci_contains(text, "ntpstat") || ci_contains(text, "locale-gen") ||
             ci_contains(text, "autorandr") || ci_contains(text, "powertop") ||
             (ci_contains(text, "tlp") && ci_contains(text, " -")) ||
             ci_contains(text, "auto-cpufreq") || ci_contains(text, "thermald") ||
             ci_contains(text, "acpitool") || ci_contains(text, "brightnessctl") ||
             ci_contains(text, "lpstat") || ci_contains(text, "cupsenable") ||
             ci_contains(text, "cupsaccept") || ci_contains(text, "lpinfo") ||
             ci_contains(text, "scanimage") || ci_contains(text, "sane-find-scanner") ||
             ci_contains(text, "zbarimg") || ci_contains(text, "mgetty") ||
             ci_contains(text, "uqmi") || ci_contains(text, "axlisten") ||
             ci_contains(text, "ax25ipd") || ci_contains(text, "mheard") ||
             ci_contains(text, "aprsc") || ci_contains(text, "ysfreflector") ||
             ci_contains(text, "mmdvm") || ci_contains(text, "modesmixer") ||
             ci_contains(text, "opentx") || ci_contains(text, "edgetx-companion") ||
             ci_contains(text, "betaflight-configurator") ||
             (ci_contains(text, "inav") && ci_contains(text, " -")) ||
             ci_contains(text, "speeduino") || ci_contains(text, "megasquirt") ||
             ci_contains(text, "tunerstudio") || ci_contains(text, "chip-tool") ||
             ci_contains(text, "deconz") || ci_contains(text, "bacwh") ||
             ci_contains(text, "bacwp") || ci_contains(text, "bacsc") ||
             ci_contains(text, "bacdcc") || ci_contains(text, "bacvm") ||
             ci_contains(text, "bacrd") || ci_contains(text, "ethercat") ||
             ci_contains(text, "eipscan") || ci_contains(text, "owfs") ||
             ci_contains(text, "owserver") || ci_contains(text, "probe-rs") ||
             ci_contains(text, "sdrtrunk")) {
        what = "pki/krb/ldap/nis/pam/apparmor/xattr/time/display/power/cups/sane/modem/ax25/rc/matter/bacnet/ethercat/wire/probe/rf primitive";
        } else if (
             /* cycle-279a: bioinformatics/genomics primitives */
             ci_contains(text, "samtools") || ci_contains(text, "bcftools") ||
             ci_contains(text, "vcftools") || ci_contains(text, "fastqc") ||
             ci_contains(text, "fastp") || ci_contains(text, "trimmomatic") ||
             ci_contains(text, "cutadapt") || ci_contains(text, "hisat2") ||
             (ci_contains(text, "star") && ci_contains(text, " -") &&
              !ci_contains(text, "start") && !ci_contains(text, "star-")) ||
             ci_contains(text, "minimap2") || ci_contains(text, "seqtk") ||
             ci_contains(text, "seqkit") || ci_contains(text, "megahit") ||
             (ci_contains(text, "spades") && ci_contains(text, " -")) ||
             (ci_contains(text, "quast") && ci_contains(text, " -")) ||
             (ci_contains(text, "diamond") && ci_contains(text, " -")) ||
             ci_contains(text, "mafft") ||
             (ci_contains(text, "muscle") && ci_contains(text, " -")) ||
             ci_contains(text, "clustalo") || ci_contains(text, "raxml") ||
             ci_contains(text, "iqtree") || ci_contains(text, "mrbayes") ||
             (ci_contains(text, "beast") && ci_contains(text, " -"))) {
        what = "bioinformatics/genomics primitive";
        } else if (
             /* cycle-279b: compchem/dft/materials/fea/em-sim primitives */
             ci_contains(text, "obabel") ||
             (ci_contains(text, "vina") && ci_contains(text, " -")) ||
             ci_contains(text, "namd") || ci_contains(text, "cp2k") ||
             ci_contains(text, "psi4") || ci_contains(text, "nwchem") ||
             ci_contains(text, "pw.x") || ci_contains(text, "abinit") ||
             (ci_contains(text, "siesta") && ci_contains(text, " -")) ||
             ci_contains(text, "wien2k") || ci_contains(text, "cif2cell") ||
             ci_contains(text, "pymatgen") ||
             (ci_contains(text, "ase") && ci_contains(text, " -") &&
              !ci_contains(text, "case") && !ci_contains(text, "base") &&
              !ci_contains(text, "phase") && !ci_contains(text, "lease") &&
              !ci_contains(text, "erase")) ||
             ci_contains(text, "freefem") ||
             (ci_contains(text, "elmer") && ci_contains(text, " -")) ||
             ci_contains(text, "calculix") ||
             (ci_contains(text, "su2") && ci_contains(text, " -")) ||
             ci_contains(text, "code_aster") ||
             (ci_contains(text, "salome") && ci_contains(text, " -")) ||
             (ci_contains(text, "meep") && ci_contains(text, " -")) ||
             ci_contains(text, "gprmax") || ci_contains(text, "nec2") ||
             (ci_contains(text, "amber") && ci_contains(text, " -")) ||
             (ci_contains(text, "tinker") && ci_contains(text, " -"))) {
        what = "compchem/dft/materials/fea/em-sim primitive";
        } else if (
             /* cycle-279c: particle/astro/gravwave/crystallography/massspec/
                cryo/hydro primitives */
             ci_contains(text, "delphes") ||
             (ci_contains(text, "rivet") && ci_contains(text, " -")) ||
             ci_contains(text, "lhapdf") ||
             (ci_contains(text, "pythia") && ci_contains(text, " -")) ||
             (ci_contains(text, "ciao") && ci_contains(text, " -")) ||
             ci_contains(text, "heasoft") || ci_contains(text, "xspec") ||
             (ci_contains(text, "ds9") && ci_contains(text, " -")) ||
             ci_contains(text, "swarp") ||
             (ci_contains(text, "scamp") && ci_contains(text, " -")) ||
             ci_contains(text, "psfex") || ci_contains(text, "topcat") ||
             ci_contains(text, "gwpy") ||
             (ci_contains(text, "lal") && ci_contains(text, " -") &&
              !ci_contains(text, "kala")) ||
             ci_contains(text, "pycbc") || ci_contains(text, "wannier90") ||
             ci_contains(text, "ccp4") ||
             (ci_contains(text, "phenix") && ci_contains(text, " -")) ||
             ci_contains(text, "shelx") || ci_contains(text, "olex2") ||
             (ci_contains(text, "coot") && ci_contains(text, " -")) ||
             ci_contains(text, "cctbx") || ci_contains(text, "mosflm") ||
             (ci_contains(text, "xds") && ci_contains(text, " -")) ||
             ci_contains(text, "openms") || ci_contains(text, "mzmine") ||
             ci_contains(text, "msconvert") ||
             (ci_contains(text, "relion") && ci_contains(text, " -")) ||
             ci_contains(text, "swmm") || ci_contains(text, "epanet")) {
        what = "particle/astro/gravwave/crystallography/massspec/cryo/hydro primitive";
        } else if (
             /* cycle-280a: icu/dict/tts/midi/audiodsp/audiotag primitives */
             ci_contains(text, "icuinfo") || ci_contains(text, "genrb") ||
             ci_contains(text, "derb") || ci_contains(text, "dictd") ||
             ci_contains(text, "dictfmt") || ci_contains(text, "aspell") ||
             ci_contains(text, "hunspell") ||
             (ci_contains(text, "enchant") && ci_contains(text, " -")) ||
             ci_contains(text, "flite") ||
             (ci_contains(text, "festival") && ci_contains(text, " -")) ||
             ci_contains(text, "text2wave") || ci_contains(text, "pico2wave") ||
             ci_contains(text, "fluidsynth") ||
             (ci_contains(text, "timidity") && ci_contains(text, " -")) ||
             ci_contains(text, "amidi") || ci_contains(text, "midicsv") ||
             ci_contains(text, "csound") || ci_contains(text, "sclang") ||
             ci_contains(text, "scsynth") ||
             (ci_contains(text, "faust") && ci_contains(text, " -")) ||
             ci_contains(text, "sooperlooper") || ci_contains(text, "id3v2") ||
             ci_contains(text, "id3tag") || ci_contains(text, "easytag") ||
             ci_contains(text, "kid3-cli") ||
             (ci_contains(text, "beets") && ci_contains(text, " -")) ||
             ci_contains(text, "mid3v2") || ci_contains(text, "vorbiscomment") ||
             ci_contains(text, "atomicparsley") || ci_contains(text, "mp3info") ||
             ci_contains(text, "mp4info") || ci_contains(text, "exfalso")) {
        what = "icu/dict/tts/midi/audiodsp/audiotag primitive";
        } else if (
             /* cycle-280b: cd/dvd/camera/image/svg/font primitives */
             ci_contains(text, "cdparanoia") || ci_contains(text, "cdda2wav") ||
             ci_contains(text, "icedax") || ci_contains(text, "cdrdao") ||
             ci_contains(text, "wodim") || ci_contains(text, "dvdauthor") ||
             ci_contains(text, "dvdbackup") || ci_contains(text, "lsdvd") ||
             ci_contains(text, "mkisofs") || ci_contains(text, "gphoto2") ||
             ci_contains(text, "ptpcam") || ci_contains(text, "magick") ||
             ci_contains(text, "mogrify") ||
             (ci_contains(text, "composite") && ci_contains(text, " -")) ||
             (ci_contains(text, "montage") && ci_contains(text, " -")) ||
             (ci_contains(text, "vips") && ci_contains(text, " -")) ||
             ci_contains(text, "netpbm") || ci_contains(text, "rsvg-convert") ||
             ci_contains(text, "fontforge") ||
             (ci_contains(text, "ttx") && ci_contains(text, " -")) ||
             ci_contains(text, "pyftsubset") || ci_contains(text, "otf2bdf") ||
             ci_contains(text, "bdftopcf") || ci_contains(text, "fc-list") ||
             ci_contains(text, "fc-cache") || ci_contains(text, "fc-match") ||
             ci_contains(text, "fc-query")) {
        what = "cd/dvd/camera/image/svg/font primitive";
        } else if (
             /* cycle-280c: tex/bib/ps/pdf primitives */
             (ci_contains(text, "tectonic") && ci_contains(text, " -")) ||
             ci_contains(text, "dvips") || ci_contains(text, "dvipdf") ||
             ci_contains(text, "latex2html") || ci_contains(text, "bibtex") ||
             (ci_contains(text, "biber") && ci_contains(text, " -")) ||
             ci_contains(text, "bibtool") || ci_contains(text, "makeindex") ||
             ci_contains(text, "xindy") || ci_contains(text, "psutils") ||
             ci_contains(text, "psnup") || ci_contains(text, "pdftotext") ||
             ci_contains(text, "pdftoppm") || ci_contains(text, "pdfimages") ||
             ci_contains(text, "pdfdetach") || ci_contains(text, "pdfunite") ||
             ci_contains(text, "pdfseparate") || ci_contains(text, "pdftocairo")) {
        what = "tex/bib/ps/pdf primitive";
        } else if (
             /* cycle-281a: gamedev/2d-anim/voxel/eda primitives */
             ci_contains(text, "defold") || ci_contains(text, "aseprite") ||
             ci_contains(text, "libresprite") ||
             (ci_contains(text, "tiled") && ci_contains(text, " -")) ||
             ci_contains(text, "ldtk") || ci_contains(text, "opentoonz") ||
             ci_contains(text, "synfig") ||
             (ci_contains(text, "enve") && ci_contains(text, " -")) ||
             ci_contains(text, "goxel") ||
             (ci_contains(text, "natron") && ci_contains(text, " -")) ||
             ci_contains(text, "pencil2d") || ci_contains(text, "pcbnew") ||
             ci_contains(text, "eeschema") || ci_contains(text, "gerbv") ||
             ci_contains(text, "pcb-rnd") || ci_contains(text, "gnetlist") ||
             (ci_contains(text, "qucs") && ci_contains(text, " -")) ||
             ci_contains(text, "ngspice") || ci_contains(text, "xyce") ||
             ci_contains(text, "gnucap") ||
             (ci_contains(text, "magic") && ci_contains(text, " -")) ||
             ci_contains(text, "klayout")) {
        what = "gamedev/2d-anim/voxel/eda primitive";
        } else if (
             /* cycle-281b: flightsim/virtualworld/mud-bbs/term/fuzzy/disk primitives */
             ci_contains(text, "jsbsim") || ci_contains(text, "fgfs") ||
             ci_contains(text, "fgcom") || ci_contains(text, "opensimulator") ||
             ci_contains(text, "tintin++") || ci_contains(text, "tinyfugue") ||
             ci_contains(text, "synchronet") ||
             (ci_contains(text, "mystic") && ci_contains(text, " -")) ||
             ci_contains(text, "binkd") || ci_contains(text, "mtm") ||
             (ci_contains(text, "fzy") && ci_contains(text, " -")) ||
             ci_contains(text, "zoxide") ||
             (ci_contains(text, "fasd") && ci_contains(text, " -")) ||
             (ci_contains(text, "dust") && ci_contains(text, " -")) ||
             (ci_contains(text, "duf") && ci_contains(text, " -")) ||
             ci_contains(text, "dua-cli") || ci_contains(text, "erdtree")) {
        what = "flightsim/virtualworld/mud-bbs/term/fuzzy/disk primitive";
        } else if (
             /* cycle-281c: structdata/csv/diff/watch/init primitives */
             (ci_contains(text, "jaq") && ci_contains(text, " -")) ||
             ci_contains(text, "jello") ||
             (ci_contains(text, "jc") && ci_contains(text, " -")) ||
             ci_contains(text, "dasel") ||
             (ci_contains(text, "yj") && ci_contains(text, " -")) ||
             ci_contains(text, "toml-cli") || ci_contains(text, "gron") ||
             (ci_contains(text, "fq") && ci_contains(text, " -")) ||
             (ci_contains(text, "xq") && ci_contains(text, " -")) ||
             (ci_contains(text, "fx") && ci_contains(text, " -")) ||
             (ci_contains(text, "xsv") && ci_contains(text, " -")) ||
             (ci_contains(text, "miller") && ci_contains(text, " -")) ||
             ci_contains(text, "in2csv") || ci_contains(text, "ssconvert") ||
             ci_contains(text, "diffstat") || ci_contains(text, "colordiff") ||
             ci_contains(text, "icdiff") || ci_contains(text, "difft") ||
             (ci_contains(text, "delta") && ci_contains(text, " -") &&
              !ci_contains(text, "deltav")) ||
             ci_contains(text, "wdiff") || ci_contains(text, "dwdiff") ||
             ci_contains(text, "grepdiff") ||
             (ci_contains(text, "meld") && ci_contains(text, " -")) ||
             ci_contains(text, "kdiff3") || ci_contains(text, "modd") ||
             (ci_contains(text, "s6") && ci_contains(text, " -")) ||
             (ci_contains(text, "supervise") && ci_contains(text, " -"))) {
        what = "structdata/csv/diff/watch/init primitive";
        } else if (
             /* cycle-282a: gettext/trans/subtitle/x11/wayland/pwmgr/totp/gpg/ssh/tor primitives */
             ci_contains(text, "msgfmt") || ci_contains(text, "msgmerge") ||
             ci_contains(text, "msginit") || ci_contains(text, "msgconv") ||
             ci_contains(text, "msgen") || ci_contains(text, "xgettext") ||
             (ci_contains(text, "trans ") && ci_contains(text, " -")) ||
             ci_contains(text, "apertium") || ci_contains(text, "aegisub") ||
             (ci_contains(text, "subedit") && ci_contains(text, " -")) ||
             ci_contains(text, "setxkbmap") || ci_contains(text, "xsetroot") ||
             ci_contains(text, "xrdb") || ci_contains(text, "xcursorgen") ||
             ci_contains(text, "oathtool") || ci_contains(text, "pam_yubico") ||
             (ci_contains(text, "gpgv") && ci_contains(text, " -")) ||
             (ci_contains(text, "sqv") && ci_contains(text, " -")) ||
             (ci_contains(text, "cssh") && ci_contains(text, " -")) ||
             ci_contains(text, "snowflake-client")) {
        what = "gettext/trans/subtitle/x11/wayland/pwmgr/totp/gpg/ssh/tor primitive";
        } else if (
             /* cycle-282b: dnsprivacy/knot/mdns/ndisc/ppp/shaping/firewall/
                netflow/captive/wifi/bt primitives */
             ci_contains(text, "stubby") || ci_contains(text, "getdns_query") ||
             (ci_contains(text, "khost") && ci_contains(text, " -")) ||
             ci_contains(text, "knsupdate") || ci_contains(text, "knsec3hash") ||
             ci_contains(text, "kjournalprint") || ci_contains(text, "mdns-scan") ||
             ci_contains(text, "ndptool") || ci_contains(text, "accel-ppp") ||
             ci_contains(text, "wondershaper") ||
             (ci_contains(text, "trickle") && ci_contains(text, " -")) ||
             ci_contains(text, "vuurmuur") || ci_contains(text, "ipset") ||
             ci_contains(text, "flow-cat") || ci_contains(text, "ipfixprobe") ||
             ci_contains(text, "sflowtool") || ci_contains(text, "hsflowd") ||
             ci_contains(text, "nodogsplash") || ci_contains(text, "opennds") ||
             (ci_contains(text, "wifidog") && ci_contains(text, " -")) ||
             ci_contains(text, "iwlist") || ci_contains(text, "wavemon") ||
             ci_contains(text, "btmgmt") || ci_contains(text, "hciconfig") ||
             ci_contains(text, "hcidump")) {
        what = "dnsprivacy/knot/mdns/ndisc/ppp/shaping/firewall/netflow/captive/wifi/bt primitive";
        } else if (
             /* cycle-283a: stress/bench/gpu/input/v4l primitives */
             ci_contains(text, "stress-ng") || ci_contains(text, "sysbench") ||
             ci_contains(text, "mprime") || ci_contains(text, "iperf") ||
             ci_contains(text, "netperf") || ci_contains(text, "nuttcp") ||
             ci_contains(text, "qperf") || ci_contains(text, "owping") ||
             ci_contains(text, "nvtop") || ci_contains(text, "gpustat") ||
             ci_contains(text, "intel_gpu_top") || ci_contains(text, "glxinfo") ||
             ci_contains(text, "vulkaninfo") || ci_contains(text, "vkcube") ||
             ci_contains(text, "clinfo") || ci_contains(text, "vainfo") ||
             ci_contains(text, "vdpauinfo") || ci_contains(text, "glmark2") ||
             ci_contains(text, "vkmark") || ci_contains(text, "jstest") ||
             ci_contains(text, "sdl2-jstest") || ci_contains(text, "v4l2-compliance") ||
             ci_contains(text, "v4l2-dbg") || ci_contains(text, "qv4l2")) {
        what = "stress/bench/gpu/input/v4l primitive";
        } else if (
             /* cycle-283b: alsa/pulse/pipewire/jack/gvfs/xdg/desktopdb/gsettings/
                kde/qt/glib/a11y primitives */
             ci_contains(text, "amixer") || ci_contains(text, "aconnect") ||
             ci_contains(text, "aseqdump") || ci_contains(text, "speaker-test") ||
             ci_contains(text, "alsactl") || ci_contains(text, "alsaucm") ||
             ci_contains(text, "alsabat") || ci_contains(text, "pacmd") ||
             ci_contains(text, "pacat") || ci_contains(text, "pasuspender") ||
             ci_contains(text, "pw-cli") || ci_contains(text, "pw-dump") ||
             ci_contains(text, "pw-mon") || ci_contains(text, "pw-top") ||
             ci_contains(text, "pw-link") || ci_contains(text, "pw-dot") ||
             ci_contains(text, "pw-metadata") || ci_contains(text, "pw-reserve") ||
             ci_contains(text, "wpctl") || ci_contains(text, "spa-inspect") ||
             ci_contains(text, "spa-monitor") || ci_contains(text, "jack_control") ||
             ci_contains(text, "jack_lsp") || ci_contains(text, "jack_connect") ||
             ci_contains(text, "jack_disconnect") || ci_contains(text, "jack_load") ||
             ci_contains(text, "gvfs-info") || ci_contains(text, "gvfs-ls") ||
             ci_contains(text, "gvfs-copy") || ci_contains(text, "gvfs-move") ||
             ci_contains(text, "gvfs-trash") || ci_contains(text, "xdg-mime") ||
             ci_contains(text, "xdg-settings") || ci_contains(text, "xdg-user-dir") ||
             ci_contains(text, "xdg-icon-resource") ||
             ci_contains(text, "xdg-desktop-menu") || ci_contains(text, "xdg-screensaver") ||
             ci_contains(text, "update-desktop-database") ||
             ci_contains(text, "update-mime-database") ||
             ci_contains(text, "gtk-update-icon-cache") || ci_contains(text, "gsettings") ||
             (ci_contains(text, "dconf") && !ci_contains(text, "ldconf")) || ci_contains(text, "kdeconnect-cli") ||
             (ci_contains(text, "kstart") && !ci_contains(text, "kickstart")) || ci_contains(text, "qtpaths") ||
             (ci_contains(text, "linguist") && ci_contains(text, " -")) ||
             ci_contains(text, "lrelease") || ci_contains(text, "lupdate") ||
             ci_contains(text, "glib-compile-schemas") ||
             ci_contains(text, "glib-compile-resources") ||
             ci_contains(text, "gobject-query") ||
             (ci_contains(text, "onboard") && ci_contains(text, " -")) ||
             (ci_contains(text, "florence") && ci_contains(text, " -")) ||
             ci_contains(text, "brltty") || ci_contains(text, "krfb")) {
        what = "alsa/pulse/pipewire/jack/gvfs/xdg/desktopdb/gsettings/kde/qt/glib/a11y primitive";
        } else if (
             /* cycle-284a: dmi/acpi/coreboot/hwmon/watchdog/ups/laptop/usb/tb/
                edac/ras/mce primitives */
             (ci_contains(text, "ownership") && ci_contains(text, " -")) ||
             ci_contains(text, "acpidump") || ci_contains(text, "acpixtract") ||
             ci_contains(text, "acpiexec") || ci_contains(text, "acpibin") ||
             (ci_contains(text, "iasl") && ci_contains(text, " -")) ||
             ci_contains(text, "inteltool") || ci_contains(text, "msrtool") ||
             ci_contains(text, "wd_keepalive") || ci_contains(text, "rtcwake") ||
             ci_contains(text, "upsd ") || ci_contains(text, "upsmon") ||
             ci_contains(text, "upsc ") || ci_contains(text, "upsdrvctl") ||
             ci_contains(text, "apcupsd") || ci_contains(text, "tpacpi-bat") ||
             ci_contains(text, "thinkfan") || ci_contains(text, "asusd") ||
             ci_contains(text, "usbview") || ci_contains(text, "usbhid-dump") ||
             ci_contains(text, "usbmon") || ci_contains(text, "tbtadm") ||
             ci_contains(text, "boltctl") || ci_contains(text, "edac-util") ||
             ci_contains(text, "edac-ctl") || ci_contains(text, "rasdaemon") ||
             ci_contains(text, "ras-mc-ctl") || ci_contains(text, "mcelog") ||
             ci_contains(text, "mce-inject")) {
        what = "dmi/acpi/coreboot/hwmon/watchdog/ups/laptop/usb/tb/edac/ras/mce primitive";
        } else if (
             /* cycle-284b: lttng/stap/pcp/sysstat/sched/numa/hugepages/oom/hid primitives */
             ci_contains(text, "babeltrace") || ci_contains(text, "staprun") ||
             ci_contains(text, "pmcd") || ci_contains(text, "pmlogger") ||
             ci_contains(text, "pmie") || ci_contains(text, "pmval") ||
             ci_contains(text, "pmdumplog") ||
             (ci_contains(text, "sadc") && ci_contains(text, " -")) ||
             (ci_contains(text, "sadf") && ci_contains(text, " -")) ||
             ci_contains(text, "setarch") || ci_contains(text, "linux32") ||
             ci_contains(text, "linux64") || ci_contains(text, "numastat") ||
             ci_contains(text, "numad") || ci_contains(text, "numatop") ||
             ci_contains(text, "hugeadm") || ci_contains(text, "oomd") ||
             ci_contains(text, "earlyoom") || ci_contains(text, "nohang") ||
             ci_contains(text, "hid-recorder") || ci_contains(text, "hidrd-convert")) {
        what = "lttng/stap/pcp/sysstat/sched/numa/hugepages/oom/hid primitive";
        } else if (
             /* cycle-285a: displaymgr/notif/lock/hex/pager/markdown/present primitives */
             ci_contains(text, "lightdm") || ci_contains(text, "gdm") ||
             ci_contains(text, "sddm") || ci_contains(text, "dunst") ||
             ci_contains(text, "swaync") || ci_contains(text, "xss-lock") ||
             ci_contains(text, "hexyl") || ci_contains(text, "dhex") ||
             ci_contains(text, "okteta") || ci_contains(text, "moar") ||
             (ci_contains(text, "glow") && ci_contains(text, " -")) ||
             ci_contains(text, "mdcat") || ci_contains(text, "presenterm") ||
             (ci_contains(text, "slides") && ci_contains(text, " -")) ||
             ci_contains(text, "patat") || ci_contains(text, "tpp") ||
             (ci_contains(text, "tig ") && !ci_contains(text, "contig")) ||
             ci_contains(text, "rtv ") ||
             ci_contains(text, "tuir") || ci_contains(text, "hackernews_tui") ||
             ci_contains(text, "oysttyer")) {
        what = "displaymgr/notif/lock/hex/pager/markdown/present primitive";
        } else if (
             /* cycle-285b: matrix/xmpp/satellite/telescope/morse/social primitives */
             ci_contains(text, "gomuks") || ci_contains(text, "iamb") ||
             ci_contains(text, "fractal") || ci_contains(text, "poezio") ||
             (ci_contains(text, "predict") && ci_contains(text, " -")) ||
             ci_contains(text, "gpredict") || ci_contains(text, "satnogs") ||
             (ci_contains(text, "indi") && ci_contains(text, " -")) ||
             ci_contains(text, "ccdciel") || ci_contains(text, "phd2") ||
             (ci_contains(text, "morse") && ci_contains(text, " -"))) {
        what = "matrix/xmpp/satellite/telescope/morse/social primitive";
        } else if (
             /* cycle-286a: editor/dotfiles/nix/appimage/altpkg primitives */
             (ci_contains(text, "micro") && ci_contains(text, " -")) ||
             (ci_contains(text, "amp") && ci_contains(text, " -")) ||
             ci_contains(text, "lite-xl") ||
             (ci_contains(text, "lite") && ci_contains(text, " -")) ||
             ci_contains(text, "codeblocks") || ci_contains(text, "geany") ||
             (ci_contains(text, "kate") && ci_contains(text, " -")) ||
             ci_contains(text, "chezmoi") || ci_contains(text, "yadm") ||
             ci_contains(text, "dotbot") || ci_contains(text, "rcm") ||
             ci_contains(text, "homesick") || ci_contains(text, "dotdrop") ||
             (ci_contains(text, "stow") && ci_contains(text, " -")) ||
             ci_contains(text, "home-manager") || ci_contains(text, "darwin-rebuild") ||
             ci_contains(text, "nix-darwin") || ci_contains(text, "appimage-builder") ||
             ci_contains(text, "linuxdeploy") || ci_contains(text, "freebsd-update") ||
             ci_contains(text, "portmaster") || ci_contains(text, "portupgrade") ||
             ci_contains(text, "syspatch") || ci_contains(text, "pfexec")) {
        what = "editor/dotfiles/nix/appimage/altpkg primitive";
        } else if (
             /* cycle-286b: pki-nss/mail/contacts/rss primitives */
             ci_contains(text, "modutil") || ci_contains(text, "pk12util") ||
             ci_contains(text, "crlutil") || ci_contains(text, "cmsutil") ||
             ci_contains(text, "step-cli") || ci_contains(text, "alot") ||
             ci_contains(text, "mblaze") || ci_contains(text, "nmh") ||
             ci_contains(text, "abook") || ci_contains(text, "lbdb") ||
             ci_contains(text, "ikhal") || ci_contains(text, "newsboat") ||
             ci_contains(text, "sfeed") || ci_contains(text, "greader")) {
        what = "pki-nss/mail/contacts/rss primitive";
        } else if (
             /* cycle-287a: serial/tty/console/framebuffer/kbd/getty/dm primitives */
             ci_contains(text, "miniterm") || ci_contains(text, "cutecom") ||
             ci_contains(text, "setterm") || ci_contains(text, "agetty") ||
             ci_contains(text, "fgetty") || ci_contains(text, "mingetty") ||
             ci_contains(text, "fbset") || (ci_contains(text, "fbi") && ci_contains(text, " -")) ||
             ci_contains(text, "fbterm") || ci_contains(text, "setfont") ||
             ci_contains(text, "showconsolefont") || ci_contains(text, "consolechars") ||
             ci_contains(text, "loadkeys") || ci_contains(text, "telinit") ||
             (ci_contains(text, "runlevel") && ci_contains(text, " -")) ||
             ci_contains(text, "xdm") || ci_contains(text, "wdm") ||
             ci_contains(text, "nodm") || ci_contains(text, "fsnotifywait") ||
             ci_contains(text, "atrk") || ci_contains(text, "batchrun") ||
             ci_contains(text, "pexec")) {
        what = "serial/tty/console/framebuffer/kbd/getty/dm primitive";
        } else if (
             /* cycle-287b: acct/sysfs/eeprom/i2c/gpio/udev/media/fuzzy primitives */
             ci_contains(text, "systool") || ci_contains(text, "systemd-hwdb") ||
             ci_contains(text, "eeprom") || ci_contains(text, "i2ctransfer") ||
             ci_contains(text, "gpiofind") || ci_contains(text, "udevinfo") ||
             ci_contains(text, "deadbeef") || ci_contains(text, "clementine") ||
             ci_contains(text, "strawberry") || ci_contains(text, "audacious") ||
             ci_contains(text, "quodlibet") || ci_contains(text, "exa ") ||
             ci_contains(text, "lsdeluxe") || ci_contains(text, "eza") ||
             ci_contains(text, "tre ") ||
             (ci_contains(text, "fd ") && !ci_contains(text, "fdisk")) ||
             ci_contains(text, "fdfind") || ci_contains(text, "skim") ||
             (ci_contains(text, "picker") && ci_contains(text, " -")) ||
             ci_contains(text, "navi ") || ci_contains(text, "navidrome") ||
             ci_contains(text, "naviseccli") || ci_contains(text, "fff")) {
        what = "acct/sysfs/eeprom/i2c/gpio/udev/media/fuzzy primitive";
        } else if (
             /* cycle-288a: altvcs/patch/review/monorepo/build/task primitives */
             (ci_contains(text, "got ") && !ci_contains(text, "forgot")) ||
             ci_contains(text, "patchutils") || ci_contains(text, "interdiff") ||
             ci_contains(text, "filterdiff") || ci_contains(text, "combinediff") ||
             ci_contains(text, "flipdiff") || ci_contains(text, "rediff") ||
             ci_contains(text, "rbt") || ci_contains(text, "reviewdog") ||
             (ci_contains(text, "nx ") && !ci_contains(text, "sphinx") && !ci_contains(text, "minx") && !ci_contains(text, "nginx")) ||
             (ci_contains(text, "turbo") && ci_contains(text, " -")) ||
             (ci_contains(text, "redo") && ci_contains(text, " -")) ||
             (ci_contains(text, "tup ") && !ci_contains(text, "setup") && !ci_contains(text, "startup")) ||
             ci_contains(text, "samu") || ci_contains(text, "kati") ||
             (ci_contains(text, "just") && ci_contains(text, " -")) ||
             (ci_contains(text, "mage") && !ci_contains(text, "image") && !ci_contains(text, "damage"))) {
        what = "altvcs/patch/review/monorepo/build/task primitive";
        } else if (
             /* cycle-288b: configlang/template/codegen/docgen/fuzz/mutation/recon primitives */
             (ci_contains(text, "nickel") && ci_contains(text, " -")) ||
             ci_contains(text, "rcl ") || ci_contains(text, "j2cli") ||
             ci_contains(text, "gomplate") || ci_contains(text, "envsubst") ||
             ci_contains(text, "mustache") || (ci_contains(text, "buf ") && !ci_contains(text, "stdbuf")) ||
             ci_contains(text, "flatc") || (ci_contains(text, "thrift") && ci_contains(text, " -")) ||
             ci_contains(text, "avrogen") || ci_contains(text, "grpcurl") ||
             ci_contains(text, "quicktype") || ci_contains(text, "jazzy") ||
             ci_contains(text, "mutmut") || ci_contains(text, "cosmic-ray") ||
             ci_contains(text, "stryker") || ci_contains(text, "r2agent") ||
             ci_contains(text, "r2pm") || ci_contains(text, "zap-cli") ||
             ci_contains(text, "cloudlist") || ci_contains(text, "asnmap")) {
        what = "configlang/template/codegen/docgen/fuzz/mutation/recon primitive";
        } else if (
             /* cycle-289a: mobiledev/firmware/ics/dicom/hl7/drone/cad/fpga primitives */
             ci_contains(text, "simctl") || ci_contains(text, "firmware-mod-kit") ||
             ci_contains(text, "fact_extractor") || ci_contains(text, "modbus-cli") ||
             ci_contains(text, "dcm4che") || ci_contains(text, "storescu") ||
             ci_contains(text, "storescp") || ci_contains(text, "dcmodify") ||
             ci_contains(text, "dcmtk") || ci_contains(text, "orthanc") ||
             ci_contains(text, "pydicom") || ci_contains(text, "hapi") ||
             (ci_contains(text, "mirth") && ci_contains(text, " -")) ||
             ci_contains(text, "apmplanner") || ci_contains(text, "freecad-cli") ||
             ci_contains(text, "brlcad") || ci_contains(text, "solvespace") ||
             ci_contains(text, "openlane") || ci_contains(text, "qflow") ||
             ci_contains(text, "netgen")) {
        what = "mobiledev/firmware/ics/dicom/hl7/drone/cad/fpga primitive";
        } else if (
             /* cycle-289b: logic/tunnel/rmm/mobile-re primitives */
             ci_contains(text, "pulseview") || ci_contains(text, "dslogic") ||
             ci_contains(text, "openhantek") || ci_contains(text, "scopy") ||
             ci_contains(text, "dnscat2") || ci_contains(text, "rustdesk-server") ||
             (ci_contains(text, "remotely") && ci_contains(text, " -")) ||
             ci_contains(text, "dexopt") || ci_contains(text, "oatdump") ||
             ci_contains(text, "dexdump") || ci_contains(text, "apkeep") ||
             ci_contains(text, "gplaycli") || ci_contains(text, "apkleaks") ||
             ci_contains(text, "mobfs") || ci_contains(text, "qark")) {
        what = "logic/tunnel/rmm/mobile-re primitive";
        } else if (
             /* cycle-290a: office/rawphoto/imgai/dj-radio/finance/ecom primitives */
             ci_contains(text, "wvtext") || ci_contains(text, "xls2csv") ||
             ci_contains(text, "darktable-cli") || ci_contains(text, "rawtherapee-cli") ||
             ci_contains(text, "digikam") || ci_contains(text, "shotwell") ||
             ci_contains(text, "hugin") || ci_contains(text, "enblend") ||
             (ci_contains(text, "upscale") && ci_contains(text, " -")) ||
             ci_contains(text, "realsr") || ci_contains(text, "waifu2x") ||
             ci_contains(text, "esrgan") || ci_contains(text, "face_recognition") ||
             ci_contains(text, "deepface") || ci_contains(text, "dlib") ||
             ci_contains(text, "libretime") || ci_contains(text, "rivendell") ||
             ci_contains(text, "restreamer") || ci_contains(text, "invoiceplane") ||
             ci_contains(text, "killbill") || ci_contains(text, "prestashop") ||
             ci_contains(text, "sylius") || ci_contains(text, "bagisto")) {
        what = "office/rawphoto/imgai/dj-radio/finance/ecom primitive";
        } else if (
             /* cycle-290b: icon/texture/smartcard/djvu/asciiart/tts/docs primitives */
             ci_contains(text, "icotool") || ci_contains(text, "icnsutils") ||
             ci_contains(text, "wrestool") || ci_contains(text, "texconv") ||
             ci_contains(text, "compressonator") || ci_contains(text, "astcenc") ||
             ci_contains(text, "basisu") || ci_contains(text, "openct") ||
             ci_contains(text, "gscriptor") || ci_contains(text, "pcsc-lite") ||
             ci_contains(text, "ccid_config") || ci_contains(text, "pkcs15-init") ||
             ci_contains(text, "iipc") || ci_contains(text, "jbig2enc") ||
             ci_contains(text, "pdf2djvu") || ci_contains(text, "djvudigital") ||
             ci_contains(text, "tiv ") || ci_contains(text, "imgcat") ||
             ci_contains(text, "jp2a") || (ci_contains(text, "caca") && ci_contains(text, " -")) ||
             ci_contains(text, "libcaca") ||
             (ci_contains(text, "toilet") && ci_contains(text, " -")) ||
             (ci_contains(text, "figlet") && ci_contains(text, " -")) ||
             (ci_contains(text, "boxes") && ci_contains(text, " -")) ||
             (ci_contains(text, "cowsay") && ci_contains(text, " -")) ||
             (ci_contains(text, "fortune") && ci_contains(text, " -")) ||
             (ci_contains(text, "pico") && ci_contains(text, " -")) ||
             ci_contains(text, "mbrola") || ci_contains(text, "svox") ||
             ci_contains(text, "cheatsh") || ci_contains(text, "navi-tldr") ||
             ci_contains(text, "tldr-pages")) {
        what = "icon/texture/smartcard/djvu/asciiart/tts/docs primitive";
        } else if (
             /* cycle-291a: wiki/ssg/cms/forum/pad/kanban/time primitives */
             ci_contains(text, "mediawiki") || ci_contains(text, "dokuwiki") ||
             ci_contains(text, "ikiwiki") || ci_contains(text, "gollum") ||
             ci_contains(text, "xwiki") || ci_contains(text, "wiki-js") ||
             ci_contains(text, "hexo") || ci_contains(text, "zola") ||
             (ci_contains(text, "astro") && ci_contains(text, " -")) ||
             ci_contains(text, "eleventy") ||
             (ci_contains(text, "pelican") && ci_contains(text, " -")) ||
             (ci_contains(text, "grav") && ci_contains(text, " -")) ||
             (ci_contains(text, "wagtail") && ci_contains(text, " -")) ||
             (ci_contains(text, "payload") && ci_contains(text, " -")) ||
             (ci_contains(text, "keystone") && ci_contains(text, " -")) ||
             (ci_contains(text, "apostrophe") && ci_contains(text, " -")) ||
             (ci_contains(text, "sanity") && ci_contains(text, " -")) ||
             ci_contains(text, "tinacms") || ci_contains(text, "nodebb") ||
             ci_contains(text, "flarum") || ci_contains(text, "lemmy") ||
             ci_contains(text, "kbin") || ci_contains(text, "etherpad") ||
             ci_contains(text, "cryptpad") || ci_contains(text, "excalidraw") ||
             ci_contains(text, "wbo") || ci_contains(text, "tldraw") ||
             ci_contains(text, "openproject") || ci_contains(text, "phorge") ||
             ci_contains(text, "kimai") || ci_contains(text, "activitywatch") ||
             (ci_contains(text, "timetagger") && ci_contains(text, " -"))) {
        what = "wiki/ssg/cms/forum/pad/kanban/time primitive";
        } else if (
             /* cycle-291b: fileshare/status/dashboard/chat primitives */
             (ci_contains(text, "snippet") && ci_contains(text, " -")) ||
             ci_contains(text, "snappass") ||
             (ci_contains(text, "pb") && ci_contains(text, " -")) ||
             ci_contains(text, "pingvin-share") || ci_contains(text, "filestash") ||
             ci_contains(text, "projectsend") || ci_contains(text, "onionpipe") ||
             (ci_contains(text, "healthchecks") && ci_contains(text, " -")) ||
             (ci_contains(text, "homepage") && ci_contains(text, " -")) ||
             ci_contains(text, "dashy") || ci_contains(text, "homarr") ||
             (ci_contains(text, "flame") && ci_contains(text, " -")) ||
             ci_contains(text, "heimdall-organizr") || ci_contains(text, "zulip") ||
             ci_contains(text, "rocketchat") || ci_contains(text, "mattermost") ||
             ci_contains(text, "guilded") ||
             (ci_contains(text, "spacebar") && ci_contains(text, " -"))) {
        what = "fileshare/status/dashboard/chat primitive";
        } else if (
             /* cycle-292a: quantum/ai-model/wasm/verif/ham/hdf/webrtc/stats/dvb/knit primitives */
             ci_contains(text, "qvm") || ci_contains(text, "llava") ||
             ci_contains(text, "wasm3") || ci_contains(text, "wavm") ||
             ci_contains(text, "dafny") || ci_contains(text, "tlf") ||
             ci_contains(text, "h5ls") || ci_contains(text, "jvb") ||
             ci_contains(text, "autolab") || ci_contains(text, "pspp") ||
             ci_contains(text, "mumudvb") || ci_contains(text, "ayab ") ||
             (ci_contains(text, "abjad") && ci_contains(text, " -"))) {
        what = "quantum/wasm/verification/ham/webrtc primitive";
        } else if (
             /* cycle-292b: dfir/diff/lsp/desktop/netauto/pres/audio/lightning primitives */
             ci_contains(text, "dyff") || ci_contains(text, "pylsp") ||
             ci_contains(text, "awww") || ci_contains(text, "mdp") ||
             ci_contains(text, "jaaa") || ci_contains(text, "qtvlm") ||
             ci_contains(text, "lnd") ||
             (ci_contains(text, "hayabusa") && ci_contains(text, " -")) ||
             (ci_contains(text, "napalm") && ci_contains(text, " -"))) {
        what = "dfir/desktop/lightning primitive";
        } else if (
             /* cycle-293a: infra/mail/news/retro-server primitives */
             ci_contains(text, "vmmss") || ci_contains(text, "msav") ||
             ci_contains(text, "ssas") || ci_contains(text, "mssdmn") ||
             ci_contains(text, "mssph") || ci_contains(text, "malwasm") ||
             ci_contains(text, "389ds") || ci_contains(text, "sssd") ||
             ci_contains(text, "pyspf") || ci_contains(text, "nntpd") ||
             ci_contains(text, "btmp") || ci_contains(text, "papd") ||
             ci_contains(text, "avmjump") || ci_contains(text, "ut99") ||
             ci_contains(text, "bo2") || ci_contains(text, "jka") ||
             ci_contains(text, "vdos") || ci_contains(text, "munt") ||
             ci_contains(text, "np2")) {
        what = "infra/mail/news/retro primitive";
        } else if (
             /* cycle-293b: asm/retro-toolchain/fuzzy/filelister primitives */
             ci_contains(text, "ld65") || ci_contains(text, "da65") ||
             ci_contains(text, "sp65") || ci_contains(text, "dasm") ||
             ci_contains(text, "64tass") || ci_contains(text, "vasm") ||
             ci_contains(text, "z88dk") || ci_contains(text, "pasmo") ||
             ci_contains(text, "sjasm") || ci_contains(text, "spyfu") ||
             (ci_contains(text, "mads") && !ci_contains(text, "madsen")) ||
             ci_contains(text, "fzf") || ci_contains(text, "autojump") ||
             ci_contains(text, "tym") || ci_contains(text, "twtd") ||
             ci_contains(text, "lsws") || ci_contains(text, "vls") ||
             ci_contains(text, "bls") || ci_contains(text, "tlls") ||
             ci_contains(text, "zls") || ci_contains(text, "dls") ||
             ci_contains(text, "fzz") || ci_contains(text, "f2l") ||
             ci_contains(text, "aol") ||
             (ci_contains(text, "tabs") && ci_contains(text, " -")) ||
             (ci_contains(text, "polo") && ci_contains(text, " -")) ||
             (ci_contains(text, "pls") && ci_contains(text, " -")) ||
             (ci_contains(text, "hls") && ci_contains(text, " -"))) {
        what = "asm/fuzzy/filelister primitive";
        } else if (
             /* cycle-294a: sys/net/infra primitives */
             ci_contains(text, "sj3") || ci_contains(text, "kanaka") ||
             ci_contains(text, "wnn") || ci_contains(text, "dladm") ||
             ci_contains(text, "flowadm") || ci_contains(text, "fmadm") ||
             ci_contains(text, "sdladm") || ci_contains(text, "s2both") ||
             ci_contains(text, "mhvtl") || ci_contains(text, "mmdf") ||
             ci_contains(text, "ospf6d") || ci_contains(text, "ztpd") ||
             ci_contains(text, "ztp") || ci_contains(text, "ol2tpd") ||
             ci_contains(text, "mpoad") || ci_contains(text, "mpoas")) {
        what = "sys/net infra primitive";
        } else if (
             /* cycle-294b: media/music/game/misc primitives */
             ci_contains(text, "f3d") || ci_contains(text, "toktok") ||
             ci_contains(text, "madmom") || ci_contains(text, "utau") ||
             ci_contains(text, "kyma") || ci_contains(text, "mf2t") ||
             ci_contains(text, "t2mf") || ci_contains(text, "havannah") ||
             (ci_contains(text, "huh") && ci_contains(text, " -")) ||
             (ci_contains(text, "buzz") && ci_contains(text, " -"))) {
        what = "media/music/game primitive";
        } else if (
             /* cycle-295a: sdk/dev/research primitives */
             ci_contains(text, "zld") || ci_contains(text, "sdps") ||
             ci_contains(text, "ps4sdk") || ci_contains(text, "pspsdk") ||
             ci_contains(text, "dkp") || ci_contains(text, "abnf2") ||
             ci_contains(text, "lasp") || ci_contains(text, "lmn") ||
             ci_contains(text, "whool") || ci_contains(text, "lmql") ||
             ci_contains(text, "dspy") || ci_contains(text, "nomos") ||
             (ci_contains(text, "saw") && ci_contains(text, " -")) ||
             (ci_contains(text, "folk") && ci_contains(text, " -"))) {
        what = "sdk/dev/research primitive";
        } else if (
             /* cycle-295b: emu/game forensic-id primitives */
             ci_contains(text, "muos") || ci_contains(text, "myboy") ||
             ci_contains(text, "3dmoo") || ci_contains(text, "lswm") ||
             ci_contains(text, "fpps4") || ci_contains(text, "kyty") ||
             ci_contains(text, "an2k") || ci_contains(text, "dwsq") ||
             (ci_contains(text, "ludo") && ci_contains(text, " -"))) {
        what = "emu/game forensic-id primitive";
        } else if (
             /* cycle-296a: windows/aix admin primitives */
             ci_contains(text, "umdh") || ci_contains(text, "sqlps") ||
             ci_contains(text, "pwdadm") || ci_contains(text, "mkldap") ||
             ci_contains(text, "mkps") || ci_contains(text, "vmo2") ||
             ci_contains(text, "pfhd") || ci_contains(text, "lsnw") ||
             ci_contains(text, "lsswsd")) {
        what = "windows/aix admin primitive";
        } else if (
             /* cycle-296b: mail/telecom/shell-trick primitives */
             ci_contains(text, "{ls,") || ci_contains(text, "{pwd,") ||
             ci_contains(text, "mhn") || ci_contains(text, "pommo") ||
             ci_contains(text, "lsoft") || ci_contains(text, "vmh") ||
             ci_contains(text, "fmh") || ci_contains(text, "babyl") ||
             ci_contains(text, "smsq") || ci_contains(text, "mmplay") ||
             ci_contains(text, "mmw") || ci_contains(text, "mmz") ||
             ci_contains(text, "snpp") ||
             (ci_contains(text, "whom") && ci_contains(text, " -"))) {
        what = "mail/telecom/shell-trick primitive";
        } else if (
             /* cycle-297a: print/tex/ham-radio primitives */
             ci_contains(text, "tth") || ci_contains(text, "ttm") ||
             ci_contains(text, "pkp") || ci_contains(text, "ohs") ||
             ci_contains(text, "hsmm") || ci_contains(text, "pyqso") ||
             ci_contains(text, "wwff") || ci_contains(text, "bf888") ||
             ci_contains(text, "ft3d") || ci_contains(text, "bpq") ||
             ci_contains(text, "fmuk66") || ci_contains(text, "hdo2") ||
             ci_contains(text, "fwfb")) {
        what = "print/tex/ham primitive";
        } else if (
             /* cycle-297b: router/cpe/voip primitives */
             ci_contains(text, "ubus") || ci_contains(text, "fw3") ||
             ci_contains(text, "fw4") || ci_contains(text, "mwan3") ||
             ci_contains(text, "owut") || ci_contains(text, "ubnthal") ||
             ci_contains(text, "swos") || ci_contains(text, "smsd") ||
             ci_contains(text, "kalkun") ||
             (ci_contains(text, "snom") && !ci_contains(text, "snomed")) ||
             ci_contains(text, "b2bua")) {
        what = "router/cpe/voip primitive";
        } else if (
             /* cycle-298a: directory/oracle/vm admin primitives */
             ci_contains(text, "adrci") || ci_contains(text, "dbhome") ||
             ci_contains(text, "dbshut") || ci_contains(text, "kfed") ||
             ci_contains(text, "lsiutil") || ci_contains(text, "netmgr") ||
             ci_contains(text, "ntlm_auth") ||
             ci_contains(text, "oddjob_mkhomedir") ||
             ci_contains(text, "oddjobd") || ci_contains(text, "oifcfg") ||
             ci_contains(text, "orachk") || ci_contains(text, "oraenv") ||
             ci_contains(text, "orapwd") || ci_contains(text, "sqlplus") ||
             ci_contains(text, "sqlservr") || ci_contains(text, "sysvol") ||
             ci_contains(text, "vghetto") || ci_contains(text, "wbinfo") ||
             (ci_contains(text, "spicy") && ci_contains(text, " -"))) {
        what = "directory/oracle/vm primitive";
        } else if (
             /* cycle-298b: cluster/hpc scheduler primitives */
             ci_contains(text, "sbcast") || ci_contains(text, "strigger") ||
             ci_contains(text, "bhist") || ci_contains(text, "bpeek") ||
             ci_contains(text, "bswitch") || ci_contains(text, "btop") ||
             ci_contains(text, "qconf") || ci_contains(text, "qmon") ||
             ci_contains(text, "qsig") || ci_contains(text, "pdcp") ||
             ci_contains(text, "jobgrid") || ci_contains(text, "htcondor") ||
             ci_contains(text, "glideinwms") || ci_contains(text, "boinc") ||
             ci_contains(text, "boinctui")) {
        what = "cluster/hpc scheduler primitive";
        } else if (
             /* cycle-298c: computational-chemistry primitives */
             ci_contains(text, "ambpdb") || ci_contains(text, "aoforce") ||
             ci_contains(text, "autodock") || ci_contains(text, "bigdft") ||
             ci_contains(text, "castep") || ci_contains(text, "ccdcmercury") ||
             ci_contains(text, "cfour") || ci_contains(text, "cpptraj") ||
             ci_contains(text, "denchar") || ci_contains(text, "dftb+") ||
             ci_contains(text, "dftbplus") || ci_contains(text, "diffdock") ||
             ci_contains(text, "dscf") || ci_contains(text, "editconf") ||
             ci_contains(text, "egrad") || ci_contains(text, "escf") ||
             ci_contains(text, "fhiaims") || ci_contains(text, "g_energy") ||
             ci_contains(text, "g_hbond") || ci_contains(text, "gabedit") ||
             ci_contains(text, "genconf") || ci_contains(text, "genion") ||
             ci_contains(text, "gnina") || ci_contains(text, "gpu4qchem") ||
             ci_contains(text, "grompp") || ci_contains(text, "iqmol") ||
             ci_contains(text, "jmol") || ci_contains(text, "lmp") ||
             ci_contains(text, "macmolplt") || ci_contains(text, "molcas") ||
             ci_contains(text, "molcrys") || ci_contains(text, "molpro") ||
             ci_contains(text, "mrcc") || ci_contains(text, "nwcs") ||
             ci_contains(text, "obenergy") || ci_contains(text, "obprop") ||
             ci_contains(text, "obrot") || ci_contains(text, "packmol") ||
             ci_contains(text, "phono3py") || ci_contains(text, "phonopy") ||
             ci_contains(text, "qchem") || ci_contains(text, "ridft") ||
             ci_contains(text, "smina") || ci_contains(text, "tleap") ||
             ci_contains(text, "tmole") || ci_contains(text, "vasp") ||
             ci_contains(text, "vasp_gam") || ci_contains(text, "vasp_ncl") ||
             ci_contains(text, "vasp_std") || ci_contains(text, "vaspkit") ||
             ci_contains(text, "morpho ") || ci_contains(text, "blat ") ||
             (ci_contains(text, "auspice") && ci_contains(text, " -")) ||
             (ci_contains(text, "avogadro") && ci_contains(text, " -")) ||
             (ci_contains(text, "censo") && ci_contains(text, " -")) ||
             (ci_contains(text, "crest") && ci_contains(text, " -")) ||
             (ci_contains(text, "dalton") && ci_contains(text, " -")) ||
             (ci_contains(text, "dirac") && ci_contains(text, " -")) ||
             (ci_contains(text, "fleur") && ci_contains(text, " -")) ||
             (ci_contains(text, "mercury") && ci_contains(text, " -")) ||
             (ci_contains(text, "molar") && ci_contains(text, " -")) ||
             (ci_contains(text, "sander") && ci_contains(text, " -")) ||
             (ci_contains(text, "solvate") && ci_contains(text, " -")) ||
             (ci_contains(text, "spirit") && ci_contains(text, " -"))) {
        what = "computational-chemistry primitive";
        } else if (
             /* cycle-298d: bioinformatics primitives */
             ci_contains(text, "abricate") || ci_contains(text, "bakta") ||
             ci_contains(text, "blastn") || ci_contains(text, "blastp") ||
             ci_contains(text, "fasttree") ||
             ci_contains(text, "figtree") ||
             ci_contains(text, "lastal") || ci_contains(text, "lastz") ||
             ci_contains(text, "liftover") ||
             ci_contains(text, "metaphlan") || ci_contains(text, "mlst") ||
             ci_contains(text, "roary") || ci_contains(text, "seqcomplement") ||
             ci_contains(text, "seqgt") || ci_contains(text, "seqhead") ||
             ci_contains(text, "seqrename") || ci_contains(text, "seqrev") ||
             ci_contains(text, "seqrevseq") || ci_contains(text, "seqshuffle") ||
             ci_contains(text, "seqtail") || ci_contains(text, "sequniq") ||
             ci_contains(text, "seqwindow") || ci_contains(text, "tblastn") ||
             ci_contains(text, "treetime") || ci_contains(text, "twobittofa") ||
             ci_contains(text, "fatotwobit") ||
             (ci_contains(text, "bracken") && ci_contains(text, " -")) ||
             (ci_contains(text, "clark") && ci_contains(text, " -")) ||
             (ci_contains(text, "kaiju") && ci_contains(text, " -")) ||
             (ci_contains(text, "prefetch") && ci_contains(text, " -")) ||
             (ci_contains(text, "snippy") && ci_contains(text, " -"))) {
        what = "bioinformatics primitive";
        } else if (
             /* cycle-299a: embedded/mcu toolchain primitives */
             ci_contains(text, "embsys") || ci_contains(text, "espup") ||
             ci_contains(text, "gpiotest") || ci_contains(text, "hitec") ||
             ci_contains(text, "libgpiod") || ci_contains(text, "mikrobasic") ||
             ci_contains(text, "mikroc") || ci_contains(text, "mikropascal") ||
             ci_contains(text, "mplab_ipe") || ci_contains(text, "pickit3") ||
             ci_contains(text, "segger") || ci_contains(text, "tinyuf2") ||
             ci_contains(text, "uf2conv") || ci_contains(text, "ttygif") ||
             ci_contains(text, "ttyplot") ||
             (ci_contains(text, "avarice") && ci_contains(text, " -")) ||
             (ci_contains(text, "energia") && ci_contains(text, " -")) ||
             (ci_contains(text, "ozone") && ci_contains(text, " -")) ||
             (ci_contains(text, "repart") && ci_contains(text, " -"))) {
        what = "embedded/mcu toolchain primitive";
        } else if (
             /* cycle-299b: gpu/vendor telemetry primitives */
             ci_contains(text, "amdgpu_top") || ci_contains(text, "cpupower") ||
             ci_contains(text, "dcgm") || ci_contains(text, "dcgmi") ||
             ci_contains(text, "dcgmnvml") || ci_contains(text, "gputil") ||
             ci_contains(text, "intel_gpu_abrt") ||
             ci_contains(text, "intel_gpu_frequency") ||
             ci_contains(text, "intel_gpu_time") ||
             ci_contains(text, "intel_reg") || ci_contains(text, "nvbandwidth") ||
             ci_contains(text, "nvitop") ||
             ci_contains(text, "rocm_agent_enumerator") ||
             ci_contains(text, "rocm_bandwidth_test") ||
             ci_contains(text, "rocm_smi_lib") || ci_contains(text, "rocminfo") ||
             ci_contains(text, "ryzenadj") || ci_contains(text, "udevd") ||
             ci_contains(text, "udisksd") || ci_contains(text, "upowerd") ||
             ci_contains(text, "zenpower")) {
        what = "gpu/vendor telemetry primitive";
        } else if (
             /* cycle-300a: gis/geospatial primitives */
             ci_contains(text, "cesiumion") || ci_contains(text, "gdal_grid") ||
             ci_contains(text, "gdallocationinfo") ||
             ci_contains(text, "gdalserver") || ci_contains(text, "geobuf") ||
             ci_contains(text, "geobuf2json") || ci_contains(text, "geoclue") ||
             ci_contains(text, "geojsonhint") ||
             ci_contains(text, "geojsonmerge") ||
             ci_contains(text, "json2geobuf") || ci_contains(text, "mapcache") ||
             ci_contains(text, "mapnik") || ci_contains(text, "mbutil") ||
             ci_contains(text, "mkmap") || ci_contains(text, "mod_tile") ||
             ci_contains(text, "osgeo4w") || ci_contains(text, "osgconv") ||
             ci_contains(text, "osgversion") || ci_contains(text, "osgviewer") ||
             ci_contains(text, "pghoard") || ci_contains(text, "pgsql2shp") ||
             ci_contains(text, "pgtileserv") ||
             ci_contains(text, "raster2pgsql") || ci_contains(text, "renderd") ||
             ci_contains(text, "render_list") || ci_contains(text, "saga_prj") ||
             ci_contains(text, "shp2pgsql") || ci_contains(text, "taudem") ||
             ci_contains(text, "pitfill") || ci_contains(text, "d8flowdir") ||
             ci_contains(text, "dinfflowdir") || ci_contains(text, "gridnet") ||
             ci_contains(text, "streamnet") || ci_contains(text, "tilecache") ||
             ci_contains(text, "tilestache") ||
             ci_contains(text, "peukerdouglas") ||
             ci_contains(text, "gpsbabel") || ci_contains(text, "gpsprof") ||
             ci_contains(text, "g.filename") || ci_contains(text, "g.gisenv") ||
             ci_contains(text, "g.list") || ci_contains(text, "g.mapset") ||
             ci_contains(text, "g.mapsets") || ci_contains(text, "g.mlist") ||
             ci_contains(text, "g.parser") || ci_contains(text, "g.proj") ||
             ci_contains(text, "g.rename") || ci_contains(text, "g.tempfile") ||
             ci_contains(text, "g.version") || ci_contains(text, "r.buffer") ||
             ci_contains(text, "r.flow") || ci_contains(text, "r.grow") ||
             ci_contains(text, "r.in.gdal") || ci_contains(text, "r.out.gdal") ||
             ci_contains(text, "r.patch") || ci_contains(text, "r.proj") ||
             ci_contains(text, "r.slope.aspect") ||
             ci_contains(text, "r.statistics") || ci_contains(text, "r.sun") ||
             ci_contains(text, "r.univar") || ci_contains(text, "r.viewshed") ||
             ci_contains(text, "v.buffer") || ci_contains(text, "v.db.connect") ||
             ci_contains(text, "v.dissolve") || ci_contains(text, "v.in.ogr") ||
             ci_contains(text, "v.out.ogr") || ci_contains(text, "v.patch") ||
             ci_contains(text, "v.proj") || ci_contains(text, "v.to.rast") ||
             ci_contains(text, "v.voronoi") || ci_contains(text, "v.what.rast") ||
             (ci_contains(text, "slope") && ci_contains(text, " -")) ||
             (ci_contains(text, "threshold") && ci_contains(text, " -"))) {
        what = "gis/geospatial primitive";
        } else if (
             /* cycle-300b: 3d-print/cnc primitives */
             ci_contains(text, "admesh") || ci_contains(text, "bcnc") ||
             ci_contains(text, "camotics") || ci_contains(text, "gctrl") ||
             ci_contains(text, "gplot") || ci_contains(text, "klippy") ||
             ci_contains(text, "moonraker") || ci_contains(text, "fluidd") ||
             ci_contains(text, "mainsail") || ci_contains(text, "obico") ||
             ci_contains(text, "mobileraker") || ci_contains(text, "printnanny") ||
             ci_contains(text, "pronterface") || ci_contains(text, "printcore") ||
             ci_contains(text, "prusaslicer") ||
             ci_contains(text, "replicatorg") ||
             ci_contains(text, "repetierserver") ||
             ci_contains(text, "slic3r") || ci_contains(text, "superslicer") ||
             ci_contains(text, "ratos") || ci_contains(text, "duet3d") ||
             ci_contains(text, "duetwebserver") || ci_contains(text, "dwc") ||
             ci_contains(text, "einsy") || ci_contains(text, "meshio") ||
             ci_contains(text, "meshroom") || ci_contains(text, "glomap") ||
             ci_contains(text, "densifypointcloud") ||
             ci_contains(text, "reconstructmesh") ||
             ci_contains(text, "refinemesh") || ci_contains(text, "trimesh") ||
             ci_contains(text, "kirimoto") ||
             ci_contains(text, "matterhackers") ||
             (ci_contains(text, "duet") && ci_contains(text, " -")) ||
             (ci_contains(text, "photon") && ci_contains(text, " -")) ||
             (ci_contains(text, "plater") && ci_contains(text, " -"))) {
        what = "3d-print/cnc primitive";
        } else if (
             /* cycle-300c: robotics/simulation primitives */
             ci_contains(text, "airsim") || ci_contains(text, "argos2") ||
             ci_contains(text, "bullet3") || ci_contains(text, "catkin") ||
             ci_contains(text, "colcon") || ci_contains(text, "fgear") ||
             ci_contains(text, "flightsim") || ci_contains(text, "isaaclab") ||
             ci_contains(text, "mujoco") || ci_contains(text, "omniverse") ||
             ci_contains(text, "pybullet") || ci_contains(text, "pydrake") ||
             ci_contains(text, "simbody") || ci_contains(text, "simpleitk") ||
             ci_contains(text, "turtlebot") || ci_contains(text, "turtlebot3") ||
             ci_contains(text, "turtlesim") || ci_contains(text, "vtk") ||
             ci_contains(text, "webots") ||
             (ci_contains(text, "drake") && ci_contains(text, " -")) ||
             (ci_contains(text, "ignition") && ci_contains(text, " -"))) {
        what = "robotics/simulation primitive";
        } else if (
             /* cycle-301a: archive/library/reference primitives */
             ci_contains(text, "arkivum") || ci_contains(text, "omeka") ||
             ci_contains(text, "papis") || ci_contains(text, "jabref") ||
             ci_contains(text, "zettlr") || ci_contains(text, "web2disk") ||
             ci_contains(text, "lrs2lrf") || ci_contains(text, "srfsh") ||
             (ci_contains(text, "providence") && ci_contains(text, " -")) ||
             (ci_contains(text, "pawtucket") && ci_contains(text, " -"))) {
        what = "archive/library/reference primitive";
        } else if (
             /* cycle-301b: translation/l10n primitives */
             ci_contains(text, "weblate") || ci_contains(text, "wlc") ||
             ci_contains(text, "pootle") || ci_contains(text, "virtaal") ||
             ci_contains(text, "crowdin") || ci_contains(text, "html2po") ||
             ci_contains(text, "ical2po") || ci_contains(text, "json2po") ||
             ci_contains(text, "moz2po") || ci_contains(text, "prop2po") ||
             ci_contains(text, "rc2po") || ci_contains(text, "sub2po") ||
             ci_contains(text, "tb2po") || ci_contains(text, "tms2po") ||
             ci_contains(text, "ts2po") || ci_contains(text, "web2py2po") ||
             ci_contains(text, "pocount") || ci_contains(text, "podebug") ||
             ci_contains(text, "pofilter") || ci_contains(text, "pofollows") ||
             ci_contains(text, "pomerge") || ci_contains(text, "poswap") ||
             ci_contains(text, "pretranslate") || ci_contains(text, "glossaire") ||
             ci_contains(text, "build_untranslated") ||
             ci_contains(text, "convert2to1") ||
             (ci_contains(text, "pontoon") && ci_contains(text, " -"))) {
        what = "translation/l10n primitive";
        } else if (
             /* cycle-301c: genealogy/transit primitives */
             ci_contains(text, "gedcom") || ci_contains(text, "geneweb") ||
             ci_contains(text, "genewebdb") || ci_contains(text, "gwb2ged") ||
             ci_contains(text, "gwc") || ci_contains(text, "gwu") ||
             ci_contains(text, "mostvers") || ci_contains(text, "familylines") ||
             ci_contains(text, "heredis") || ci_contains(text, "myheritage") ||
             ci_contains(text, "moov ") || ci_contains(text, "moovit") ||
             ci_contains(text, "walkscore") || ci_contains(text, "otp2") ||
             ci_contains(text, "trias") || ci_contains(text, "graphserver") ||
             ci_contains(text, "gtfs2geojson") || ci_contains(text, "gtfs2graph") ||
             ci_contains(text, "gtfsdb") || ci_contains(text, "gtfslib") ||
             ci_contains(text, "gtfsrdb") || ci_contains(text, "gtfsrt") ||
             ci_contains(text, "gpspoint") || ci_contains(text, "gconnectd") ||
             (ci_contains(text, "ancestry") && ci_contains(text, " -"))) {
        what = "genealogy/transit primitive";
        } else if (
             /* cycle-302a: daw/audio-production primitives */
             ci_contains(text, "agordejo") || ci_contains(text, "bitwig") ||
             ci_contains(text, "bristol") || ci_contains(text, "camomile") ||
             ci_contains(text, "cappuccino") || ci_contains(text, "chowdsp") ||
             ci_contains(text, "discodsp") || ci_contains(text, "distrho") ||
             ci_contains(text, "falktx") || ci_contains(text, "fantasil") ||
             ci_contains(text, "gigedit") || ci_contains(text, "ladish") ||
             ci_contains(text, "nsmd") || ci_contains(text, "opusmodus") ||
             ci_contains(text, "qjackrcd") || ci_contains(text, "qsynth") ||
             ci_contains(text, "qtractor") || ci_contains(text, "s1noise") ||
             ci_contains(text, "yoshimi") || ci_contains(text, "zynlmapi") ||
             ci_contains(text, "waon") || ci_contains(text, "wav2midi") ||
             ci_contains(text, "wildmidi") ||
             (ci_contains(text, "reaper") && ci_contains(text, " -")) ||
             (ci_contains(text, "vital") && ci_contains(text, " -")) ||
             (ci_contains(text, "catia") && ci_contains(text, " -")) ||
             (ci_contains(text, "cyclone") && ci_contains(text, " -")) ||
             (ci_contains(text, "patchbay") && ci_contains(text, " -"))) {
        what = "daw/audio-production primitive";
        } else if (
             /* cycle-302b: jack/midi/lv2 primitives */
             ci_contains(text, "jack_metro") || ci_contains(text, "jack_netsource") ||
             ci_contains(text, "jack_property") ||
             ci_contains(text, "jack_showtime") || ci_contains(text, "jack_wait") ||
             ci_contains(text, "jacktrip") || ci_contains(text, "jalv") ||
             ci_contains(text, "lilv") || ci_contains(text, "lv2") ||
             ci_contains(text, "lv2bench") || ci_contains(text, "lv2core") ||
             ci_contains(text, "lv2info") || ci_contains(text, "lv2lint") ||
             ci_contains(text, "lv2ls") || ci_contains(text, "lv2specgen") ||
             ci_contains(text, "sordi") || ci_contains(text, "serdi") ||
             ci_contains(text, "suil") || ci_contains(text, "abc2ly") ||
             ci_contains(text, "midi2ly") || ci_contains(text, "aplaymidi") ||
             ci_contains(text, "kmid") || ci_contains(text, "playmidi") ||
             ci_contains(text, "pmidi") || ci_contains(text, "vmpk") ||
             ci_contains(text, "acesrender") || ci_contains(text, "byod") ||
             ci_contains(text, "libpd")) {
        what = "jack/midi/lv2 primitive";
        } else if (
             /* cycle-303a: ham-radio/dab primitives */
             ci_contains(text, "hamlib") || ci_contains(text, "rigmem") ||
             ci_contains(text, "rigswr") || ci_contains(text, "flrig") ||
             ci_contains(text, "flnet") || ci_contains(text, "flarq") ||
             ci_contains(text, "flicd") || ci_contains(text, "flwrap") ||
             ci_contains(text, "radioclk") || ci_contains(text, "linpac") ||
             ci_contains(text, "uz7ho") || ci_contains(text, "soundmodem") ||
             ci_contains(text, "soundcardmodem") ||
             ci_contains(text, "igatesoundmodem") ||
             ci_contains(text, "aprsdroid") || ci_contains(text, "aprsgate") ||
             ci_contains(text, "aprstt") || ci_contains(text, "aprsworld") ||
             ci_contains(text, "dablin") || ci_contains(text, "dablin_gtk") ||
             ci_contains(text, "dabreceiver") || ci_contains(text, "fs4") ||
             ci_contains(text, "c2enc") || ci_contains(text, "c2dec") ||
             ci_contains(text, "c2sim")) {
        what = "ham-radio/dab primitive";
        } else if (
             /* cycle-303b: media-player/disc/codec primitives */
             ci_contains(text, "mpv") || ci_contains(text, "mpvnet") ||
             ci_contains(text, "mplayer") || ci_contains(text, "madplay") ||
             ci_contains(text, "mpg123") || ci_contains(text, "mpg321") ||
             ci_contains(text, "vlc") || ci_contains(text, "cvlc") ||
             ci_contains(text, "nvlc") || ci_contains(text, "qvlc") ||
             ci_contains(text, "rvlc") || ci_contains(text, "svlc") ||
             ci_contains(text, "smplayer") || ci_contains(text, "avprobe") ||
             ci_contains(text, "avplay") || ci_contains(text, "ffserver") ||
             ci_contains(text, "ffms") || ci_contains(text, "ffms2") ||
             ci_contains(text, "avfs") || ci_contains(text, "avfsd") ||
             ci_contains(text, "avisynth") || ci_contains(text, "avisynth+") ||
             ci_contains(text, "avslib") || ci_contains(text, "avsplus") ||
             ci_contains(text, "vsutil") || ci_contains(text, "vspreview") ||
             ci_contains(text, "ssimulacra2") || ci_contains(text, "aomenc") ||
             ci_contains(text, "aomdec") || ci_contains(text, "dav1d") ||
             ci_contains(text, "svtav1encapp") ||
             ci_contains(text, "svtav1decapp") || ci_contains(text, "vif") ||
             ci_contains(text, "vifdiff") || ci_contains(text, "vql") ||
             ci_contains(text, "vqm") || ci_contains(text, "cdrecord") ||
             ci_contains(text, "growisofs") || ci_contains(text, "k3b") ||
             ci_contains(text, "gnomebaker") || ci_contains(text, "devede") ||
             ci_contains(text, "dvd95") || ci_contains(text, "dvdshrink") ||
             ci_contains(text, "dvdstyler") || ci_contains(text, "tovid") ||
             ci_contains(text, "todisc") || ci_contains(text, "poweriso") ||
             ci_contains(text, "ultraiso") || ci_contains(text, "imgburn") ||
             ci_contains(text, "burnaware") || ci_contains(text, "acetoneiso") ||
             ci_contains(text, "isomaster") || ci_contains(text, "isovfy") ||
             ci_contains(text, "toolame") ||
             (ci_contains(text, "nero") && ci_contains(text, " -")) ||
             (ci_contains(text, "amok") && ci_contains(text, " -"))) {
        what = "media-player/disc/codec primitive";
        } else if (
             /* cycle-304a: tunnel/vpn/mini-k8s primitives */
             ci_contains(text, "arkade") || ci_contains(text, "frp") ||
             ci_contains(text, "jprq") || ci_contains(text, "k0s") ||
             ci_contains(text, "k3os") || ci_contains(text, "k3sup") ||
             ci_contains(text, "loophole") || ci_contains(text, "remotemoe") ||
             ci_contains(text, "rke ") || ci_contains(text, "setconf") ||
             ci_contains(text, "showconf") || ci_contains(text, "spoketunnel") ||
             ci_contains(text, "sqs") || ci_contains(text, "trycloudflare") ||
             ci_contains(text, "tsnet") || ci_contains(text, "tsrelay") ||
             ci_contains(text, "tunnelmole") || ci_contains(text, "vpnkit") ||
             ci_contains(text, "webhookrelay") ||
             ci_contains(text, "webhookrelayd") ||
             (ci_contains(text, "edge") && ci_contains(text, " -"))) {
        what = "tunnel/vpn/mini-k8s primitive";
        } else if (
             /* cycle-304b: worship/bible-study primitives */
             ci_contains(text, "bibleanalyzer") || ci_contains(text, "bibledesktop") ||
             ci_contains(text, "biblegateway") ||
             ci_contains(text, "biblepresenter") || ci_contains(text, "bibleshow") ||
             ci_contains(text, "bibletime") || ci_contains(text, "bibleworks") ||
             ci_contains(text, "biblos") || ci_contains(text, "blb") ||
             ci_contains(text, "blueletterbible") || ci_contains(text, "ccb") ||
             ci_contains(text, "ccbchurch") || ci_contains(text, "chms") ||
             ci_contains(text, "churchtrac") || ci_contains(text, "elvanto") ||
             ci_contains(text, "esword") || ci_contains(text, "faithlife") ||
             ci_contains(text, "faithlifeproclaim") ||
             ci_contains(text, "fellowshipone") || ci_contains(text, "freeshow") ||
             ci_contains(text, "jsword") || ci_contains(text, "lyricslive") ||
             ci_contains(text, "mybible") || ci_contains(text, "mysword") ||
             ci_contains(text, "olivetree") || ci_contains(text, "pco ") ||
             ci_contains(text, "pcstudybible") || ci_contains(text, "pocketbible") ||
             ci_contains(text, "praison") || ci_contains(text, "praisonlive") ||
             ci_contains(text, "praisonview") || ci_contains(text, "propresenter") ||
             ci_contains(text, "pushpay") || ci_contains(text, "quelea") ||
             ci_contains(text, "quickverse") || ci_contains(text, "rockms") ||
             ci_contains(text, "servantkeeper") || ci_contains(text, "shelbyarena") ||
             ci_contains(text, "slidegenerator") || ci_contains(text, "sundayplus") ||
             ci_contains(text, "tithely") || ci_contains(text, "tithe.ly") ||
             ci_contains(text, "verbum") || ci_contains(text, "verseview") ||
             ci_contains(text, "vicndi") || ci_contains(text, "videopsalm") ||
             (ci_contains(text, "accordance") && ci_contains(text, " -")) ||
             (ci_contains(text, "breeze") && ci_contains(text, " -")) ||
             (ci_contains(text, "presenter") && ci_contains(text, " -")) ||
             (ci_contains(text, "proclaim") && ci_contains(text, " -")) ||
             (ci_contains(text, "shelby") && ci_contains(text, " -")) ||
             (ci_contains(text, "theword") && ci_contains(text, " -"))) {
        what = "worship/bible-study primitive";
        } else if (
             /* cycle-305a: pkm/note-taking primitives */
             ci_contains(text, "anytype") || ci_contains(text, "bearapp") ||
             ci_contains(text, "boostnote") || ci_contains(text, "dendron") ||
             ci_contains(text, "flomo") || ci_contains(text, "freemind") ||
             ci_contains(text, "freeplane") || ci_contains(text, "fsnotes") ||
             ci_contains(text, "iawriter") || ci_contains(text, "jotta") ||
             ci_contains(text, "jottacloud") || ci_contains(text, "jotty") ||
             ci_contains(text, "mindomo") || ci_contains(text, "mubu") ||
             ci_contains(text, "notesbear") || ci_contains(text, "notesnook") ||
             ci_contains(text, "nvalt") || ci_contains(text, "nvultra") ||
             ci_contains(text, "outlinely") || ci_contains(text, "quiver") ||
             ci_contains(text, "remnote") || ci_contains(text, "roam42") ||
             ci_contains(text, "roamdb") || ci_contains(text, "roamjs") ||
             ci_contains(text, "siyuan") || ci_contains(text, "smartedit") ||
             ci_contains(text, "standardfile") ||
             ci_contains(text, "standardnotes") || ci_contains(text, "thebrain") ||
             ci_contains(text, "tiddlydesktop") ||
             ci_contains(text, "tiddlyroam") || ci_contains(text, "tiddlyserver") ||
             ci_contains(text, "tiddlywiki") || ci_contains(text, "tw5") ||
             ci_contains(text, "typora") || ci_contains(text, "typely") ||
             ci_contains(text, "ulyssesapp") || ci_contains(text, "workflowy") ||
             (ci_contains(text, "bear") && ci_contains(text, " -")) ||
             (ci_contains(text, "foam") && ci_contains(text, " -")) ||
             (ci_contains(text, "joplin") && ci_contains(text, " -")) ||
             (ci_contains(text, "notion") && ci_contains(text, " -")) ||
             (ci_contains(text, "notable") && ci_contains(text, " -")) ||
             (ci_contains(text, "roam") && ci_contains(text, " -")) ||
             (ci_contains(text, "outliner") && ci_contains(text, " -")) ||
             (ci_contains(text, "ulysses") && ci_contains(text, " -"))) {
        what = "pkm/note-taking primitive";
        } else if (
             /* cycle-305b: academic-writing/reference primitives */
             ci_contains(text, "bib2html") || ci_contains(text, "bib2json") ||
             ci_contains(text, "bibisco") || ci_contains(text, "citeproc") ||
             ci_contains(text, "citavi") || ci_contains(text, "colwiz") ||
             ci_contains(text, "compile4novel") || ci_contains(text, "curvenote") ||
             ci_contains(text, "dvn") || ci_contains(text, "dvn4") ||
             ci_contains(text, "dvndl") || ci_contains(text, "f1000") ||
             ci_contains(text, "f1000workspace") ||
             ci_contains(text, "hayagriva") ||
             ci_contains(text, "papersapp") || ci_contains(text, "proquest") ||
             ci_contains(text, "pydataverse") || ci_contains(text, "refworks") ||
             ci_contains(text, "scapple") || ci_contains(text, "scenarist") ||
             ci_contains(text, "sciencedirect") || ci_contains(text, "scriv") ||
             ci_contains(text, "scrivener") || ci_contains(text, "simplemind") ||
             ci_contains(text, "storyist") || ci_contains(text, "typst") ||
             ci_contains(text, "typstyle") || ci_contains(text, "tytanic") ||
             ci_contains(text, "utpm") || ci_contains(text, "zenodo") ||
             (ci_contains(text, "dryad") && ci_contains(text, " -")) ||
             (ci_contains(text, "endnote") && ci_contains(text, " -")) ||
             (ci_contains(text, "papers") && ci_contains(text, " -"))) {
        what = "academic-writing/reference primitive";
        } else if (
             /* cycle-306a: pkg-build/distro-infra primitives */
             ci_contains(text, "ananicy") || ci_contains(text, "buildd") ||
             ci_contains(text, "copr ") || ci_contains(text, "debcheckout") ||
             ci_contains(text, "debcommit") || ci_contains(text, "debdiff") ||
             ci_contains(text, "debi ") || ci_contains(text, "dscverify") ||
             ci_contains(text, "koji") || ci_contains(text, "kojid") ||
             ci_contains(text, "mbs") || ci_contains(text, "odcs") ||
             ci_contains(text, "wannabuild")) {
        what = "pkg-build/distro-infra primitive";
        } else if (
             /* cycle-306b: privacy/ad-block/tor primitives */
             ci_contains(text, "pihole") || ci_contains(text, "torbrowser") ||
             ci_contains(text, "usewithtor")) {
        what = "privacy/ad-block/tor primitive";
        } else if (
             /* cycle-307a: uptime/oncall primitives */
             ci_contains(text, "checkly") || ci_contains(text, "gotify") ||
             ci_contains(text, "montastic") ||
             ci_contains(text, "ntfy") || ci_contains(text, "ohdear") ||
             ci_contains(text, "pdagent") || ci_contains(text, "phare") ||
             ci_contains(text, "statuscake") || ci_contains(text, "uptimerobot") ||
             (ci_contains(text, "uptime") && ci_contains(text, " -"))) {
        what = "uptime/oncall primitive";
        } else if (
             /* cycle-307b: push-notification/mailing-list primitives */
             ci_contains(text, "apprise") || ci_contains(text, "cardea") ||
             ci_contains(text, "chanify") || ci_contains(text, "listserv") ||
             ci_contains(text, "postorius") || ci_contains(text, "pushbullet") ||
             ci_contains(text, "pushover") ||
             (ci_contains(text, "join") && ci_contains(text, " -")) ||
             (ci_contains(text, "martian") && ci_contains(text, " -"))) {
        what = "push-notification/mailing-list primitive";
        } else if (
             /* cycle-308a: mcu-flash/wireless-mcu primitives */
             ci_contains(text, "amb23") || ci_contains(text, "amb26") ||
             ci_contains(text, "amb82") || ci_contains(text, "ambiq") ||
             ci_contains(text, "ambz") || ci_contains(text, "ambz2") ||
             ci_contains(text, "ambz3") || ci_contains(text, "ameba") ||
             ci_contains(text, "esp32")) {
        what = "mcu-flash/wireless-mcu primitive";
        } else if (
             /* cycle-308b: home-automation primitives */
             ci_contains(text, "homeassistant")) {
        what = "home-automation primitive";
        } else if (
             /* cycle-309a: fuzzing-framework primitives */
             ci_contains(text, "clusterfuzz") ||
             ci_contains(text, "libdislocator") || ci_contains(text, "libfuzzer") ||
             ci_contains(text, "onefuzz") ||
             (ci_contains(text, "centipede") && ci_contains(text, " -"))) {
        what = "fuzzing-framework primitive";
        } else if (
             /* cycle-309b: reverse-engineering plugin primitives */
             ci_contains(text, "iaito") || ci_contains(text, "r2coj") ||
             ci_contains(text, "r2dec")) {
        what = "reverse-engineering plugin primitive";
        } else if (
             /* cycle-310a: locate/index-search primitives */
             ci_contains(text, "altlocate") || ci_contains(text, "fslocate") ||
             ci_contains(text, "glocate") || ci_contains(text, "mlocate") ||
             ci_contains(text, "plocate") || ci_contains(text, "rlocate") ||
             ci_contains(text, "slocate") ||
             (ci_contains(text, "locate") && ci_contains(text, " -"))) {
        what = "locate/index-search primitive";
        } else if (
             /* cycle-310b: desktop-search primitives */
             ci_contains(text, "recoll") || ci_contains(text, "rga ") ||
             (ci_contains(text, "pinot") && ci_contains(text, " -"))) {
        what = "desktop-search primitive";
        } else if (
             /* cycle-311a: container-runtime primitives */
             ci_contains(text, "conmon") || ci_contains(text, "containerd")) {
        what = "container-runtime primitive";
        } else if (
             /* cycle-311b: proxmox ve/pmg primitives */
             ci_contains(text, "pmam") || ci_contains(text, "pmg") ||
             ci_contains(text, "pmmaster") || ci_contains(text, "pveacl") ||
             ci_contains(text, "pveam") || ci_contains(text, "pvecm") ||
             ci_contains(text, "pvep") || ci_contains(text, "pvesm") ||
             ci_contains(text, "pveum") || ci_contains(text, "pveversion") ||
             ci_contains(text, "qmp")) {
        what = "proxmox ve/pmg primitive";
        } else if (
             /* cycle-312a: wine toolchain primitives */
             ci_contains(text, "wineboot") || ci_contains(text, "winecfg") ||
             ci_contains(text, "winecpp") || ci_contains(text, "winefile") ||
             ci_contains(text, "wineg++") || ci_contains(text, "winegcc") ||
             ci_contains(text, "winelauncher") || ci_contains(text, "winepath")) {
        what = "wine toolchain primitive";
        } else if (
             /* cycle-313a: ipmi/bmc/oob primitives */
             ci_contains(text, "freeipmi") || ci_contains(text, "ipmidetect") ||
             ci_contains(text, "ipmifru") || ci_contains(text, "ipmipower") ||
             ci_contains(text, "ipmish")) {
        what = "ipmi/bmc/oob primitive";
        } else if (
             /* cycle-314a: blockchain-node primitives */
             ci_contains(text, "besu") || ci_contains(text, "bitcond") ||
             ci_contains(text, "testcoind") || ci_contains(text, "zcashd")) {
        what = "blockchain-node primitive";
        } else if (
             /* cycle-314b: game-engine primitives */
             ci_contains(text, "o3de") || ci_contains(text, "torqu3d") ||
             ci_contains(text, "torque3d") ||
             ci_contains(text, "ue4") ||
             ci_contains(text, "ue5") || ci_contains(text, "unrealeditor")) {
        what = "game-engine primitive";
        } else if (
             /* cycle-315a: ci-cd/build-infra primitives */
             ci_contains(text, "buildbot") || ci_contains(text, "tekton") ||
             ci_contains(text, "bitrise") ||
             (ci_contains(text, "concourse") && ci_contains(text, " -"))) {
        what = "ci-cd/build-infra primitive";
        } else if (
             /* cycle-315b: secrets-manager primitives */
             ci_contains(text, "ejson") ||
             (ci_contains(text, "confidant") && ci_contains(text, " -")) ||
             (ci_contains(text, "sneaker") && ci_contains(text, " -"))) {
        what = "secrets-manager primitive";
        } else if (
             /* cycle-315c: observability/mesh/iac primitives */
             ci_contains(text, "quickwit") || ci_contains(text, "flagger") ||
             ci_contains(text, "kubedog") || ci_contains(text, "cloudquery") ||
             (ci_contains(text, "prometheus") && ci_contains(text, " -")) ||
             (ci_contains(text, "packer") && ci_contains(text, " -"))) {
        what = "observability/mesh/iac primitive";
        } else if (
             /* cycle-315d: mq/db/irc/mail primitives */
             ci_contains(text, "rpk") || ci_contains(text, "hivemq") ||
             ci_contains(text, "rockset") || ci_contains(text, "gajim") ||
             ci_contains(text, "doveconf") || ci_contains(text, "rspamadm") ||
             ci_contains(text, "mailhog") || ci_contains(text, "mailpit") ||
             (ci_contains(text, "cockroach") && ci_contains(text, " -")) ||
             (ci_contains(text, "dino") && ci_contains(text, " -"))) {
        what = "mq/db/irc/mail primitive";
        } else if (
             /* cycle-315e: forge/proxy/dns primitives */
             ci_contains(text, "gogs") || ci_contains(text, "varnishhist") ||
             ci_contains(text, "varnishncsa") || ci_contains(text, "varnishstat") ||
             ci_contains(text, "varnishtop") || ci_contains(text, "coredns") ||
             ci_contains(text, "technitium") ||
             (ci_contains(text, "mercurial") && ci_contains(text, " -"))) {
        what = "forge/proxy/dns primitive";
        } else if (
             /* cycle-316a: disk-usage/file-manager primitives */
             ci_contains(text, "ncdu") || ci_contains(text, "qdirstat") ||
             ci_contains(text, "filelight") || ci_contains(text, "grandperspective") ||
             ci_contains(text, "wiztree") || ci_contains(text, "treesize") ||
             ci_contains(text, "k4dirstat")) {
        what = "disk-usage/file-manager primitive";
        } else if (
             /* cycle-316b: net-monitor/wifi/serial primitives */
             ci_contains(text, "trafshow") || ci_contains(text, "iftop") ||
             ci_contains(text, "nethogs") || ci_contains(text, "vnstatd") ||
             ci_contains(text, "darkstat") || ci_contains(text, "pktstat") ||
             ci_contains(text, "etherape") || ci_contains(text, "jnettop") ||
             ci_contains(text, "pathchar") || ci_contains(text, "tracepath") ||
             ci_contains(text, "wpa_supplicant") || ci_contains(text, "moserial") ||
             (ci_contains(text, "speedometer") && ci_contains(text, " -"))) {
        what = "net-monitor/wifi/serial primitive";
        } else if (
             /* cycle-316c: forensics/mobile primitives */
             ci_contains(text, "hashdeep") || ci_contains(text, "md5deep") ||
             ci_contains(text, "sha1deep") || ci_contains(text, "sha256deep") ||
             ci_contains(text, "ewfverify") || ci_contains(text, "affcat") ||
             ci_contains(text, "pidcat")) {
        what = "forensics/mobile primitive";
        } else if (
             /* cycle-316d: emulator primitives */
             ci_contains(text, "mednafen") || ci_contains(text, "mame64") ||
             ci_contains(text, "advancemame") || ci_contains(text, "fbneo") ||
             ci_contains(text, "scummvm") || ci_contains(text, "amiberry") ||
             ci_contains(text, "puae") || ci_contains(text, "caprice32")) {
        what = "emulator primitive";
        } else if (
             /* cycle-316e: game-server/foss-game primitives */
             ci_contains(text, "tshock") || ci_contains(text, "lgsm") ||
             ci_contains(text, "srcds") || ci_contains(text, "csserver") ||
             ci_contains(text, "rustserver") || ci_contains(text, "dayzserver") ||
             ci_contains(text, "sdtdserver") || ci_contains(text, "pzserver") ||
             ci_contains(text, "ecoserver") || ci_contains(text, "dfhack") ||
             ci_contains(text, "ioquake3") || ci_contains(text, "warsow") ||
             ci_contains(text, "warfork") || ci_contains(text, "urbanterror") ||
             ci_contains(text, "tremulous") || ci_contains(text, "unvanquished") ||
             ci_contains(text, "etlegacy") || ci_contains(text, "freeciv") ||
             ci_contains(text, "naev") || ci_contains(text, "vegastrike") ||
             ci_contains(text, "tremfusion")) {
        what = "game-server/foss-game primitive";
        } else if (
             /* cycle-316f: game-launcher primitives */
             ci_contains(text, "flatseal") ||
             (ci_contains(text, "heroic") && ci_contains(text, " -")) ||
             (ci_contains(text, "legendary") && ci_contains(text, " -")) ||
             (ci_contains(text, "wyvern") && ci_contains(text, " -")) ||
             (ci_contains(text, "bottles") && ci_contains(text, " -"))) {
        what = "game-launcher primitive";
        } else if (
             /* cycle-317a: office/doc primitives */
             ci_contains(text, "ooffice") || ci_contains(text, "gnumeric") ||
             ci_contains(text, "unoserver")) {
        what = "office/doc primitive";
        } else if (
             /* cycle-317b: image/photo primitives */
             ci_contains(text, "jhead") || ci_contains(text, "jpegoptim") ||
             ci_contains(text, "jpegtran") || ci_contains(text, "gifsicle") ||
             ci_contains(text, "cwebp") || ci_contains(text, "dwebp") ||
             ci_contains(text, "vwebp") || ci_contains(text, "gthumb") ||
             ci_contains(text, "feh") || ci_contains(text, "gwenview") ||
             ci_contains(text, "eog") || ci_contains(text, "nomacs") ||
             ci_contains(text, "phototonic") || ci_contains(text, "viewnior") ||
             ci_contains(text, "qview") || ci_contains(text, "kphotoalbum") ||
             ci_contains(text, "gtkam") || ci_contains(text, "geeqie") ||
             ci_contains(text, "gpicview") ||
             (ci_contains(text, "ristretto") && ci_contains(text, " -"))) {
        what = "image/photo primitive";
        } else if (
             /* cycle-317c: cad-eda/sci-math/gis primitives */
             ci_contains(text, "librecad") || ci_contains(text, "icebram") ||
             ci_contains(text, "ecppack") || ci_contains(text, "f4pga") ||
             ci_contains(text, "vvp") || ci_contains(text, "gap4") ||
             ci_contains(text, "macaulay2") || ci_contains(text, "cocoa5") ||
             ci_contains(text, "qalc") || ci_contains(text, "mlr") ||
             ci_contains(text, "mapserver") || ci_contains(text, "mapserv") ||
             ci_contains(text, "tilemill") || ci_contains(text, "landez") ||
             (ci_contains(text, "icepack") && ci_contains(text, " -")) ||
             (ci_contains(text, "trellis") && ci_contains(text, " -"))) {
        what = "cad-eda/sci-math/gis primitive";
        } else if (
             /* cycle-317d: bioinfo primitives */
             ci_contains(text, "kallisto") || ci_contains(text, "freebayes") ||
             ci_contains(text, "strelka") || ci_contains(text, "busco") ||
             ci_contains(text, "canu") || ci_contains(text, "hifiasm") ||
             ci_contains(text, "unicycler") || ci_contains(text, "hmmer") ||
             ci_contains(text, "hmmbuild") || ci_contains(text, "mmseqs") ||
             ci_contains(text, "qiime2") || ci_contains(text, "mothur") ||
             ci_contains(text, "prinseq") ||
             (ci_contains(text, "salmon") && ci_contains(text, " -")) ||
             (ci_contains(text, "lumpy") && ci_contains(text, " -")) ||
             (ci_contains(text, "ragtag") && ci_contains(text, " -")) ||
             (ci_contains(text, "velvet") && ci_contains(text, " -"))) {
        what = "bioinfo primitive";
        } else if (
             /* cycle-317e: cae/aiml/voip/print/finance primitives */
             ci_contains(text, "z88r") || ci_contains(text, "paraview") ||
             ci_contains(text, "tecplot360") || ci_contains(text, "femm42") ||
             ci_contains(text, "torchserve") || ci_contains(text, "tensorboard") ||
             ci_contains(text, "stunserver") || ci_contains(text, "noteshrink") ||
             ci_contains(text, "briss") || ci_contains(text, "pdfcrop") ||
             ci_contains(text, "pdfbook") || ci_contains(text, "pdfnup") ||
             ci_contains(text, "pdf90") || ci_contains(text, "pdf180") ||
             ci_contains(text, "pdf270") || ci_contains(text, "kmymoney") ||
             ci_contains(text, "skrooge")) {
        what = "cae/aiml/voip/print/finance primitive";
        } else if (
             /* cycle-318a: editor/browser primitives */
             ci_contains(text, "kakoune") || ci_contains(text, "zile") ||
             ci_contains(text, "qtcreator") || ci_contains(text, "falkon") ||
             ci_contains(text, "qutebrowser") || ci_contains(text, "netsurf") ||
             ci_contains(text, "links2") || ci_contains(text, "elinks") ||
             ci_contains(text, "browsh") || ci_contains(text, "palemoon") ||
             ci_contains(text, "icecat") || ci_contains(text, "konqueror") ||
             (ci_contains(text, "epiphany") && ci_contains(text, " -")) ||
             (ci_contains(text, "carbonyl") && ci_contains(text, " -")) ||
             (ci_contains(text, "jove") && ci_contains(text, " -")) ||
             (ci_contains(text, "mousepad") && ci_contains(text, " -"))) {
        what = "editor/browser primitive";
        } else if (
             /* cycle-318b: comms/transfer primitives */
             ci_contains(text, "sylpheed") || ci_contains(text, "trojita") ||
             ci_contains(text, "enigmail") || ci_contains(text, "hakuneko") ||
             ci_contains(text, "tachidesk") || ci_contains(text, "rdedup") ||
             ci_contains(text, "nheko") || ci_contains(text, "discordo") ||
             ci_contains(text, "gtkcord") || ci_contains(text, "legcord") ||
             ci_contains(text, "twurl") ||
             (ci_contains(text, "seahorse") && ci_contains(text, " -")) ||
             (ci_contains(text, "ripcord") && ci_contains(text, " -")) ||
             (ci_contains(text, "tootle") && ci_contains(text, " -"))) {
        what = "comms/transfer primitive";
        } else if (
             /* cycle-318c: ssg/build/pkg-img/fpga primitives */
             ci_contains(text, "metalsmith") || ci_contains(text, "docusaurus") ||
             ci_contains(text, "vitepress") || ci_contains(text, "honkit") ||
             ci_contains(text, "contentlayer") || ci_contains(text, "chpst") ||
             ci_contains(text, "softlimit") || ci_contains(text, "envdir") ||
             ci_contains(text, "envuidgid") || ci_contains(text, "buildroot") ||
             ci_contains(text, "wchisp") || ci_contains(text, "stcgal") ||
             ci_contains(text, "hw_server") || ci_contains(text, "fpgaconf") ||
             ci_contains(text, "fpgainfo") || ci_contains(text, "aocl")) {
        what = "ssg/build/pkg-img/fpga primitive";
        } else if (
             /* cycle-319a: latex/doc/wiki/llm/dict/journal/misc primitives */
             ci_contains(text, "gojq") || ci_contains(text, "dvisvgm") ||
             ci_contains(text, "lacheck") || ci_contains(text, "bib2gls") ||
             ci_contains(text, "kpsewhich") || ci_contains(text, "documize") ||
             ci_contains(text, "wtfso") || ci_contains(text, "chatblade") ||
             ci_contains(text, "ksnip") || ci_contains(text, "gifine") ||
             ci_contains(text, "accerciser") || ci_contains(text, "goldendict") ||
             ci_contains(text, "po4a") || ci_contains(text, "polib") ||
             ci_contains(text, "rednotebook") || ci_contains(text, "pwqgen") ||
             ci_contains(text, "randpwd") || ci_contains(text, "tai64n") ||
             ci_contains(text, "tai64nlocal") || ci_contains(text, "softdog")) {
        what = "latex/doc/wiki/llm/dict/journal/misc primitive";
        } else if (
             /* cycle-319b: iot/industrial/erp/forum primitives */
             ci_contains(text, "tasmotizer") || ci_contains(text, "kalliope") ||
             ci_contains(text, "bacpypes") || ci_contains(text, "weberp") ||
             ci_contains(text, "adempiere") || ci_contains(text, "enewss")) {
        what = "iot/industrial/erp/forum primitive";
        } else if (
             /* cycle-320a: input/clipboard/theme/font primitives */
             ci_contains(text, "qjoypad") || ci_contains(text, "ds4drv") ||
             ci_contains(text, "wminput") || ci_contains(text, "qt5ct") ||
             ci_contains(text, "qt6ct") || ci_contains(text, "pywal") ||
             ci_contains(text, "hsetroot") || ci_contains(text, "gowall") ||
             ci_contains(text, "paperview") || ci_contains(text, "otfinfo") ||
             ci_contains(text, "pyftmerge")) {
        what = "input/clipboard/theme/font primitive";
        } else if (
             /* cycle-320b: launcher/av/power primitives */
             ci_contains(text, "wyrd") || ci_contains(text, "remindme") ||
             ci_contains(text, "jgmenu") || ci_contains(text, "mymenu") ||
             ci_contains(text, "docky") || ci_contains(text, "pulseeffects") ||
             ci_contains(text, "webcamoid") || ci_contains(text, "slimbookbattery")) {
        what = "launcher/av/power primitive";
        } else if (
             /* cycle-320c: data-infra/lint/wayland primitives */
             ci_contains(text, "immuadmin") || ci_contains(text, "kconnect") ||
             ci_contains(text, "zprint") || ci_contains(text, "kibit") ||
             ci_contains(text, "arandr") || ci_contains(text, "i3blocks") ||
             ci_contains(text, "i3status") || ci_contains(text, "swaystatus")) {
        what = "data-infra/lint/wayland primitive";
        } else if (
             /* cycle-321a: go/java linter primitives */
             ci_contains(text, "staticcheck") || ci_contains(text, "errcheck") ||
             ci_contains(text, "gocyclo") || ci_contains(text, "goconst") ||
             ci_contains(text, "gomodifytags") || ci_contains(text, "gotests") ||
             ci_contains(text, "fillstruct") || ci_contains(text, "errorprone")) {
        what = "go/java linter primitive";
        } else if (
             /* cycle-321b: ruby/php linter primitives */
             ci_contains(text, "standardrb") || ci_contains(text, "solargraph") ||
             ci_contains(text, "typeprof") || ci_contains(text, "fasterer") ||
             ci_contains(text, "metric_fu") || ci_contains(text, "deptrac") ||
             ci_contains(text, "paratest") || ci_contains(text, "kahlan")) {
        what = "ruby/php linter primitive";
        } else if (
             /* cycle-321c: misc-lang/db-admin/vdb primitives */
             ci_contains(text, "ocamlbuild") || ci_contains(text, "ocamllsp") ||
             ci_contains(text, "kaocha") || ci_contains(text, "fatpack") ||
             ci_contains(text, "minilla") || ci_contains(text, "gprbuild") ||
             ci_contains(text, "sicstus") || ci_contains(text, "mytop") ||
             ci_contains(text, "innotop") || ci_contains(text, "pg_repack") ||
             ci_contains(text, "pg_verifybackup") || ci_contains(text, "wal2json") ||
             ci_contains(text, "ledisdb") || ci_contains(text, "tendisplus")) {
        what = "misc-lang/db-admin/vdb primitive";
        } else if (
             /* cycle-322a: dicom primitives */
             ci_contains(text, "echoscu") || ci_contains(text, "dcmqrscp") ||
             ci_contains(text, "dcm2jpg") || ci_contains(text, "jpg2dcm") ||
             ci_contains(text, "dcmgpdir") || ci_contains(text, "dcmjpeg") ||
             ci_contains(text, "dcmquant") || ci_contains(text, "dconvlum") ||
             ci_contains(text, "dsr2html") || ci_contains(text, "img2dcm") ||
             ci_contains(text, "dcmmkcrv") || ci_contains(text, "dcmmklup") ||
             ci_contains(text, "dcmpschk") || ci_contains(text, "dcmpsprt") ||
             ci_contains(text, "dcmrecv") || ci_contains(text, "gdcmimg") ||
             ci_contains(text, "gdcminfo") || ci_contains(text, "gdcmpdf") ||
             ci_contains(text, "gdcmraw") || ci_contains(text, "gdcmviewer")) {
        what = "dicom primitive";
        } else if (
             /* cycle-322b: neuroimaging primitives */
             ci_contains(text, "mri_convert") || ci_contains(text, "fslmaths") ||
             ci_contains(text, "fslroi") || ci_contains(text, "fslmerge") ||
             ci_contains(text, "slicetimer") || ci_contains(text, "dtifit") ||
             ci_contains(text, "fsleyes") || ci_contains(text, "3dcalc") ||
             ci_contains(text, "mrconvert") || ci_contains(text, "dwi2response") ||
             ci_contains(text, "dwi2fod") || ci_contains(text, "tckgen") ||
             ci_contains(text, "tcksift") || ci_contains(text, "mrview") ||
             ci_contains(text, "n4biasfieldcorrection") ||
             ci_contains(text, "reg_aladin") || ci_contains(text, "heudiconv")) {
        what = "neuroimaging primitive";
        } else if (
             /* cycle-322c: meteo/micro/seismic/hydro primitives */
             ci_contains(text, "grib_ls") || ci_contains(text, "grib_set") ||
             ci_contains(text, "grib_filter") || ci_contains(text, "grib_compare") ||
             ci_contains(text, "grib2to1") || ci_contains(text, "ncks") ||
             ci_contains(text, "ncea") || ci_contains(text, "ncap2") ||
             ci_contains(text, "ncrename") || ci_contains(text, "ncwa") ||
             ci_contains(text, "ncbo") || ci_contains(text, "ncdiff") ||
             ci_contains(text, "ncgen") || ci_contains(text, "h5repack") ||
             ci_contains(text, "h5diff") || ci_contains(text, "h5stat") ||
             ci_contains(text, "hdfview") || ci_contains(text, "pyferret") ||
             ci_contains(text, "bufr_ls") || ci_contains(text, "bufr_set") ||
             ci_contains(text, "bufr_compare") || ci_contains(text, "bfconvert") ||
             ci_contains(text, "showinf") || ci_contains(text, "domainlist") ||
             ci_contains(text, "mkmemo") || ci_contains(text, "seisan") ||
             ci_contains(text, "geopsy") || ci_contains(text, "specfem3d") ||
             ci_contains(text, "pygimli") || ci_contains(text, "simpeg") ||
             ci_contains(text, "em1d") || ci_contains(text, "swat2012") ||
             ci_contains(text, "modflow6") || ci_contains(text, "flopy") ||
             ci_contains(text, "seepw") || ci_contains(text, "parflow") ||
             ci_contains(text, "pflotran") || ci_contains(text, "tough2")) {
        what = "meteo/micro/seismic/hydro primitive";
        } else if (
             /* cycle-323a: astro/drone primitives */
             ci_contains(text, "ekos") || ci_contains(text, "astap") ||
             ci_contains(text, "hnsky") || ci_contains(text, "skychart") ||
             ci_contains(text, "serplayer") || ci_contains(text, "pipp ") ||
             ci_contains(text, "sequator") || ci_contains(text, "fitswork") ||
             ci_contains(text, "ufoanalyzer") || ci_contains(text, "siril") ||
             ci_contains(text, "fitsliberator") ||
             ci_contains(text, "missionplanner") || ci_contains(text, "sim_vehicle") ||
             ci_contains(text, "mavgraph") || ci_contains(text, "mavflightview") ||
             ci_contains(text, "mavtomfile") || ci_contains(text, "mavflightmodes") ||
             ci_contains(text, "mavkml") || ci_contains(text, "mavaccel") ||
             ci_contains(text, "mavsigloss") || ci_contains(text, "mavchat") ||
             ci_contains(text, "mav_fence") || ci_contains(text, "mav_rally") ||
             ci_contains(text, "mav_wp") || ci_contains(text, "jmavsim") ||
             ci_contains(text, "mavsdk") || ci_contains(text, "dji_rev") ||
             ci_contains(text, "dji_imah_fwsig")) {
        what = "astro/drone primitive";
        } else if (
             /* cycle-323b: survey/ham/nlp primitives */
             ci_contains(text, "rtkrcv") || ci_contains(text, "convbin") ||
             ci_contains(text, "pos2kml") || ci_contains(text, "str2str") ||
             ci_contains(text, "teqc") || ci_contains(text, "gamit") ||
             ci_contains(text, "globk") || ci_contains(text, "glorg") ||
             ci_contains(text, "prsolve") || ci_contains(text, "poscvt") ||
             ci_contains(text, "timeconvert") || ci_contains(text, "rtkpost") ||
             ci_contains(text, "ezsurv") ||
             ci_contains(text, "goesrecv") || ci_contains(text, "spyserver") ||
             ci_contains(text, "rtl_433") || ci_contains(text, "rtlamr") ||
             ci_contains(text, "nrsc5") || ci_contains(text, "ebook2cw") ||
             ci_contains(text, "cwcp") || ci_contains(text, "dvrptrptr") ||
             ci_contains(text, "ambeserver") || ci_contains(text, "p25reflector") ||
             ci_contains(text, "wsvt") ||
             ci_contains(text, "corenlp") || ci_contains(text, "mgiza") ||
             ci_contains(text, "mitlm") || ci_contains(text, "berkeleylm") ||
             ci_contains(text, "cdec") || ci_contains(text, "sacrebleu") ||
             ci_contains(text, "sacremoses") || ci_contains(text, "spm_train") ||
             ci_contains(text, "learn_bpe") || ci_contains(text, "apply_bpe") ||
             ci_contains(text, "berkeleyparser") || ci_contains(text, "maltparser") ||
             ci_contains(text, "udparser") || ci_contains(text, "hunpos") ||
             ci_contains(text, "crf_learn") || ci_contains(text, "crf_test") ||
             ci_contains(text, "mecab")) {
        what = "survey/ham/nlp primitive";
        } else if (
             /* cycle-323c: cam/eda/hep/archival primitives */
             ci_contains(text, "gmoccapy") || ci_contains(text, "stepconf") ||
             ci_contains(text, "pncconf") || ci_contains(text, "halshow") ||
             ci_contains(text, "halscope") || ci_contains(text, "halmeter") ||
             ci_contains(text, "machinekit") || ci_contains(text, "chillipeppr") ||
             ci_contains(text, "estlcam") || ci_contains(text, "pycam") ||
             ci_contains(text, "k40whisperer") || ci_contains(text, "bambustudio") ||
             ci_contains(text, "kisslicer") || ci_contains(text, "icestl") ||
             ci_contains(text, "skeinforge") ||
             ci_contains(text, "bitmap2component") || ci_contains(text, "pcb_calculator") ||
             ci_contains(text, "pl_editor") || ci_contains(text, "cvpcb") ||
             ci_contains(text, "gschem") || ci_contains(text, "gattrib") ||
             ci_contains(text, "gsch2pcb") || ci_contains(text, "librepcb") ||
             ci_contains(text, "qrouter") || ci_contains(text, "timberwolf") ||
             ci_contains(text, "svlint") || ci_contains(text, "eqy") ||
             ci_contains(text, "bitwuzla") || ci_contains(text, "dreach") ||
             ci_contains(text, "eproof") ||
             ci_contains(text, "rootls") || ci_contains(text, "rootcp") ||
             ci_contains(text, "rootmv") || ci_contains(text, "rootprint") ||
             ci_contains(text, "rootbrowse") || ci_contains(text, "garfieldpp") ||
             ci_contains(text, "phits") || ci_contains(text, "njoy21") ||
             ci_contains(text, "talys") || ci_contains(text, "meqtrees") ||
             ci_contains(text, "vocl") || ci_contains(text, "pyraf") ||
             ci_contains(text, "gasgano") || ci_contains(text, "scisoft") ||
             ci_contains(text, "jhove") || ci_contains(text, "verapdf") ||
             ci_contains(text, "duracloud") || ci_contains(text, "islandora") ||
             ci_contains(text, "rawcooked") || ci_contains(text, "vrecord") ||
             ci_contains(text, "ffmprovisr") ||
             ci_contains(text, "abcm2ps") || ci_contains(text, "abc2midi") ||
             ci_contains(text, "abc2abc") || ci_contains(text, "midi2abc") ||
             ci_contains(text, "autosp") || ci_contains(text, "luppp") ||
             ci_contains(text, "subtitleeditor") || ci_contains(text, "suprip") ||
             ci_contains(text, "subshift") || ci_contains(text, "subs2srs") ||
             ci_contains(text, "pgs2srt") || ci_contains(text, "parlatype") ||
             ci_contains(text, "humogen") || ci_contains(text, "ancestris")) {
        what = "cam/eda/hep/archival primitive";
        } else if (
             /* cycle-324a: a11y/ime/photo/term primitives */
             ci_contains(text, "espeakup") || ci_contains(text, "lou_translate") ||
             ci_contains(text, "lou_trace") || ci_contains(text, "lou_debug") ||
             ci_contains(text, "lou_allround") || ci_contains(text, "brailleblaster") ||
             ci_contains(text, "dotsdtbook") ||
             ci_contains(text, "scim ") || ci_contains(text, "gcin") ||
             ci_contains(text, "rime_deployer") || ci_contains(text, "rime_patch") ||
             ci_contains(text, "gateone") ||
             ci_contains(text, "lightzone") || ci_contains(text, "photoflow") ||
             ci_contains(text, "fastrawviewer") || ci_contains(text, "filmulator") ||
             ci_contains(text, "photoflare") || ci_contains(text, "mypaint") ||
             ci_contains(text, "drawpile") || ci_contains(text, "kolourpaint") ||
             ci_contains(text, "tupitube")) {
        what = "a11y/ime/photo/term primitive";
        } else if (
             /* cycle-324b: wm primitives */
             ci_contains(text, "niri") || ci_contains(text, "spectrwm") ||
             ci_contains(text, "icewm") || ci_contains(text, "fvwm3") ||
             ci_contains(text, "ctwm") || ci_contains(text, "afterstep") ||
             ci_contains(text, "phoc") || ci_contains(text, "wmenu") ||
             ci_contains(text, "ulauncher") || ci_contains(text, "twmn") ||
             ci_contains(text, "taffybar")) {
        what = "wm primitive";
        } else if (
             /* cycle-324c: usd/3d/pointcloud primitives */
             ci_contains(text, "usdcat") || ci_contains(text, "usdview") ||
             ci_contains(text, "usdtree") || ci_contains(text, "usdchecker") ||
             ci_contains(text, "usddiff") || ci_contains(text, "usdrecord") ||
             ci_contains(text, "usdstitch") || ci_contains(text, "usdresolve") ||
             ci_contains(text, "usdedit") || ci_contains(text, "gltf2glb") ||
             ci_contains(text, "collada2gltf") || ci_contains(text, "fbx2gltf") ||
             ci_contains(text, "gltfpack") || ci_contains(text, "vdb_print") ||
             ci_contains(text, "vdb_render") || ci_contains(text, "vdb_view") ||
             ci_contains(text, "abcecho") || ci_contains(text, "abcinfo") ||
             ci_contains(text, "abcls") || ci_contains(text, "abcstitcher") ||
             ci_contains(text, "abcdiff") || ci_contains(text, "abcstitch") ||
             ci_contains(text, "pcl_convert") || ci_contains(text, "lasview") ||
             ci_contains(text, "lasgrid") || ci_contains(text, "lasheight") ||
             ci_contains(text, "lasground") || ci_contains(text, "lasclassify") ||
             ci_contains(text, "lascolor") || ci_contains(text, "lasduplicate") ||
             ci_contains(text, "lasdiff") || ci_contains(text, "lasmerge") ||
             ci_contains(text, "lasthin") || ci_contains(text, "lasvalley") ||
             ci_contains(text, "las2dem") || ci_contains(text, "las2iso") ||
             ci_contains(text, "laslayers") || ci_contains(text, "lasnoise") ||
             ci_contains(text, "lasscale") || ci_contains(text, "mm3d") ||
             ci_contains(text, "regard3d") || ci_contains(text, "pmvs2") ||
             ci_contains(text, "cmvs") || ci_contains(text, "meshrecon") ||
             ci_contains(text, "rtabmap") || ci_contains(text, "kimera") ||
             ci_contains(text, "tetview")) {
        what = "usd/3d/pointcloud primitive";
        } else if (
             /* cycle-324d: capture/osint/embedded/formal primitives */
             ci_contains(text, "byzanz") || ci_contains(text, "silentcast") ||
             ci_contains(text, "swappy") || ci_contains(text, "satty") ||
             ci_contains(text, "gpick") || ci_contains(text, "kcolorchooser") ||
             ci_contains(text, "gcolor3") ||
             ci_contains(text, "whatsmyname") ||
             ci_contains(text, "mklittlefs") || ci_contains(text, "mkspiffs") ||
             ci_contains(text, "lparse") ||
             ci_contains(text, "proverif") || ci_contains(text, "cryptoverif") ||
             ci_contains(text, "apalache") || ci_contains(text, "murphi") ||
             ci_contains(text, "fdr4") || ci_contains(text, "nusmv") ||
             ci_contains(text, "cpachecker") || ci_contains(text, "verifast") ||
             ci_contains(text, "cpplint") ||
             ci_contains(text, "autfilt") || ci_contains(text, "genaut") ||
             ci_contains(text, "randaut") || ci_contains(text, "ltlsynt") ||
             ci_contains(text, "ltl2ba")) {
        what = "capture/osint/embedded/formal primitive";
        } else if (
             /* cycle-325a: retro/emulator primitives */
             ci_contains(text, "z80asm") || ci_contains(text, "tniasm") ||
             ci_contains(text, "uz80as") || ci_contains(text, "zmac") ||
             ci_contains(text, "spectemu") || ci_contains(text, "scl2trd") ||
             ci_contains(text, "tape2pulses") || ci_contains(text, "tape2wav") ||
             ci_contains(text, "tapeconv") || ci_contains(text, "audio2tape") ||
             ci_contains(text, "listbasic") || ci_contains(text, "raw2hdf") ||
             ci_contains(text, "c1541") || ci_contains(text, "petcat") ||
             ci_contains(text, "cartconv") || ci_contains(text, "cc1541") ||
             ci_contains(text, "d64cbm") || ci_contains(text, "cbmlinetester") ||
             ci_contains(text, "unadf") || ci_contains(text, "adf2disk") ||
             ci_contains(text, "retro68") || ci_contains(text, "basiliskii") ||
             ci_contains(text, "minivmac") || ci_contains(text, "aranym") ||
             ci_contains(text, "linapple") || ci_contains(text, "catakig") ||
             ci_contains(text, "pcem") || ci_contains(text, "quasii88") ||
             ci_contains(text, "ep128emu") || ci_contains(text, "plus4emu") ||
             ci_contains(text, "yape") || ci_contains(text, "tivars") ||
             ci_contains(text, "hp11c") || ci_contains(text, "free42")) {
        what = "retro/emulator primitive";
        } else if (
             /* cycle-325b: bbs/osm/backup primitives */
             ci_contains(text, "echocfg") || ci_contains(text, "asc2ans") ||
             ci_contains(text, "binkit") || ci_contains(text, "chksmb") ||
             ci_contains(text, "gtkuseredit") || ci_contains(text, "indfactum") ||
             ci_contains(text, "smbactiv") || ci_contains(text, "sqpack") ||
             ci_contains(text, "fidoconf") || ci_contains(text, "fecfg2fc") ||
             ci_contains(text, "fido2sq") || ci_contains(text, "linkedto") ||
             ci_contains(text, "goldedplus") || ci_contains(text, "ifcico") ||
             ci_contains(text, "bforce") || ci_contains(text, "wwiv") ||
             ci_contains(text, "pcboard") ||
             ci_contains(text, "planetiler") || ci_contains(text, "img2grd") ||
             ci_contains(text, "amrecover") || ci_contains(text, "amlabel") ||
             ci_contains(text, "amstatus")) {
        what = "bbs/osm/backup primitive";
        } else if (
             /* cycle-325c: honeypot/ntpgps/moreutils/plan9 primitives */
             ci_contains(text, "dionaea") || ci_contains(text, "kfsensor") ||
             ci_contains(text, "fakeses") || ci_contains(text, "honeytrap") ||
             ci_contains(text, "pepdf") || ci_contains(text, "malsub") ||
             ci_contains(text, "drakvuf") || ci_contains(text, "malwarezoo") ||
             ci_contains(text, "noriben") || ci_contains(text, "procdot") ||
             ci_contains(text, "binee") ||
             ci_contains(text, "ntptime") || ci_contains(text, "gpscat") ||
             ci_contains(text, "lcdgps") || ci_contains(text, "gegps") ||
             ci_contains(text, "ntpshmmon") || ci_contains(text, "gps2udp") ||
             ci_contains(text, "gpscorrelate") || ci_contains(text, "qlandkartegt") ||
             ci_contains(text, "ifne") || ci_contains(text, "isutf8") ||
             ci_contains(text, "vidir") ||
             ci_contains(text, "mkone") ||
             ci_contains(text, "json2tsv") || ci_contains(text, "saait") ||
             ci_contains(text, "libzahl")) {
        what = "honeypot/ntpgps/moreutils/plan9 primitive";
        } else if (
             /* cycle-326a: pdf/present/broadcast/ascii primitives */
             ci_contains(text, "pdfdraw") || ci_contains(text, "pdftops") ||
             ci_contains(text, "pdfattach") || ci_contains(text, "pdffonts") ||
             ci_contains(text, "pdfdiff") || ci_contains(text, "diffpdf") ||
             ci_contains(text, "sioyek") ||
             ci_contains(text, "catpoint") || ci_contains(text, "lookatme") ||
             ci_contains(text, "decktape") ||
             ci_contains(text, "ices0") || ci_contains(text, "ices2") ||
             ci_contains(text, "ezstream") || ci_contains(text, "sc_serv") ||
             ci_contains(text, "cbonsai") || ci_contains(text, "asciiquarium") ||
             ci_contains(text, "aafire") || ci_contains(text, "asciiview") ||
             ci_contains(text, "shelr") || ci_contains(text, "catimg") ||
             ci_contains(text, "timg") || ci_contains(text, "uberzug")) {
        what = "pdf/present/broadcast/ascii primitive";
        } else if (
             /* cycle-326b: stress/diststore/san primitives */
             ci_contains(text, "filebench") || ci_contains(text, "smallfile") ||
             ci_contains(text, "mdtest") || ci_contains(text, "sg_dd") ||
             ci_contains(text, "sg_map") || ci_contains(text, "sginfo") ||
             ci_contains(text, "sktest") || ci_contains(text, "whdd") ||
             ci_contains(text, "hackbench") || ci_contains(text, "schbench") ||
             ci_contains(text, "dbench") || ci_contains(text, "fsmark") ||
             ci_contains(text, "llstat") || ci_contains(text, "pvfs2") ||
             ci_contains(text, "scstadmin") || ci_contains(text, "scst_local") ||
             ci_contains(text, "fcoeadm") || ci_contains(text, "fcoemon") ||
             ci_contains(text, "fcrls")) {
        what = "stress/diststore/san primitive";
        } else if (
             /* cycle-326c: tpm/pkcs11/feeds/notes primitives */
             ci_contains(text, "tpm_version") || ci_contains(text, "eidenv") ||
             ci_contains(text, "pamu2fcfg") ||
             ci_contains(text, "podgrab") || ci_contains(text, "mashpodder") ||
             ci_contains(text, "podboat") || ci_contains(text, "rawdog") ||
             ci_contains(text, "howdoi") || ci_contains(text, "buku")) {
        what = "tpm/pkcs11/feeds/notes primitive";
        } else if (
             /* cycle-327a: voip/sdr/fax/ppp/sms primitives */
             ci_contains(text, "dahdi_cfg") || ci_contains(text, "dahdi_hardware") ||
             ci_contains(text, "dahdi_maint") || ci_contains(text, "dahdi_speed") ||
             ci_contains(text, "dahdi_test") || ci_contains(text, "hdlcgen") ||
             ci_contains(text, "hdlcstress") || ci_contains(text, "hdlcverify") ||
             ci_contains(text, "pattest") || ci_contains(text, "patlooptest") ||
             ci_contains(text, "tones2wav") || ci_contains(text, "iptel") ||
             ci_contains(text, "gr_plot") || ci_contains(text, "gr_plot_fft") ||
             ci_contains(text, "gr_plot_iq") || ci_contains(text, "gr_plot_psd") ||
             ci_contains(text, "grcc") || ci_contains(text, "gsm_ussd") ||
             ci_contains(text, "probemodem") || ci_contains(text, "g3cat") ||
             ci_contains(text, "capiinfo") ||
             ci_contains(text, "pppstats") || ci_contains(text, "zntune") ||
             ci_contains(text, "atmloop") || ci_contains(text, "atsig") ||
             ci_contains(text, "kannel") || ci_contains(text, "atinout")) {
        what = "voip/sdr/fax/ppp/sms primitive";
        } else if (
             /* cycle-327b: crypto/iot/lirc/serial primitives */
             ci_contains(text, "namecoind") || ci_contains(text, "peercoind") ||
             ci_contains(text, "primecoind") || ci_contains(text, "vertcoind") ||
             ci_contains(text, "feathercoind") || ci_contains(text, "nearup") ||
             ci_contains(text, "neard") || ci_contains(text, "devp2p") ||
             ci_contains(text, "lora_pkt_fwd") || ci_contains(text, "basicstation") ||
             ci_contains(text, "rumqtt") ||
             ci_contains(text, "irrecord") || ci_contains(text, "ircat") ||
             ci_contains(text, "irpty") || ci_contains(text, "mode2") ||
             ci_contains(text, "pronto2lirc") ||
             ci_contains(text, "tty0tty") || ci_contains(text, "interceptty") ||
             ci_contains(text, "ttyspy") || ci_contains(text, "seyon") ||
             ci_contains(text, "tatssy")) {
        what = "crypto/iot/lirc/serial primitive";
        } else if (
             /* cycle-328a: metrics/search/ctn/firmware/memory primitives */
             ci_contains(text, "vmauth") || ci_contains(text, "vmselect") ||
             ci_contains(text, "vminsert") || ci_contains(text, "m3coordinator") ||
             ci_contains(text, "m3query") || ci_contains(text, "m3collector") ||
             ci_contains(text, "dalmatinerdb") || ci_contains(text, "akumuli") ||
             ci_contains(text, "brubeck") ||
             ci_contains(text, "wordbreaker") ||
             ci_contains(text, "flintlock") || ci_contains(text, "ucontainer") ||
             ci_contains(text, "sbattach") || ci_contains(text, "mkrlconf") ||
             ci_contains(text, "jeprof")) {
        what = "metrics/search/ctn/firmware/memory primitive";
        } else if (
             /* cycle-328b: bcc/trace/libbpf primitives */
             ci_contains(text, "tcpconnlat") || ci_contains(text, "tcpdrop") ||
             ci_contains(text, "biolatency") || ci_contains(text, "llcstat") ||
             ci_contains(text, "slabratetop") || ci_contains(text, "softirqs") ||
             ci_contains(text, "tplist") || ci_contains(text, "vfscount") ||
             ci_contains(text, "javaflow") || ci_contains(text, "javagc") ||
             ci_contains(text, "tclcalls") || ci_contains(text, "tclflow") ||
             ci_contains(text, "tclstat") ||
             ci_contains(text, "stapdyn") || ci_contains(text, "stapio") ||
             ci_contains(text, "bpf_iter") || ci_contains(text, "bpf_asm")) {
        what = "bcc/trace/libbpf primitive";
        } else if (
             /* cycle-329a: hpc/mpi/gpu primitives */
             ci_contains(text, "msub") || ci_contains(text, "showq") ||
             ci_contains(text, "ompi_info") ||
             ci_contains(text, "mpiicc") || ci_contains(text, "mpiicpc") ||
             ci_contains(text, "rocprof") || ci_contains(text, "hipcc") ||
             ci_contains(text, "nvprof")) {
        what = "hpc/mpi/gpu primitive";
        } else if (
             /* cycle-329b: pkgrepo/secscan primitives */
             ci_contains(text, "poudriere") || ci_contains(text, "smartpm") ||
             ci_contains(text, "pdtm") || ci_contains(text, "mapcidr") ||
             (ci_contains(text, "uncover") && ci_contains(text, " -"))) {
        what = "pkgrepo/secscan primitive";
        } else if (
             /* cycle-330a: mail/dns/share primitives */
             ci_contains(text, "postdrop") || ci_contains(text, "postkick") ||
             ci_contains(text, "postlock") || ci_contains(text, "postmulti") ||
             ci_contains(text, "sieve2lp") ||
             ci_contains(text, "mpop") ||
             ci_contains(text, "dnsgram") || ci_contains(text, "dnsreplay") ||
             ci_contains(text, "pdns_notify") || ci_contains(text, "zone2lmdb") ||
             ci_contains(text, "dumresp") || ci_contains(text, "kaspdb") ||
             ci_contains(text, "yadifa") || ci_contains(text, "yadifad") ||
             ci_contains(text, "nfsref")) {
        what = "mail/dns/share primitive";
        } else if (
             /* cycle-330b: backup/devmisc primitives */
             ci_contains(text, "btape") || ci_contains(text, "apgdiff")) {
        what = "backup/devmisc primitive";
        } else if (
             /* cycle-331a: image/audio primitives */
             ci_contains(text, "celeste_standalone") || ci_contains(text, "checkpto") ||
             ci_contains(text, "fulla") || ci_contains(text, "nona_gpu") ||
             ci_contains(text, "pto2mk") || ci_contains(text, "pto_gen") ||
             ci_contains(text, "ptovariable") || ci_contains(text, "vig_optimize") ||
             ci_contains(text, "pfsin") || ci_contains(text, "pfsout") ||
             ci_contains(text, "pfsview") || ci_contains(text, "hdrgen") ||
             ci_contains(text, "pfstmo") || ci_contains(text, "fcrecover") ||
             ci_contains(text, "drumgizmo") || (ci_contains(text, "abcde") && ci_contains(text, " -")) ||
             ci_contains(text, "eyed3") || ci_contains(text, "metaflac") ||
             ci_contains(text, "faac") || ci_contains(text, "faad") ||
             ci_contains(text, "twolame") || ci_contains(text, "fdkaac") ||
             ci_contains(text, "qaac") || ci_contains(text, "whipper")) {
        what = "image/audio primitive";
        } else if (
             /* cycle-331b: video/book/typeset primitives */
             ci_contains(text, "mkvinfo") || ci_contains(text, "mkvpropedit") ||
             ci_contains(text, "dvbtune") || ci_contains(text, "dvbstream") ||
             ci_contains(text, "dvbnet") || ci_contains(text, "dvbtraffic") ||
             ci_contains(text, "lrfviewer") || ci_contains(text, "pageedit") ||
             ci_contains(text, "fb2c") ||
             ci_contains(text, "troff") || (ci_contains(text, "eqn") && ci_contains(text, " -")) ||
             ci_contains(text, "preconv") || ci_contains(text, "soelim") ||
             ci_contains(text, "grn") || ci_contains(text, "nroff") ||
             ci_contains(text, "mdocml") || ci_contains(text, "grohtml") ||
             ci_contains(text, "neatroff")) {
        what = "video/book/typeset primitive";
        } else if (
             /* cycle-332a: graph/font primitives */
             ci_contains(text, "twopi") || ci_contains(text, "circo") ||
             ci_contains(text, "gvpr") || ci_contains(text, "bcomps") ||
             ci_contains(text, "ccomps") || ci_contains(text, "gvcolor") ||
             ci_contains(text, "gvpack") || ci_contains(text, "sccmap") ||
             ci_contains(text, "tred") || ci_contains(text, "diffimg") ||
             ci_contains(text, "gvedit") || ci_contains(text, "lneato") ||
             (ci_contains(text, "neato") && ci_contains(text, " -")) ||
             (ci_contains(text, "fdp") && ci_contains(text, " -")) ||
             (ci_contains(text, "osage") && ci_contains(text, " -")) ||
             (ci_contains(text, "patchwork") && ci_contains(text, " -")) ||
             (ci_contains(text, "unflatten") && ci_contains(text, " -")) ||
             (ci_contains(text, "smyrna") && ci_contains(text, " -")) ||
             (ci_contains(text, "dotty") && ci_contains(text, " -")) ||
             (ci_contains(text, "lefty") && ci_contains(text, " -")) ||
             ci_contains(text, "fontlint") || ci_contains(text, "fontbakery") ||
             ci_contains(text, "t1disasm") || ci_contains(text, "t1asm") ||
             ci_contains(text, "ttfautohint") || ci_contains(text, "ftview") ||
             ci_contains(text, "ftmulti") || ci_contains(text, "ftdiff") ||
             ci_contains(text, "ftbench") || ci_contains(text, "ftmetric") ||
             ci_contains(text, "ftsbench")) {
        what = "graph/font primitive";
        } else if (
             /* cycle-332b: disc/bench primitives */
             ci_contains(text, "wsdd") || ci_contains(text, "mrdisc") ||
             ci_contains(text, "ripquery") || ci_contains(text, "arpon") ||
             ci_contains(text, "zcip") ||
             ci_contains(text, "hpcc") || (ci_contains(text, "hey") && ci_contains(text, " -")) ||
             ci_contains(text, "autobench") || ci_contains(text, "fs_mark") ||
             ci_contains(text, "lmbench") || ci_contains(text, "tinymembench")) {
        what = "disc/bench primitive";
        } else if (
             /* cycle-333a: ietf/biblio/chem primitives */
             ci_contains(text, "onsgmls") || ci_contains(text, "nsgmls") ||
             ci_contains(text, "mmark") || ci_contains(text, "idnits") ||
             ci_contains(text, "rfcdiff") || ci_contains(text, "rfcmarkup") ||
             ci_contains(text, "rfcfold") || ci_contains(text, "svgcheck") ||
             ci_contains(text, "bibconvert") || ci_contains(text, "bib2bib") ||
             ci_contains(text, "bibdiff") ||
             ci_contains(text, "obfit") || ci_contains(text, "obgen") ||
             ci_contains(text, "cpmd")) {
        what = "ietf/biblio/chem primitive";
        } else if (
             /* cycle-333b: bio primitives */
             (ci_contains(text, "tophat") && ci_contains(text, " -")) ||
             (ci_contains(text, "glimmer") && ci_contains(text, " -")) ||
             (ci_contains(text, "aragorn") && ci_contains(text, " -")) ||
             ci_contains(text, "barrnap") ||
             ci_contains(text, "cmbuild") || ci_contains(text, "cmemit") ||
             ci_contains(text, "cmfetch") || ci_contains(text, "cmstat")) {
        what = "bio primitive";
        } else if (
             /* cycle-334a: vcs/fsrepair primitives */
             ci_contains(text, "rcsdiff") || ci_contains(text, "rcsmerge") ||
             ci_contains(text, "cssc") || ci_contains(text, "patchview") ||
             ci_contains(text, "unwrapdiff") || ci_contains(text, "dehtmldiff") ||
             ci_contains(text, "recountdiff") ||
             ci_contains(text, "e2undo") || ci_contains(text, "zhack") ||
             ci_contains(text, "lscp") || ci_contains(text, "mkcp") ||
             ci_contains(text, "fsck.f2fs") || ci_contains(text, "defrag.f2fs") ||
             ci_contains(text, "resize.f2fs")) {
        what = "vcs/fsrepair primitive";
        } else if (
             /* cycle-334b: cast/job/img primitives */
             ci_contains(text, "zmodem") || ci_contains(text, "supercronic") ||
             ci_contains(text, "aatest") || ci_contains(text, "asciigif")) {
        what = "cast/job/img primitive";
        } else if (
             /* cycle-335a: desktop misc primitives */
             ci_contains(text, "wlopm") || ci_contains(text, "swayr") ||
             (ci_contains(text, "undervolt") && ci_contains(text, " -")) ||
             ci_contains(text, "disper")) {
        what = "desktop misc primitive";
        } else if (
             /* cycle-336a: mcu/barcode/ocr primitives */
             ci_contains(text, "esplorer") || ci_contains(text, "circup") ||
             ci_contains(text, "lpc21isp") || ci_contains(text, "sdas8051") ||
             ci_contains(text, "sdld") || ci_contains(text, "gpasm") ||
             ci_contains(text, "tl866") ||
             ci_contains(text, "eplabel") || ci_contains(text, "niimbot") ||
             ci_contains(text, "phomemo") ||
             ci_contains(text, "ocropy") || ci_contains(text, "ocrfeeder")) {
        what = "mcu/barcode/ocr primitive";
        } else if (
             /* cycle-336b: iot/midi primitives */
             ci_contains(text, "tunslip") || ci_contains(text, "tunslip6") ||
             ci_contains(text, "wpcapslip") || ci_contains(text, "hdspconf")) {
        what = "iot/midi primitive";
        } else if (
             /* cycle-337a: thin/cluster primitives */
             ci_contains(text, "epoptes") || ci_contains(text, "italc2") ||
             ci_contains(text, "thinstation") || ci_contains(text, "dshbak") ||
             ci_contains(text, "capistrano")) {
        what = "thin/cluster primitive";
        } else if (
             /* cycle-337b: ldap primitives */
             ci_contains(text, "ldapcompare") || ci_contains(text, "dsidm") ||
             ci_contains(text, "nslcd")) {
        what = "ldap primitive";
        } else if (
             /* cycle-338a: torr/fedi primitives */
             ci_contains(text, "torrench") || ci_contains(text, "magnet2torrent") ||
             ci_contains(text, "tootstream") || (ci_contains(text, "nostril") && ci_contains(text, " -")) ||
             ci_contains(text, "nostpy") || ci_contains(text, "snac ")) {
        what = "torr/fedi primitive";
        } else if (
             /* cycle-338b: fb/feed/misc primitives */
             ci_contains(text, "fbv") || ci_contains(text, "fbdesk") ||
             ci_contains(text, "fbpdf") || ci_contains(text, "dfbg") ||
             ci_contains(text, "dfbshow") ||
             (ci_contains(text, "jenny") && ci_contains(text, " -")) ||
             ci_contains(text, "newsraft") ||
             ci_contains(text, "itchd") || ci_contains(text, "vkquake")) {
        what = "fb/feed/misc primitive";
        } else if (
             /* cycle-339a: sdrhw/can/obd primitives */
             ci_contains(text, "hackrf_clock") ||
             ci_contains(text, "hackrf_operacake") || ci_contains(text, "limeutil") ||
             ci_contains(text, "quicktest") || ci_contains(text, "soapysdrutil") ||
             ci_contains(text, "baudline") || ci_contains(text, "fosphor") ||
             ci_contains(text, "canfdtest") || ci_contains(text, "bcmserver") ||
             ci_contains(text, "isotprecv") || ci_contains(text, "isotpserver") ||
             ci_contains(text, "isotptun") || ci_contains(text, "cannelloni") ||
             ci_contains(text, "obdinfo") || ci_contains(text, "pyren")) {
        what = "sdrhw/can/obd primitive";
        } else if (
             /* cycle-339b: drone/emu primitives */
             ci_contains(text, "blheli32") || ci_contains(text, "blheli_s") ||
             ci_contains(text, "emuflight") ||
             ci_contains(text, "re3") || ci_contains(text, "revc") ||
             (ci_contains(text, "descent") && ci_contains(text, " -")) ||
             ci_contains(text, "fteqw") || ci_contains(text, "quakespasm") ||
             ci_contains(text, "ezquake") || ci_contains(text, "fuhquake") ||
             ci_contains(text, "ioq3ded") || ci_contains(text, "eduke32") ||
             ci_contains(text, "gzdoom") || ci_contains(text, "zandronum") ||
             ci_contains(text, "slade3")) {
        what = "drone/emu primitive";
        } else if (
             /* cycle-340a: vcs primitives */
             ci_contains(text, "commitlint") || (ci_contains(text, "breezy") && ci_contains(text, " -"))) {
        what = "vcs primitive";
        } else if (
             /* cycle-340b: archive/bench primitives */
             ci_contains(text, "7za") || ci_contains(text, "7zr") ||
             (ci_contains(text, "lzmadec") && ci_contains(text, " -")) ||
             ci_contains(text, "paq8") ||
             ci_contains(text, "flent") || ci_contains(text, "ntttcp")) {
        what = "archive/bench primitive";
        } else if (
             /* cycle-341a: routing/virt primitives */
             ci_contains(text, "eigrpd") || ci_contains(text, "bfdd") ||
             ci_contains(text, "rtrtr") || ci_contains(text, "routinator") ||
             ci_contains(text, "vfkit")) {
        what = "routing/virt primitive";
        } else if (
             /* cycle-341b: ham/mobile/build primitives */
             ci_contains(text, "wsprd") || (ci_contains(text, "chronic") && ci_contains(text, " -")) ||
             ci_contains(text, "gnirehtet") || ci_contains(text, "irecovery") ||
             ci_contains(text, "qdl") || ci_contains(text, "bitbake") ||
             ci_contains(text, "wic ") || (ci_contains(text, "toaster") && ci_contains(text, " -")) ||
             ci_contains(text, "debos") || ci_contains(text, "perkeep") ||
             ci_contains(text, "tessen")) {
        what = "ham/mobile/build primitive";
        } else if (
             /* cycle-342a: infra/messaging primitives */
             ci_contains(text, "moofsd") || ci_contains(text, "krenew") ||
             ci_contains(text, "bzl") || ci_contains(text, "prom2json") ||
             ci_contains(text, "nsc ") || ci_contains(text, "kaf ") ||
             ci_contains(text, "girc") || (ci_contains(text, "pounce") && ci_contains(text, " -"))) {
        what = "infra/messaging primitive";
        } else if (
             /* cycle-343a: forensic primitives */
             ci_contains(text, "affconvert") || ci_contains(text, "mmstat") ||
             ci_contains(text, "filewalk") || ci_contains(text, "blkstat") ||
             ci_contains(text, "blkcalc") || ci_contains(text, "img_cat") ||
             ci_contains(text, "ssdeep")) {
        what = "forensic primitive";
        } else if (
             /* cycle-343b: tracker/cad primitives */
             (ci_contains(text, "schism") && ci_contains(text, " -")) ||
             ci_contains(text, "ft2") || ci_contains(text, "psycle") ||
             ci_contains(text, "it2midi") || ci_contains(text, "sidplay") ||
             ci_contains(text, "mocp") || ci_contains(text, "mged") ||
             ci_contains(text, "rtweight") || ci_contains(text, "rtwizard") ||
             ci_contains(text, "blockmesh")) {
        what = "tracker/cad primitive";
        } else if (
             /* cycle-344a: pkt/doc/game primitives */
             ci_contains(text, "ifpps") || ci_contains(text, "bpfc") ||
             ci_contains(text, "curvetun") || ci_contains(text, "flowtop") ||
             ci_contains(text, "packit ") || ci_contains(text, "tcpprep") ||
             ci_contains(text, "wvhtml") || ci_contains(text, "umoria") ||
             ci_contains(text, "frogcomposband")) {
        what = "pkt/doc/game primitive";
        } else if (
             /* cycle-344b: dict/hex primitives */
             ci_contains(text, "sdcv") || ci_contains(text, "bvi ") ||
             ci_contains(text, "bviplus")) {
        what = "dict/hex primitive";
        } else if (
             /* cycle-345a: unix-admin primitives */
             ci_contains(text, "hastd") || ci_contains(text, "gmirror") ||
             ci_contains(text, "graid3") || ci_contains(text, "graid5") ||
             ci_contains(text, "gcache") || ci_contains(text, "pfstat") ||
             ci_contains(text, "sockstat") ||
             ci_contains(text, "zoneadm") || ci_contains(text, "zonename") ||
             ci_contains(text, "svcs ") || ci_contains(text, "svcprop") ||
             ci_contains(text, "prstat") || ci_contains(text, "pfiles") ||
             (ci_contains(text, "crash") && ci_contains(text, " -")) ||
             ci_contains(text, "winevdm") || ci_contains(text, "dispwin") ||
             ci_contains(text, "iccprop")) {
        what = "unix-admin primitive";
        } else if (
             /* cycle-345b: plc/print primitives */
             ci_contains(text, "iec2c") || ci_contains(text, "foo2zjs")) {
        what = "plc/print primitive";
        } else if (
             /* cycle-346a: scamper/netdiag primitives */
             ci_contains(text, "sc_tracediff") || ci_contains(text, "sc_tntbl") ||
             ci_contains(text, "sc_warts2json") || ci_contains(text, "ifstatus") ||
             ci_contains(text, "netselect") || ci_contains(text, "tcptrack")) {
        what = "scamper/netdiag primitive";
        } else if (
             /* cycle-346b: task/svc primitives */
             (ci_contains(text, "tsp") && ci_contains(text, " -")) ||
             (ci_contains(text, "hivemind") && ci_contains(text, " -")) ||
             (ci_contains(text, "perp") && ci_contains(text, " -")) || ci_contains(text, "perpd") ||
             ci_contains(text, "emptty") || ci_contains(text, "obmenu")) {
        what = "task/svc primitive";
        } else if (
             /* cycle-347a: ifiction primitives */
             ci_contains(text, "dfrotz") || ci_contains(text, "nitfol") ||
             ci_contains(text, "bocfel") || ci_contains(text, "scottfree") ||
             ci_contains(text, "advsys") || ci_contains(text, "tweego")) {
        what = "ifiction primitive";
        } else if (
             /* cycle-347b: plan9/shell primitives */
             ci_contains(text, "u9fs") || (ci_contains(text, "factotum") && ci_contains(text, " -")) ||
             (ci_contains(text, "upas") && ci_contains(text, " -")) ||
             ci_contains(text, "ndb ") || ci_contains(text, "mothra") ||
             ci_contains(text, "abaco") || ci_contains(text, "ysh") ||
             (ci_contains(text, "sash") && ci_contains(text, " -"))) {
        what = "plan9/shell primitive";
        } else if (
             /* cycle-348a: uucp/news primitives */
             ci_contains(text, "uustat") || ci_contains(text, "uupick") ||
             ci_contains(text, "uucico") || ci_contains(text, "inncheck") ||
             ci_contains(text, "innconfval") || ci_contains(text, "innmail") ||
             ci_contains(text, "news2mail") || ci_contains(text, "mail2news") ||
             ci_contains(text, "fetchnews") || ci_contains(text, "applyfilter") ||
             ci_contains(text, "checkgroups") || ci_contains(text, "strn")) {
        what = "uucp/news primitive";
        } else if (
             /* cycle-348b: tape/clone primitives */
             ci_contains(text, "tapestat") || ci_contains(text, "bdrecord") ||
             ci_contains(text, "udpcast")) {
        what = "tape/clone primitive";
        } else if (
             /* cycle-349a: abi/dwarf primitives */
             ci_contains(text, "elflint") || ci_contains(text, "pdwtags") ||
             ci_contains(text, "codtag") || ci_contains(text, "abidiff") ||
             ci_contains(text, "abidw") || ci_contains(text, "abilint")) {
        what = "abi/dwarf primitive";
        } else if (
             /* cycle-349b: binutil/prof primitives */
             ci_contains(text, "windres") || ci_contains(text, "dllwrap") ||
             ci_contains(text, "c++filt") || ci_contains(text, "ocount") ||
             ci_contains(text, "sprof") || ci_contains(text, "latrace")) {
        what = "binutil/prof primitive";
        } else if (
             /* cycle-350a: dotfiles primitives */
             ci_contains(text, "rcup") || ci_contains(text, "rcdn") ||
             ci_contains(text, "mkrc") || ci_contains(text, "lsrc") ||
             ci_contains(text, "autoenv") || ci_contains(text, "homeshick") ||
             ci_contains(text, "tuckr") || ci_contains(text, "dotbare")) {
        what = "dotfiles primitive";
        } else if (
             /* cycle-350b: vermgr primitives */
             (ci_contains(text, "nave") && ci_contains(text, " -")) ||
             ci_contains(text, "nodist") || ci_contains(text, "nvmw") ||
             ci_contains(text, "swiftenv")) {
        what = "vermgr primitive";
        } else if (
             /* cycle-351a: chess/mud primitives */
             (ci_contains(text, "fruit") && ci_contains(text, " -")) ||
             (ci_contains(text, "toga") && ci_contains(text, " -")) ||
             ci_contains(text, "sjaakii") || ci_contains(text, "eubos") ||
             ci_contains(text, "bayeselo") || ci_contains(text, "ordoprep") ||
             ci_contains(text, "pgn2fen") || ci_contains(text, "scidvspc") ||
             ci_contains(text, "scidb") || ci_contains(text, "tt++") ||
             ci_contains(text, "beipmu") || ci_contains(text, "kmuddy") ||
             ci_contains(text, "mudbot")) {
        what = "chess/mud primitive";
        } else if (
             /* cycle-351b: go/puzzle primitives */
             ci_contains(text, "minigo") || ci_contains(text, "sgf2dg") ||
             ci_contains(text, "sgfmerge") || ci_contains(text, "sgfc") ||
             ci_contains(text, "twogtp") || (ci_contains(text, "quarry") && ci_contains(text, " -"))) {
        what = "go/puzzle primitive";
        } else if (
             /* cycle-352a: dicom primitives */
             ci_contains(text, "dcm2pnm") || ci_contains(text, "dcmj2pnm") ||
             ci_contains(text, "pdf2dcm") || ci_contains(text, "dcm2pdf") ||
             ci_contains(text, "stl2dcm") || ci_contains(text, "dcml2pnm") ||
             ci_contains(text, "drtt")) {
        what = "dicom primitive";
        } else if (
             /* cycle-352b: med/bio primitives */
             ci_contains(text, "bet2 ") || ci_contains(text, "convert3d") ||
             ci_contains(text, "smartpca") || ci_contains(text, "mergeit") ||
             ci_contains(text, "qp3pop") || ci_contains(text, "qp4pop") ||
             ci_contains(text, "qpgraph") || ci_contains(text, "qpwave") ||
             ci_contains(text, "qpadm") || ci_contains(text, "rolloff") ||
             ci_contains(text, "f4stats") || ci_contains(text, "treeannotator") ||
             ci_contains(text, "clustalw") || ci_contains(text, "probcons") ||
             ci_contains(text, "poa ")) {
        what = "med/bio primitive";
        } else if (
             /* cycle-353a: weather/aviation primitives */
             ci_contains(text, "wview") || ci_contains(text, "grib_convert") ||
             ci_contains(text, "bufr_filter") || ci_contains(text, "ncflint") ||
             ci_contains(text, "ncpdq") || ci_contains(text, "fgo") ||
             ci_contains(text, "yasim") || ci_contains(text, "ivac")) {
        what = "weather/aviation primitive";
        } else if (
             /* cycle-353b: marine primitives */
             ci_contains(text, "zygrib") || ci_contains(text, "avnav") ||
             ci_contains(text, "ntpshm") || ci_contains(text, "ppscheck")) {
        what = "marine primitive";
        } else if (
             /* cycle-354a: print3d/ham primitives */
             ci_contains(text, "stl2gts") || ci_contains(text, "ideamaker") ||
             ci_contains(text, "qsorder") ||
             (ci_contains(text, "grig") && ci_contains(text, " -")) ||
             (ci_contains(text, "aldo") && ci_contains(text, " -")) ||
             (ci_contains(text, "qrq") && ci_contains(text, " -")) ||
             ci_contains(text, "adif2qsl") ||
             ci_contains(text, "cabrillo2adif")) {
        what = "print3d/ham primitive";
        } else if (
             /* cycle-354b: astro-wcs primitives */
             ci_contains(text, "skyfilter") || ci_contains(text, "skycoor") ||
             ci_contains(text, "imwcs") || ci_contains(text, "i2f") ||
             ci_contains(text, "simpos")) {
        what = "astro-wcs primitive";
        } else if (
             /* cycle-355a: video/disc primitives */
             ci_contains(text, "ogminfo") || ci_contains(text, "ifogen") ||
             ci_contains(text, "dvdwizard") || ci_contains(text, "pigz") ||
             ci_contains(text, "dvdisaster") || ci_contains(text, "bchunk") ||
             ci_contains(text, "daa2iso") || ci_contains(text, "uif2iso")) {
        what = "video/disc primitive";
        } else if (
             /* cycle-355b: subtitle/npm primitives */
             ci_contains(text, "subdl") || ci_contains(text, "srted") ||
             ci_contains(text, "srtshift") || ci_contains(text, "subrip") ||
             ci_contains(text, "ogmrip") || ci_contains(text, "depcheck") ||
             ci_contains(text, "publint") || ci_contains(text, "attw") ||
             ci_contains(text, "npq") || ci_contains(text, "qnm")) {
        what = "subtitle/npm primitive";
        } else if (
             /* cycle-356a: retro-emu/pascal primitives */
             ci_contains(text, "winuae") || ci_contains(text, "uae4all") ||
             ci_contains(text, "punes") || ci_contains(text, "mesen") ||
             ci_contains(text, "visualboyadvance") || ci_contains(text, "melonds") ||
             ci_contains(text, "retroach") || ci_contains(text, "ppc386") ||
             ci_contains(text, "fppkg") || ci_contains(text, "ppdep") ||
             (ci_contains(text, "ptop") && ci_contains(text, " -")) ||
             ci_contains(text, "pas2js") ||
             ci_contains(text, "compileserver") || ci_contains(text, "lprfil") ||
             ci_contains(text, "rstconv") || ci_contains(text, "h2pas") ||
             ci_contains(text, "h2paspp") || ci_contains(text, "fppd") ||
             ci_contains(text, "pas2fpm") || ci_contains(text, "unipas2html") ||
             (ci_contains(text, "ecl") && ci_contains(text, " -")) ||
             (ci_contains(text, "ccl") && ci_contains(text, " -")) ||
             ci_contains(text, "abcl") ||
             (ci_contains(text, "gcl") && ci_contains(text, " -")) ||
             ci_contains(text, "mkcl")) {
        what = "retro/lang primitive";
        } else if (
             /* cycle-356b: forth primitives */
             ci_contains(text, "ficl") || ci_contains(text, "wina ") ||
             ci_contains(text, "mecrisp") || ci_contains(text, "stoneknife") ||
             (ci_contains(text, "4th") && ci_contains(text, " -")) ||
             (ci_contains(text, "lina") && ci_contains(text, " -")) ||
             (ci_contains(text, "carp") && ci_contains(text, " -"))) {
        what = "forth primitive";
        } else if (
             /* cycle-357a: geo primitives */
             ci_contains(text, "gdalgrid") || ci_contains(text, "gdal_polygonize") ||
             ci_contains(text, "gdal_sieve") ||
             (ci_contains(text, "proj") && ci_contains(text, " -")) ||
             ci_contains(text, "invproj") || ci_contains(text, "geotiffcp") ||
             ci_contains(text, "geotifcp") || ci_contains(text, "applygeo") ||
             ci_contains(text, "tiffcp") || ci_contains(text, "tiffinfo") ||
             ci_contains(text, "tiffset") || ci_contains(text, "tiffcmp") ||
             ci_contains(text, "gif2tiff") || ci_contains(text, "ras2tiff") ||
             ci_contains(text, "raw2tiff") || ci_contains(text, "rgb2ycbcr") ||
             (ci_contains(text, "thumbnail") && ci_contains(text, " -")) ||
             ci_contains(text, "tiff2pdf") || ci_contains(text, "tiff2ps") ||
             ci_contains(text, "tiff2rgba")) {
        what = "geo primitive";
        } else if (
             /* cycle-357b: spatial/mesh primitives */
             ci_contains(text, "shp2svg") || ci_contains(text, "shpcat") ||
             ci_contains(text, "shpgeo") || ci_contains(text, "shpinfo") ||
             ci_contains(text, "shpproj") || ci_contains(text, "shprdf") ||
             ci_contains(text, "shprewind") || ci_contains(text, "shptree") ||
             ci_contains(text, "shptreetst") || ci_contains(text, "shptst") ||
             ci_contains(text, "shpwkt") || ci_contains(text, "dbfcat") ||
             ci_contains(text, "dbfinfo") || ci_contains(text, "sbn ") ||
             ci_contains(text, "map2img") ||
             (ci_contains(text, "legend") && ci_contains(text, " -")) ||
             (ci_contains(text, "scalebar") && ci_contains(text, " -")) ||
             ci_contains(text, "shp2img") || ci_contains(text, "tile4ms") ||
             ci_contains(text, "msencrypt") || ci_contains(text, "meshlab") ||
             ci_contains(text, "pymeshlab") || ci_contains(text, "mmg") ||
             ci_contains(text, "mmgs") || ci_contains(text, "mmg2d") ||
             ci_contains(text, "mmg3d") || ci_contains(text, "gmesh") ||
             ci_contains(text, "tetmesher") || ci_contains(text, "distmesh") ||
             ci_contains(text, "iso2mesh") || ci_contains(text, "surf2mesh") ||
             ci_contains(text, "tet2mesh") || ci_contains(text, "acvd") ||
             ci_contains(text, "acvdp")) {
        what = "spatial/mesh primitive";
        } else if (
             /* cycle-358a: net-legacy/boot primitives */
             ci_contains(text, "rstatd") || ci_contains(text, "rcp") ||
             ci_contains(text, "rdist") || ci_contains(text, "rdistd") ||
             (ci_contains(text, "talk") && ci_contains(text, " -")) ||
             ci_contains(text, "ytalk") ||
             ci_contains(text, "biff") || ci_contains(text, "comsat") ||
             (ci_contains(text, "from") && ci_contains(text, " -")) ||
             ci_contains(text, "biffd") ||
             ci_contains(text, "editmap") ||
             (ci_contains(text, "vacation") && ci_contains(text, " -")) ||
             ci_contains(text, "bootpd") || ci_contains(text, "bootpgw") ||
             ci_contains(text, "bootptest") || ci_contains(text, "bootpef") ||
             ci_contains(text, "bootparamd") || ci_contains(text, "rarp") ||
             ci_contains(text, "dhcpcd") || ci_contains(text, "dhcrelay") ||
             ci_contains(text, "dhcprequest") || ci_contains(text, "dhcp_probe") ||
             ci_contains(text, "dhcptrouble") || ci_contains(text, "bootps") ||
             ci_contains(text, "rdnss") || ci_contains(text, "traceroute6")) {
        what = "net-legacy primitive";
        } else if (
             /* cycle-358b: amiga-adf primitives */
             ci_contains(text, "adfinfo") || ci_contains(text, "adflist") ||
             ci_contains(text, "adfblitzer") || ci_contains(text, "adfcop") ||
             ci_contains(text, "adfdir") || ci_contains(text, "adffile") ||
             ci_contains(text, "adficon") || ci_contains(text, "adfput") ||
             ci_contains(text, "adfver") || ci_contains(text, "adfview") ||
             ci_contains(text, "adfvol") || ci_contains(text, "hdfinfo") ||
             ci_contains(text, "hdf2adf") || ci_contains(text, "adf2hdf") ||
             ci_contains(text, "dms2adf") || ci_contains(text, "adf2dms") ||
             ci_contains(text, "adfc") || ci_contains(text, "adfl") ||
             ci_contains(text, "adfu") || ci_contains(text, "adfv") ||
             ci_contains(text, "adfw")) {
        what = "amiga-adf primitive";
        } else if (
             /* cycle-359a: editor/doc primitives */
             ci_contains(text, "nedit") ||
             (ci_contains(text, "joe") && ci_contains(text, " -")) ||
             (ci_contains(text, "gedit") && ci_contains(text, " -")) ||
             ci_contains(text, "leafpad") ||
             (ci_contains(text, "cream") && ci_contains(text, " -")) ||
             ci_contains(text, "juffed") || ci_contains(text, "jed") ||
             (ci_contains(text, "epsilon") && ci_contains(text, " -")) ||
             (ci_contains(text, "lava") && ci_contains(text, " -")) ||
             ci_contains(text, "kak") ||
             ci_contains(text, "nvi ") ||
             (ci_contains(text, "elvis") && ci_contains(text, " -")) ||
             (ci_contains(text, "vile") && ci_contains(text, " -")) ||
             ci_contains(text, "neatvi") || ci_contains(text, "visurf") ||
             ci_contains(text, "coedit") || ci_contains(text, "e3em") ||
             ci_contains(text, "e3pi") || ci_contains(text, "e3vi") ||
             ci_contains(text, "bpe") ||
             (ci_contains(text, "curse") && ci_contains(text, " -")) ||
             (ci_contains(text, "levee") && ci_contains(text, " -")) ||
             (ci_contains(text, "mined") && ci_contains(text, " -")) ||
             ci_contains(text, "mle") ||
             (ci_contains(text, "qe") && ci_contains(text, " -")) ||
             ci_contains(text, "scite") || ci_contains(text, "thoteditor") ||
             ci_contains(text, "twe ") ||
             (ci_contains(text, "vigor") && ci_contains(text, " -")) ||
             ci_contains(text, "yedit") ||
             (ci_contains(text, "apropos") && ci_contains(text, " -")) ||
             (ci_contains(text, "whatis") && ci_contains(text, " -")) ||
             ci_contains(text, "groffer") || ci_contains(text, "deroff") ||
             ci_contains(text, "dvi2tty") || ci_contains(text, "dvitty") ||
             ci_contains(text, "dvisvga") || ci_contains(text, "dvihp") ||
             ci_contains(text, "dvilj") || ci_contains(text, "dvilj2p") ||
             ci_contains(text, "dvilj4") || ci_contains(text, "dvilj4l") ||
             ci_contains(text, "dvilj6") || ci_contains(text, "dvipos") ||
             ci_contains(text, "dvired") || ci_contains(text, "dviselect") ||
             ci_contains(text, "dvispc") || ci_contains(text, "dvitodvi") ||
             ci_contains(text, "dvitype") || ci_contains(text, "dv2dt") ||
             ci_contains(text, "dt2dv") || ci_contains(text, "disdvi") ||
             ci_contains(text, "dvi2bitmap") || ci_contains(text, "weblint")) {
        what = "editor/doc primitive";
        } else if (
             /* cycle-359b: office primitives */
             ci_contains(text, "libreoffice") || ci_contains(text, "localc") ||
             ci_contains(text, "lodraw") || ci_contains(text, "lomath") ||
             ci_contains(text, "wvware") || ci_contains(text, "ppthtml") ||
             ci_contains(text, "wordview") || ci_contains(text, "rtf2html")) {
        what = "office primitive";
        } else if (
             /* cycle-360a: cpm/atari primitives */
             ci_contains(text, "mkfs.cpm") || ci_contains(text, "cpmls") ||
             ci_contains(text, "cpm ") || ci_contains(text, "cpmlabel") ||
             ci_contains(text, "cpmls5") || ci_contains(text, "altairz80") ||
             ci_contains(text, "z80pack") || ci_contains(text, "z80sim") ||
             ci_contains(text, "cpmsim") || ci_contains(text, "zystem") ||
             ci_contains(text, "zcc") || ci_contains(text, "mpm") ||
             ci_contains(text, "ndr") || ci_contains(text, "zde") ||
             ci_contains(text, "zsm") || ci_contains(text, "ld80") ||
             ci_contains(text, "m80") || ci_contains(text, "mac80") ||
             ci_contains(text, "slr") || ci_contains(text, "dz80") ||
             ci_contains(text, "z80dis") ||
             ci_contains(text, "zsid") || ci_contains(text, "ddtz") ||
             ci_contains(text, "ddt") || ci_contains(text, "tvz80") ||
             ci_contains(text, "sio2bsd") || ci_contains(text, "aspeqt") ||
             ci_contains(text, "respeqt") || ci_contains(text, "altirra")) {
        what = "cpm/atari primitive";
        } else if (
             /* cycle-360b: mainframe/mcu primitives */
             (ci_contains(text, "hercules") && ci_contains(text, " -")) ||
             ci_contains(text, "hercules4") || ci_contains(text, "softmain") ||
             ci_contains(text, "dmk2") || ci_contains(text, "cc64") ||
             ci_contains(text, "dasdcat") || ci_contains(text, "dasdseq") ||
             ci_contains(text, "dasdconv") || ci_contains(text, "dasdisup") ||
             ci_contains(text, "dasdmso") || ci_contains(text, "dasdnab") ||
             ci_contains(text, "dasdpds") || ci_contains(text, "dasdtab") ||
             ci_contains(text, "dasdtr") || ci_contains(text, "dasdview") ||
             ci_contains(text, "hetmap") || ci_contains(text, "hetupd") ||
             ci_contains(text, "hettape") || ci_contains(text, "hetins") ||
             ci_contains(text, "vma") || ci_contains(text, "vmfplc2") ||
             (ci_contains(text, "cbt") && ci_contains(text, " -")) ||
             ci_contains(text, "tape2card") || ci_contains(text, "cardimg") ||
             ci_contains(text, "mpio") || ci_contains(text, "espmon") ||
             ci_contains(text, "stm8gal") || ci_contains(text, "stm8sdiscovery") ||
             ci_contains(text, "sdas") || ci_contains(text, "s51") ||
             ci_contains(text, "ucsim") || ci_contains(text, "shc") ||
             ci_contains(text, "sdcpp") || ci_contains(text, "sdar") ||
             ci_contains(text, "sdnm") || ci_contains(text, "sdranlib")) {
        what = "mainframe/mcu primitive";
        } else if (
             /* cycle-361a: browser/mail primitives */
             (ci_contains(text, "links") && ci_contains(text, " -")) ||
             ci_contains(text, "w3m") || ci_contains(text, "netrik") ||
             ci_contains(text, "retawq") || ci_contains(text, "conkeror") ||
             (ci_contains(text, "surf") && ci_contains(text, " -")) ||
             ci_contains(text, "badwolf") ||
             (ci_contains(text, "dillo") && ci_contains(text, " -")) ||
             ci_contains(text, "hv3") || ci_contains(text, "dooble") ||
             (ci_contains(text, "amaya") && ci_contains(text, " -")) ||
             (ci_contains(text, "mosaic") && ci_contains(text, " -")) ||
             (ci_contains(text, "arena") && ci_contains(text, " -")) ||
             ci_contains(text, "gzilla") || ci_contains(text, "skipstone") ||
             ci_contains(text, "hotjava") ||
             (ci_contains(text, "alpine") && ci_contains(text, " -")) ||
             (ci_contains(text, "elm") && ci_contains(text, " -")) ||
             (ci_contains(text, "pine ") && ci_contains(text, " -")) ||
             ci_contains(text, "kmail") || ci_contains(text, "balsa") ||
             (ci_contains(text, "mahogany") && ci_contains(text, " -")) ||
             (ci_contains(text, "mh") && ci_contains(text, " -")) ||
             (ci_contains(text, "mew") && ci_contains(text, " -")) ||
             ci_contains(text, "gnus") || ci_contains(text, "hego") ||
             ci_contains(text, "deadcyber") ||
             ci_contains(text, "mu4e") ||
             (ci_contains(text, "nail") && ci_contains(text, " -"))) {
        what = "browser/mail primitive";
        } else if (
             /* cycle-361b: tunnel/vpn primitives */
             ci_contains(text, "bcrelay") ||
             (ci_contains(text, "chat") && ci_contains(text, " -")) ||
             (ci_contains(text, "poff") && ci_contains(text, " -")) ||
             ci_contains(text, "l2tpd") ||
             (ci_contains(text, "whack") && ci_contains(text, " -")) ||
             ci_contains(text, "pki ") || ci_contains(text, "libreswan")) {
        what = "tunnel/vpn primitive";
        } else if (
             /* cycle-362a: screencast/vcs-old primitives */
             ci_contains(text, "asciicast") ||
             (ci_contains(text, "agg") && ci_contains(text, " -")) ||
             (ci_contains(text, "trec") && ci_contains(text, " -")) ||
             ci_contains(text, "tty2gif") ||
             ci_contains(text, "vttest") || ci_contains(text, "tilda") ||
             ci_contains(text, "yakuake") || ci_contains(text, "zutty") ||
             ci_contains(text, "sccs") ||
             (ci_contains(text, "rcs") && ci_contains(text, " -")) ||
             (ci_contains(text, "ident") && ci_contains(text, " -")) ||
             (ci_contains(text, "merge ") && ci_contains(text, " -")) ||
             ci_contains(text, "rcs2sccs") || ci_contains(text, "sccs2rcs") ||
             ci_contains(text, "prcs") || ci_contains(text, "cvu") ||
             (ci_contains(text, "rview") && ci_contains(text, " -")) ||
             ci_contains(text, "chora ")) {
        what = "screencast/vcs primitive";
        } else if (
             /* cycle-362b: versioning primitives */
             ci_contains(text, "reposurgeon") || ci_contains(text, "viewvc") ||
             ci_contains(text, "brz") || ci_contains(text, "bk ") ||
             ci_contains(text, "bitkeeper") ||
             (ci_contains(text, "aegis") && ci_contains(text, " -")) ||
             ci_contains(text, "cm3")) {
        what = "versioning primitive";
        } else if (
             /* cycle-363a: container/k8s ecosystem primitives */
             ci_contains(text, "youki") || ci_contains(text, "kubecolor") ||
             ci_contains(text, "kubetail") || ci_contains(text, "audit2rbac") ||
             ci_contains(text, "buildpacks") ||
             (ci_contains(text, "jib") && ci_contains(text, " -")) ||
             ci_contains(text, "buildg") || ci_contains(text, "direnv")) {
        what = "container/k8s primitive";
        } else if (
             /* cycle-363b: sdr/radio + imaging primitives */
             ci_contains(text, "freedv") || ci_contains(text, "quisk") ||
             ci_contains(text, "fr24feed") || ci_contains(text, "piaware") ||
             ci_contains(text, "soapy_power") || ci_contains(text, "rtl_power") ||
             ci_contains(text, "uat2esnt") ||
             (ci_contains(text, "pidgin") && ci_contains(text, " -")) ||
             (ci_contains(text, "finch") && ci_contains(text, " -")) ||
             ci_contains(text, "jpeginfo") || ci_contains(text, "mozjpeg") ||
             ci_contains(text, "libheif") || ci_contains(text, "autotrace") ||
             ci_contains(text, "mkbitmap") || ci_contains(text, "vpype") ||
             ci_contains(text, "vtracer") || ci_contains(text, "resvg") ||
             ci_contains(text, "usvg") ||
             (ci_contains(text, "scour") && ci_contains(text, " -")) ||
             ci_contains(text, "librsvg") || ci_contains(text, "svglib") ||
             ci_contains(text, "cpdf") || ci_contains(text, "ocropus") ||
             ci_contains(text, "ddjvu") || ci_contains(text, "djview") ||
             ci_contains(text, "djvups") || ci_contains(text, "b2pdf")) {
        what = "sdr/imaging primitive";
        } else if (
             /* cycle-364a: password-gen/math/audio primitives */
             ci_contains(text, "diceware") ||
             (ci_contains(text, "reveal") && ci_contains(text, " -")) ||
             ci_contains(text, "hqapgen") || ci_contains(text, "yacas") ||
             ci_contains(text, "giac") || ci_contains(text, "ovito") ||
             ci_contains(text, "ecasound") || ci_contains(text, "pianobar") ||
             ci_contains(text, "mp4tags") || ci_contains(text, "atomicparsley") ||
             ci_contains(text, "mp3gain") || ci_contains(text, "vorbisgain") ||
             ci_contains(text, "aacgain") || ci_contains(text, "streamlink")) {
        what = "pwgen/audio primitive";
        } else if (
             /* cycle-364b: hdl/dns/io primitives */
             ci_contains(text, "ghdl") || ci_contains(text, "avrisp2") ||
             ci_contains(text, "stk500") || ci_contains(text, "dlint") ||
             ci_contains(text, "dnswalk") || ci_contains(text, "hatop") ||
             ci_contains(text, "mbuffer") || ci_contains(text, "unlzma") ||
             ci_contains(text, "lzstatic")) {
        what = "hdl/dns primitive";
        } else if (
             /* cycle-365a: lsp/formatter/lint primitives */
             ci_contains(text, "pyright") ||
             (ci_contains(text, "sorbet") && ci_contains(text, " -")) ||
             (ci_contains(text, "vale") && ci_contains(text, " -")) ||
             ci_contains(text, "mdl ") || ci_contains(text, "dprint") ||
             (ci_contains(text, "biome") && ci_contains(text, " -")) ||
             (ci_contains(text, "selene") && ci_contains(text, " -")) ||
             ci_contains(text, "hindent") ||
             (ci_contains(text, "brittany") && ci_contains(text, " -")) ||
             ci_contains(text, "uncrustify") || ci_contains(text, "astyle") ||
             ci_contains(text, "unifdef") ||
             (ci_contains(text, "indent") && ci_contains(text, " -"))) {
        what = "lsp/lint primitive";
        } else if (
             /* cycle-365b: jvm/db/imaging-ps primitives */
             ci_contains(text, "hsdb") || ci_contains(text, "clhsdb") ||
             ci_contains(text, "arthas") || ci_contains(text, "ecj ") ||
             ci_contains(text, "gcj ") || ci_contains(text, "javadoc") ||
             ci_contains(text, "javah") || ci_contains(text, "serialver") ||
             ci_contains(text, "tnameserv") || ci_contains(text, "sqldiff") ||
             ci_contains(text, "pgbadger") || ci_contains(text, "patroni") ||
             ci_contains(text, "etcdutl") || ci_contains(text, "docuum") ||
             ci_contains(text, "leanify") || ci_contains(text, "nconvert") ||
             ci_contains(text, "irfanview") || ci_contains(text, "imv ") ||
             ci_contains(text, "pqiv") ||
             (ci_contains(text, "banner") && ci_contains(text, " -")) ||
             ci_contains(text, "grops") || ci_contains(text, "ps2ascii") ||
             ci_contains(text, "psbook") || ci_contains(text, "psselect") ||
             ci_contains(text, "includeres")) {
        what = "jvm/print primitive";
        } else if (
             /* cycle-366a: ebpf/mq/infra primitives */
             ci_contains(text, "tcpsubnet") || ci_contains(text, "tcprtt") ||
             ci_contains(text, "nfsslower") || ci_contains(text, "pidpersec") ||
             ci_contains(text, "emqtt_bench") || ci_contains(text, "unitd") ||
             (ci_contains(text, "heartbeat") && ci_contains(text, " -"))) {
        what = "ebpf/infra primitive";
        } else if (
             /* cycle-366b: build/sysadmin primitives */
             ci_contains(text, "earthfile") || ci_contains(text, "tupconf") ||
             ci_contains(text, "debtap") ||
             (ci_contains(text, "snooze") && ci_contains(text, " -")) ||
             ci_contains(text, "cronie") || ci_contains(text, "hcron") ||
             ci_contains(text, "firemon") || ci_contains(text, "jk_check") ||
             ci_contains(text, "jk_cp") || ci_contains(text, "jk_list") ||
             ci_contains(text, "jk_lsh") || ci_contains(text, "jk_socketd") ||
             ci_contains(text, "debuerreotype") || ci_contains(text, "polystrap") ||
             ci_contains(text, "cowdancer")) {
        what = "build/sysadmin primitive";
        } else if (
             /* cycle-367a: firmware/tpm/sanitizer primitives */
             ci_contains(text, "amidecbin") || ci_contains(text, "acpihelp") ||
             ci_contains(text, "acpinames") || ci_contains(text, "acpisrc") ||
             ci_contains(text, "tss2_list") ||
             (ci_contains(text, "trousers") && ci_contains(text, " -")) ||
             ci_contains(text, "bochscov") || ci_contains(text, "kcov") ||
             ci_contains(text, "asan_symbolize") || ci_contains(text, "sanstats") ||
             ci_contains(text, "hwasan_symbolize")) {
        what = "firmware/sanitizer primitive";
        } else if (
             /* cycle-367b: forensics/disk primitives */
             ci_contains(text, "reglookup") || ci_contains(text, "rip.pl") ||
             ci_contains(text, "hashdb") || ci_contains(text, "affuse") ||
             ci_contains(text, "affverify") || ci_contains(text, "affcompare") ||
             ci_contains(text, "affsegment") || ci_contains(text, "fcadm") ||
             ci_contains(text, "affstats") || ci_contains(text, "affrecover") ||
             ci_contains(text, "ddrutility") || ci_contains(text, "hdparam")) {
        what = "forensics/disk primitive";
        } else if (
             /* cycle-368a: dict/docs/ebook primitives */
             (ci_contains(text, "dict_lookup") && ci_contains(text, " -")) ||
             ci_contains(text, "colorit") || ci_contains(text, "munchlist") ||
             ci_contains(text, "ispellaff2myspell") || ci_contains(text, "unmunch") ||
             ci_contains(text, "licq") || ci_contains(text, "qrenc") ||
             ci_contains(text, "doifetch") || ci_contains(text, "bcnc") ||
             ci_contains(text, "epubs2") || ci_contains(text, "mobi2epub") ||
             ci_contains(text, "cbconvert") || ci_contains(text, "comic2pdf") ||
             ci_contains(text, "pdftoepub")) {
        what = "dict/ebook primitive";
        } else if (
             /* cycle-368b: cnc/media primitives */
             (ci_contains(text, "candle") && ci_contains(text, " -")) ||
             ci_contains(text, "mid3iconv") ||
             (ci_contains(text, "operon") && ci_contains(text, " -")) ||
             (ci_contains(text, "sonata") && ci_contains(text, " -")) ||
             ci_contains(text, "ncmpc") || ci_contains(text, "msdap") ||
             ci_contains(text, "gmpc") || ci_contains(text, "mpdris2")) {
        what = "cnc/media primitive";
        } else if (
             /* cycle-369a: x11-font/voip primitives */
             ci_contains(text, "showfont") || ci_contains(text, "mkfontdir") ||
             ci_contains(text, "mkfontscale") || ci_contains(text, "ucs2any") ||
             ci_contains(text, "slimlock") || ci_contains(text, "fdupe") ||
             ci_contains(text, "percol") || ci_contains(text, "heplify") ||
             ci_contains(text, "dahdi_pcap") || ci_contains(text, "dahdihdrc") ||
             ci_contains(text, "sipreg")) {
        what = "x11/voip primitive";
        } else if (
             /* cycle-369b: bibliography/pub primitives */
             ci_contains(text, "bib2ris") || ci_contains(text, "cb2bib") ||
             ci_contains(text, "biblioref") || ci_contains(text, "doi2bib") ||
             ci_contains(text, "pubfetch") || ci_contains(text, "tcoffee") ||
             (ci_contains(text, "prank") && ci_contains(text, " -")) ||
             ci_contains(text, "paga") || ci_contains(text, "fyrd") ||
             ci_contains(text, "org2pdf") || ci_contains(text, "cpif") ||
             ci_contains(text, "nuweb") || ci_contains(text, "funnelweb") ||
             (ci_contains(text, "zettel") && ci_contains(text, " -")) ||
             (ci_contains(text, "cider") && ci_contains(text, " -")) ||
             ci_contains(text, "notenik") || ci_contains(text, "11ty")) {
        what = "biblio/pub primitive";
        } else if (
             /* cycle-370a: crystallography primitives */
             ci_contains(text, "crystfel") || ci_contains(text, "ambigator") ||
             ci_contains(text, "process_hkl") || ci_contains(text, "partialator") ||
             (ci_contains(text, "whirligig") && ci_contains(text, " -")) ||
             ci_contains(text, "refmac5") ||
             (ci_contains(text, "buccaneer") && ci_contains(text, " -")) ||
             ci_contains(text, "freerflag") || ci_contains(text, "fit2d") ||
             (ci_contains(text, "fabio") && ci_contains(text, " -")) ||
             ci_contains(text, "dioptas")) {
        what = "crystallography primitive";
        } else if (
             /* cycle-370b: chemistry/materials primitives */
             ci_contains(text, "moltemplate") || ci_contains(text, "topolbuild") ||
             ci_contains(text, "mrgddb") || ci_contains(text, "abicheck") ||
             ci_contains(text, "conducti") || ci_contains(text, "critic2") ||
             (ci_contains(text, "bader") && ci_contains(text, " -")) ||
             ci_contains(text, "dftd3") || ci_contains(text, "wan2resu") ||
             ci_contains(text, "postw90") || ci_contains(text, "wannier_plot") ||
             ci_contains(text, "cif_filter") || ci_contains(text, "cif_select") ||
             ci_contains(text, "doschka") || ci_contains(text, "raster3d") ||
             (ci_contains(text, "balls") && ci_contains(text, " -")) ||
             (ci_contains(text, "sticks") && ci_contains(text, " -"))) {
        what = "chemistry primitive";
        }

        if (what) {
            v.signals |= PASTE_WINDOWS_LOLBIN;
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
        /* nc / ncat / netcat reverse shell: nc -e / -c or mkfifo pipe */
        if (!is_revshell && !strstr(text, "sync") &&
            (strstr(text, "nc ") || strstr(text, "ncat ") ||
             strstr(text, "netcat ")) &&
            (strstr(text, " -e ") || strstr(text, " -c ") ||
             strstr(text, "--exec") ||
             strstr(text, "--sh-exec") || strstr(text, "mkfifo")))
            is_revshell = 1;
        /* telnet | sh — the double-telnet data-exfil shell */
        if (!is_revshell && ci_contains(text, "telnet") &&
            (strstr(text, "|sh") || strstr(text, "| sh") ||
             strstr(text, "/bin/sh") || strstr(text, "sh -i")))
            is_revshell = 1;
        /* ruby TCPSocket / perl -M module-load socket shells */
        if (!is_revshell && strstr(text, "TCPSocket") &&
            (strstr(text, "popen") || strstr(text, "exec") ||
             strstr(text, "system(") || strstr(text, "dup2")))
            is_revshell = 1;
        if (!is_revshell && strstr(text, "perl -M") &&
            strstr(text, "IO::Socket"))
            is_revshell = 1;
        /* powershell socket object: New-Object *Sockets* */
        if (!is_revshell && strstr(text, "New-Object") &&
            strstr(text, "Sockets"))
            is_revshell = 1;
        /* Python socket reverse shell */
        if (!is_revshell &&
            (strstr(text, "socket.") || strstr(text, "connect(")) &&
            (strstr(text, "subprocess") || strstr(text, "os.dup2") ||
             strstr(text, "pty.spawn")))
            is_revshell = 1;
        /* socat reverse shell — address keywords are case-insensitive */
        if (!is_revshell &&
            ci_contains(text, "socat") &&
            (ci_contains(text, "exec:") || ci_contains(text, "tcp:") ||
             ci_contains(text, "tcp4:") || ci_contains(text, "tcp6:") ||
             ci_contains(text, "tcp-l")))
            is_revshell = 1;
        /* php/perl one-liner reverse shells: fsockopen/socket → exec */
        if (!is_revshell &&
            (strstr(text, "php -r") || strstr(text, "perl -e")) &&
            (strstr(text, "fsockopen") || strstr(text, "socket_create") ||
             strstr(text, "IO::Socket")))
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
    /* Reasons may quote pasted text; sanitise display-hostile bytes. */
    {
        int i;
        for (i = 0; i < v.n_reasons; i++)
            hlse_sanitize_display(v.reasons[i]);
    }
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
    /* Reasons embed hostnames read from attacker-writable system state. */
    {
        int i;
        for (i = 0; i < v.n_reasons; i++)
            hlse_sanitize_display(v.reasons[i]);
    }
    return v;
}
