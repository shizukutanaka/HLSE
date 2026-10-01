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
        strstr(text, "mkfs.") || strstr(text, "dd if=") ||
        strstr(text, "shred ") || strstr(text, "> /dev/sd") ||
        strstr(text, "chmod -R 777") || strstr(text, "chmod -R 777 /")) {
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
        strstr(text, "/etc/passwd")) {
        v.signals |= PASTE_CRED_ACCESS;
        v.score += 40;
        if (v.n_reasons < HLSE_PASTE_MAX_REASONS)
            snprintf(v.reasons[v.n_reasons++], sizeof(v.reasons[0]),
                "P10: Credential/key file access — private key, cloud "
                "creds, or auth database read (pre-exfiltration)");
    }

    /* P11: Persistence writes — appending to rc/config/ssh/crontab
     * installs the payload to run on every login */
    if ((strstr(text, ">>") || strstr(text, "echo ") ||
         strstr(text, "crontab") || strstr(text, "at now") ||
         strstr(text, "systemctl enable") || strstr(text, "launchctl load")) &&
        (strstr(text, ".bashrc") || strstr(text, ".zshrc") ||
         strstr(text, ".profile") || strstr(text, "authorized_keys") ||
         strstr(text, "crontab") || strstr(text, "systemctl enable") ||
         strstr(text, "launchctl") || strstr(text, "rc.local") ||
         strstr(text, ".xinitrc") || strstr(text, ".zshenv"))) {
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
         strstr(text, "tftp ")) &&
        (strstr(text, "&& bash") || strstr(text, "&& sh") ||
         strstr(text, "&& chmod") || strstr(text, "&& sudo") ||
         strstr(text, "&& ./") ||
         strstr(text, "; bash") || strstr(text, "; sh") ||
         strstr(text, "; chmod") || strstr(text, "; sudo"))) {
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
                    ci_contains(text, "yarn add") ||
                    ci_contains(text, "gem install")) &&
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
                   (ci_contains(text, "-d") || ci_contains(text, "-D"))) {
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
                    ci_contains(text, "-t nat") || ci_contains(text, "masquerade") ||
                    ci_contains(text, "dnat"))) {
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
                   ci_contains(text, "linenum") || ci_contains(text, "mimipenguin") ||
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
            (strstr(text, " -e ") || strstr(text, "--exec") ||
             strstr(text, "--sh-exec") || strstr(text, "mkfifo")))
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
