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
        strstr(text, "/etc/passwd")) {
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
          strstr(text, "/etc/zshenv"))) ||
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
                    (ci_contains(text, " -i") || ci_contains(text, " -U"))) ||
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
                   ci_contains(text, "init S") || ci_contains(text, "telinit 1") ||
                   ci_contains(text, "telinit s") || ci_contains(text, "telinit S") ||
                   ci_contains(text, "reboot -") || ci_contains(text, "reboot now") ||
                   ci_contains(text, "poweroff -") || ci_contains(text, "halt -") ||
                   (ci_contains(text, "shutdown") &&
                    (ci_contains(text, " -h") || ci_contains(text, " -H") ||
                     ci_contains(text, " -P") || ci_contains(text, " -r")))) {
            what = "service/runlevel/power primitive";
        } else if (ci_contains(text, "userdel ") || ci_contains(text, "groupdel ") ||
                   (ci_contains(text, "gpasswd") &&
                    (ci_contains(text, " -a") || ci_contains(text, " -d") ||
                     ci_contains(text, " -A") || ci_contains(text, " -M"))) ||
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
                     ci_contains(text, " -d") || ci_contains(text, " -B"))) ||
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
                    (ci_contains(text, " -i") || ci_contains(text, " -I") ||
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
                     ci_contains(text, " -D"))) ||
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
                   ci_contains(text, "linenum") ||
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
                   (ci_contains(text, "oc") &&
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
