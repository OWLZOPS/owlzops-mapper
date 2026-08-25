#!/usr/bin/env bash
set -euo pipefail

# Allow env manipulation only in ssh_engine.rs (scrub module)
if rg -n --pcre2 'std::env::(set_var|remove_var)' src/ | rg -v 'src/ssh_engine\.rs'; then
  echo "ERROR: env::set_var/remove_var outside ssh_engine.rs is forbidden (doctrine drift)"
  exit 1
fi

echo "env-var gate passed"