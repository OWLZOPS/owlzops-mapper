# R27-26: CI gate against doctrine drift (env mutations, unsafe fd handling)
#!/usr/bin/env bash
set -euo pipefail

fail=0

# R27-14: environment mutation is allowed only in the pre-runtime scrub.
hits=$(rg -n --pcre2 'env::(set|remove)_var' src/ \
       | rg -v '^src/ssh_engine\.rs:' || true)
if [ -n "$hits" ]; then
  echo "::error::env::set_var/remove_var outside src/ssh_engine.rs (R27-14)"
  echo "$hits"
  fail=1
fi

# R27-13/R27-14: startup scrub must be present in main.
rg -q 'take_sudo_pass_from_environ' src/main.rs || {
  echo "::error::startup environ scrub missing from main (R27-13/R27-14)"
  fail=1
}

# R27-17: SecretString must have a manual redacting Debug.
rg -q 'impl std::fmt::Debug for SecretString' src/secrets.rs || {
  echo "::error::SecretString needs a manual redacting Debug (R27-17)"
  fail=1
}

# R27-18: from_raw_fd must not silently take ownership of a borrowed fd.
raw=$(rg -n 'from_raw_fd' src/ | rg -v 'ManuallyDrop|OwnedFd' || true)
if [ -n "$raw" ]; then
  echo "::error::from_raw_fd without ManuallyDrop/OwnedFd (R27-18)"
  echo "$raw"
  fail=1
fi

exit $fail