#!/bin/bash
# Generate jbroot_transformed + trust manifest from Procursus bootstrap tars (out-of-tree).
set -euo pipefail
SCRIPT="$(cd "$(dirname "$0")" && pwd -P)"
# shellcheck source=../source/scripts/clean_project_env.sh
source "$SCRIPT/../source/scripts/clean_project_env.sh"

bash "$SCRIPT/extract_bootstrap_inputs.sh"
bash "$SCRIPT/../source/scripts/pack_tools_ldid.sh"

export DT_WORKSPACE_ROOT DT_BUILD_ROOT
PY="$DT_TOOLS_ROOT"

python3 "$PY/rootless_macho_transform.py"
python3 "$PY/rootless_bootstrap_enrichment.py"
python3 "$PY/rootless_finalize_payload.py"
python3 "$PY/rootless_add_dest_libiosexec_rpath.py" "$DT_BUILD_ROOT/work/jbroot_transformed" --patch-only
python3 "$PY/rootless_sign_trust.py"
python3 "$PY/rootless_oracle_layer1_swap.py"
python3 "$PY/rootless_prep_bootstrap.py"
python3 "$PY/rootless_r23_postlogin_prep.py"

echo "BOOTSTRAP_GENERATION=PASS tree=$DT_BUILD_ROOT/work/jbroot_transformed"
echo "TRUST_MANIFEST=$DT_BUILD_ROOT/artifacts/ROOTLESS_R4_FINAL_TRUST_MANIFEST.tsv"
