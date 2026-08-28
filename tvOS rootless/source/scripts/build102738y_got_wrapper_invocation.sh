#!/bin/bash
set -euo pipefail

PROJECT="$(cd "$(dirname "$0")/.." && pwd -P)"
PERSISTENT_Z="${DT_BUILD102738Z_PERSISTENT_HOOK:-0}"
OBSERVER_A="${DT_BUILD102739A_OBSERVER_HOOK:-0}"
OBSERVER_B="${DT_BUILD102739B_RETURN_OBSERVER_HOOK:-0}"
OBSERVER_C="${DT_BUILD102739C_OUTPUT_CONTRACT_OBSERVER_HOOK:-0}"
OBSERVER_E="${DT_BUILD102739E_DICTIONARY_CLASSIFIER_HOOK:-0}"
OBSERVER_F="${DT_BUILD102739F_CALLER_IDENTITY_HOOK:-0}"
OBSERVER_G="${DT_BUILD102739G_DOMAIN_ACTION_RESOLUTION_HOOK:-0}"
OBSERVER_H="${DT_BUILD102739H_ARGUMENT_MARSHALLING_HOOK:-0}"
OBSERVER_I="${DT_BUILD102739I_CONTROLLED_HANDLER_ABI_HOOK:-0}"
OBSERVER_J="${DT_BUILD102739J_CONTROLLED_REPLY_ROUNDTRIP_HOOK:-0}"
INPUT="$PROJECT/build/102738R/Handoff516"
INPUT_FW="$PROJECT/build/102738R/Frameworks/libjailbreak.dylib"
BUILD_ROOT="${DT_BUILD_OUTPUT_ROOT:-$PROJECT/build/102738Y}"
OUT="$BUILD_ROOT/Handoff516"
FW_OUT="$BUILD_ROOT/Frameworks"
OBJ="$BUILD_ROOT/obj/hook"
MIN="$PROJECT/handoff516/source/launchdhook/minimal"
THEOS_ROOT="${THEOS:-$HOME/theos}"
SDK="${TVOS_SYSROOT:-$THEOS_ROOT/sdks/AppleTVOS16.4.sdk}"
CC=(xcrun -sdk appletvos clang)
TVOS_MIN=14.0

expect_sha() {
    local path="$1" expected="$2" got
    got="$(shasum -a 256 "$path" | awk '{print $1}')"
    [[ "$got" == "$expected" ]] || {
        echo "SHA256 mismatch: $path" >&2
        echo "  expected $expected" >&2
        echo "  got      $got" >&2
        exit 1
    }
}

[[ -d "$INPUT" ]] || { echo "ERROR: missing frozen BUILD102738R handoff: $INPUT" >&2; exit 1; }
[[ -f "$INPUT_FW" ]] || { echo "ERROR: missing frozen BUILD102738R framework: $INPUT_FW" >&2; exit 1; }
[[ -d "$SDK" ]] || { echo "ERROR: missing AppleTVOS SDK: $SDK" >&2; exit 1; }

expect_sha "$INPUT/dt_jbctl516" "6fcede5b98ee244106b9bc0b64e9da94fb3464e0bfe671f53a99485ee466c067"
expect_sha "$INPUT/dt_opainject516" "0b7dcd9c7258d33e347c94258b57817d0a04fc163af855d3b21499598f6b48fb"
expect_sha "$INPUT/entitlements_launchdhook681.plist" "4d63822e924c55eae1c862dbebfe8a8c2270a915f72efd6b9276a434892e014b"
expect_sha "$INPUT/libchoma.dylib" "40ee6f87dcca7af63a8be1e9e185ff74ae2046cb97c3aa2405c6af6f29ae586b"
expect_sha "$INPUT/libjailbreak.dylib" "0ec9129c2b37c952794b4dd33efd5d5e2b9062cc72cf990947662baf3c519754"
expect_sha "$INPUT_FW" "b4f4ba62330f1637c26421c9b55c395392b156018148d321b0c3fc995e2672f0"

rm -rf "$OUT" "$FW_OUT" "$OBJ"
mkdir -p "$OUT" "$FW_OUT" "$OBJ"
cp -R "$INPUT/." "$OUT/"
cp "$INPUT_FW" "$FW_OUT/libjailbreak.dylib"
rm -f "$OUT/launchdhook516.dylib" "$OUT/hook_build_manifest.txt" \
  "$OUT"/BUILD102738*_RESOURCE_MANIFEST.txt

INC=(
  -I"$PROJECT/handoff516/source/libjailbreak/client"
  -I"$PROJECT/handoff516/source/include/libjailbreak"
  -I"$PROJECT/handoff516/source/include/external"
)
HOOK_CFLAGS=(
  -arch arm64 -isysroot "$SDK" -mtvos-version-min="$TVOS_MIN" -O2
  -Wno-error -fPIC -fobjc-arc
  -DDT_BUILD102732C_TELEMETRY=1
  -DDT_BUILD102735D_TRACE=1
  -DDT_BUILD102737D_TELEMETRY=1
  -DDT_BUILD102738P_TELEMETRY=1
  -DDT_BUILD102738Y_TELEMETRY=1
  "${INC[@]}"
)

if [[ "$PERSISTENT_Z" == "1" ]]; then
  HOOK_CFLAGS+=( -DDT_BUILD102738Z_PERSISTENT=1 )
fi
if [[ "$OBSERVER_A" == "1" ]]; then
  HOOK_CFLAGS+=( -DDT_BUILD102739A_OBSERVER=1 )
fi
if [[ "$OBSERVER_B" == "1" ]]; then
  HOOK_CFLAGS+=( -DDT_BUILD102739B_RETURN_OBSERVER=1 )
fi
if [[ "$OBSERVER_C" == "1" ]]; then
  HOOK_CFLAGS+=( -DDT_BUILD102739C_OUTPUT_CONTRACT_OBSERVER=1 )
fi
if [[ "$OBSERVER_E" == "1" ]]; then
  HOOK_CFLAGS+=( -DDT_BUILD102739E_DICTIONARY_CLASSIFIER=1 )
fi
if [[ "$OBSERVER_J" == "1" ]]; then
  REQUIRED_MARKERS=(
    '.dt102737_constructor_trace'
    'BUILD102738Z_PROBE_ENTER'
    'BUILD102739J_PROBE_ENTER'
    'BUILD102739J_SCOPE_CONTROLLED_REPLY_ROUNDTRIP'
    'BUILD102739_IDENTITY_TELEMETRY_EXPORTED_YES'
    'BUILD102738Z_COUNTING_WRAPPER_IMPLEMENTED_YES'
    'BUILD102738Z_PERSISTENT_INSTALL_IMPLEMENTED_YES'
    'GOT_WRAPPER_INSTALL_PASS'
    'GOT_WRAPPER_PERSISTENT_INSTALL_PASS'
    'GOT_PROTECTION_RESTORE_PASS'
    'GOT_PROTECTION_RESTORE_FATAL'
  )
elif [[ "$OBSERVER_I" == "1" ]]; then
  REQUIRED_MARKERS=(
    '.dt102737_constructor_trace'
    'BUILD102738Z_PROBE_ENTER'
    'BUILD102739I_PROBE_ENTER'
    'BUILD102739I_SCOPE_CONTROLLED_ACTION_HANDLER_ABI'
    'BUILD102739_IDENTITY_TELEMETRY_EXPORTED_YES'
    'BUILD102738Z_COUNTING_WRAPPER_IMPLEMENTED_YES'
    'BUILD102738Z_PERSISTENT_INSTALL_IMPLEMENTED_YES'
    'GOT_WRAPPER_INSTALL_PASS'
    'GOT_WRAPPER_PERSISTENT_INSTALL_PASS'
    'GOT_PROTECTION_RESTORE_PASS'
    'GOT_PROTECTION_RESTORE_FATAL'
  )
elif [[ "$OBSERVER_H" == "1" ]]; then
  REQUIRED_MARKERS=(
    '.dt102737_constructor_trace'
    'BUILD102738Z_PROBE_ENTER'
    'BUILD102739H_PROBE_ENTER'
    'BUILD102739H_SCOPE_READ_ONLY_ACTION_ARGUMENT_MARSHALLING'
    'BUILD102739_IDENTITY_TELEMETRY_EXPORTED_YES'
    'BUILD102738Z_COUNTING_WRAPPER_IMPLEMENTED_YES'
    'BUILD102738Z_PERSISTENT_INSTALL_IMPLEMENTED_YES'
    'GOT_WRAPPER_INSTALL_PASS'
    'GOT_WRAPPER_PERSISTENT_INSTALL_PASS'
    'GOT_PROTECTION_RESTORE_PASS'
    'GOT_PROTECTION_RESTORE_FATAL'
  )
elif [[ "$OBSERVER_G" == "1" ]]; then
  REQUIRED_MARKERS=(
    '.dt102737_constructor_trace'
    'BUILD102738Z_PROBE_ENTER'
    'BUILD102739G_PROBE_ENTER'
    'BUILD102739G_SCOPE_READ_ONLY_DOMAIN_PERMISSION_ACTION_RESOLUTION'
    'BUILD102739_IDENTITY_TELEMETRY_EXPORTED_YES'
    'BUILD102738Z_COUNTING_WRAPPER_IMPLEMENTED_YES'
    'BUILD102738Z_PERSISTENT_INSTALL_IMPLEMENTED_YES'
    'GOT_WRAPPER_INSTALL_PASS'
    'GOT_WRAPPER_PERSISTENT_INSTALL_PASS'
    'GOT_PROTECTION_RESTORE_PASS'
    'GOT_PROTECTION_RESTORE_FATAL'
  )
elif [[ "$OBSERVER_F" == "1" ]]; then
  HOOK_CFLAGS+=( -DDT_BUILD102739E_DICTIONARY_CLASSIFIER=1 )
  HOOK_CFLAGS+=( -DDT_BUILD102739F_CALLER_IDENTITY=1 )
fi
if [[ "$OBSERVER_J" == "1" ]]; then
  HOOK_CFLAGS+=( -DDT_BUILD102739E_DICTIONARY_CLASSIFIER=1 )
  HOOK_CFLAGS+=( -DDT_BUILD102739F_CALLER_IDENTITY=1 )
  HOOK_CFLAGS+=( -DDT_BUILD102739G_DOMAIN_ACTION_RESOLUTION=1 )
  HOOK_CFLAGS+=( -DDT_BUILD102739H_ARGUMENT_MARSHALLING=1 )
  HOOK_CFLAGS+=( -DDT_BUILD102739I_CONTROLLED_HANDLER_ABI=1 )
  HOOK_CFLAGS+=( -DDT_BUILD102739J_CONTROLLED_REPLY_ROUNDTRIP=1 )
elif [[ "$OBSERVER_I" == "1" ]]; then
  HOOK_CFLAGS+=( -DDT_BUILD102739E_DICTIONARY_CLASSIFIER=1 )
  HOOK_CFLAGS+=( -DDT_BUILD102739F_CALLER_IDENTITY=1 )
  HOOK_CFLAGS+=( -DDT_BUILD102739G_DOMAIN_ACTION_RESOLUTION=1 )
  HOOK_CFLAGS+=( -DDT_BUILD102739H_ARGUMENT_MARSHALLING=1 )
  HOOK_CFLAGS+=( -DDT_BUILD102739I_CONTROLLED_HANDLER_ABI=1 )
elif [[ "$OBSERVER_H" == "1" ]]; then
  HOOK_CFLAGS+=( -DDT_BUILD102739E_DICTIONARY_CLASSIFIER=1 )
  HOOK_CFLAGS+=( -DDT_BUILD102739F_CALLER_IDENTITY=1 )
  HOOK_CFLAGS+=( -DDT_BUILD102739G_DOMAIN_ACTION_RESOLUTION=1 )
  HOOK_CFLAGS+=( -DDT_BUILD102739H_ARGUMENT_MARSHALLING=1 )
elif [[ "$OBSERVER_G" == "1" ]]; then
  HOOK_CFLAGS+=( -DDT_BUILD102739E_DICTIONARY_CLASSIFIER=1 )
  HOOK_CFLAGS+=( -DDT_BUILD102739F_CALLER_IDENTITY=1 )
  HOOK_CFLAGS+=( -DDT_BUILD102739G_DOMAIN_ACTION_RESOLUTION=1 )
fi

if [[ "$OBSERVER_J" == "1" ]]; then
  echo "=== BUILD102739J controlled reply roundtrip ==="
elif [[ "$OBSERVER_I" == "1" ]]; then
  echo "=== BUILD102739I controlled action handler ABI ==="
elif [[ "$OBSERVER_H" == "1" ]]; then
  echo "=== BUILD102739H persistent read-only action argument marshalling ==="
elif [[ "$OBSERVER_G" == "1" ]]; then
  echo "=== BUILD102739G persistent read-only domain/permission/action resolver ==="
elif [[ "$OBSERVER_F" == "1" ]]; then
  echo "=== BUILD102739F persistent read-only caller identity observer ==="
elif [[ "$OBSERVER_E" == "1" ]]; then
  echo "=== BUILD102739E persistent read-only XPC dictionary classifier ==="
elif [[ "$PERSISTENT_Z" == "1" ]]; then
  echo "=== BUILD102738Z persistent launchd GOT transparent-wrapper install ==="
else
  echo "=== BUILD102738Y controlled launchd GOT wrapper-invocation proof ==="
fi
"${CC[@]}" "${HOOK_CFLAGS[@]}" -c "$MIN/dt_launchdhook516_main_gate1b.m" -o "$OBJ/main_gate1b.o"
"${CC[@]}" "${HOOK_CFLAGS[@]}" -c "$MIN/dt_launchdhook516_boomerang.c" -o "$OBJ/boomerang.o"
"${CC[@]}" "${HOOK_CFLAGS[@]}" -c "$MIN/dt_launchdhook516_got_store_102738w.c" -o "$OBJ/got_invocation.o"

HOOK="$OUT/launchdhook516.dylib"
"${CC[@]}" -arch arm64 -isysroot "$SDK" -mtvos-version-min="$TVOS_MIN" \
  -dynamiclib -install_name "@loader_path/launchdhook516.dylib" \
  -L"$OUT" -ljailbreak \
  "$OBJ/main_gate1b.o" "$OBJ/boomerang.o" "$OBJ/got_invocation.o" \
  -framework Foundation -framework Security -framework CoreServices \
  -lbsm -lobjc -o "$HOOK"

chmod +x "$OUT/"* "$FW_OUT/libjailbreak.dylib"
bash "$PROJECT/scripts/write_hook_build_manifest.sh" "$HOOK" "$OUT/hook_build_manifest.txt"

if [[ "$OBSERVER_J" == "1" ]]; then
  MANIFEST="$OUT/BUILD102739J_RESOURCE_MANIFEST.txt"
elif [[ "$OBSERVER_I" == "1" ]]; then
  MANIFEST="$OUT/BUILD102739I_RESOURCE_MANIFEST.txt"
elif [[ "$OBSERVER_H" == "1" ]]; then
  MANIFEST="$OUT/BUILD102739H_RESOURCE_MANIFEST.txt"
elif [[ "$OBSERVER_G" == "1" ]]; then
  MANIFEST="$OUT/BUILD102739G_RESOURCE_MANIFEST.txt"
elif [[ "$OBSERVER_F" == "1" ]]; then
  MANIFEST="$OUT/BUILD102739F_RESOURCE_MANIFEST.txt"
elif [[ "$OBSERVER_E" == "1" ]]; then
  MANIFEST="$OUT/BUILD102739E_RESOURCE_MANIFEST.txt"
elif [[ "$PERSISTENT_Z" == "1" ]]; then
  MANIFEST="$OUT/BUILD102738Z_RESOURCE_MANIFEST.txt"
else
  MANIFEST="$OUT/BUILD102738Y_RESOURCE_MANIFEST.txt"
fi

{
    echo "CFBundleVersion=102738"
    if [[ "$OBSERVER_J" == "1" ]]; then
        echo "SCOPE=CONTROLLED_REPLY_ROUNDTRIP"
        echo "VARIANT=102739J_CONTROLLED_REPLY_ROUNDTRIP"
        echo "TELEMETRY_RECORD_SIZE=584"
        echo "WRAPPER_PERSISTENT_AFTER_CTOR=YES"
        echo "ORIGINAL_POINTER_RESTORE_IN_CTOR=NO"
        echo "NONPROBE_OWNERSHIP_CHANGED=NO"
        echo "NONPROBE_RETURN_VALUE_CHANGED=NO"
        echo "CONTROLLED_HANDLER_ARGUMENT_COUNT=8"
        echo "CONTROLLED_HANDLER_ENABLED=YES"
        echo "REAL_JBROOT_HANDLER_ENABLED=NO"
        echo "STATIC_SENTINEL_OUTPUT=YES"
        echo "REPLY_CREATION_ENABLED=YES"
        echo "REPLY_SEND_ENABLED=YES"
        echo "COMMITTED_INPUT_CONSUME_ENABLED=YES"
        echo "COMMITTED_RETURN_VALUE=22"
        echo "BOOTSTRAP_CHANGED=NO"
    elif [[ "$OBSERVER_I" == "1" ]]; then
        echo "SCOPE=CONTROLLED_ACTION_HANDLER_ABI"
        echo "VARIANT=102739I_CONTROLLED_ACTION_HANDLER_ABI"
        echo "TELEMETRY_RECORD_SIZE=352"
        echo "WRAPPER_PERSISTENT_AFTER_CTOR=YES"
        echo "ORIGINAL_POINTER_RESTORE_IN_CTOR=NO"
        echo "XPC_OBJECT_OWNERSHIP_CHANGED=NO"
        echo "ORIGINAL_RETURN_VALUE_CHANGED=NO"
        echo "ARGUMENT_DESCRIPTOR_COUNT=1"
        echo "OUTPUT_SLOT_BINDING_ENABLED=YES"
        echo "CONTROLLED_HANDLER_ARGUMENT_COUNT=8"
        echo "CONTROLLED_HANDLER_ENABLED=YES"
        echo "REAL_JBROOT_HANDLER_ENABLED=NO"
        echo "STATIC_SENTINEL_OUTPUT=YES"
        echo "REPLY_CREATION_ENABLED=NO"
        echo "BOOTSTRAP_CHANGED=NO"
    elif [[ "$OBSERVER_H" == "1" ]]; then
        echo "SCOPE=READ_ONLY_ACTION_ARGUMENT_MARSHALLING"
        echo "VARIANT=102739H_READ_ONLY_ACTION_ARGUMENT_MARSHALLING"
        echo "TELEMETRY_RECORD_SIZE=280"
        echo "WRAPPER_PERSISTENT_AFTER_CTOR=YES"
        echo "ORIGINAL_POINTER_RESTORE_IN_CTOR=NO"
        echo "XPC_OBJECT_OWNERSHIP_CHANGED=NO"
        echo "ORIGINAL_RETURN_VALUE_CHANGED=NO"
        echo "ARGUMENT_DESCRIPTOR_COUNT=1"
        echo "ARGUMENT_DESCRIPTOR_NAME=root-path"
        echo "ARGUMENT_DESCRIPTOR_TYPE=JBS_TYPE_STRING"
        echo "ARGUMENT_DESCRIPTOR_DIRECTION=OUT"
        echo "OUTPUT_SLOT_BINDING_ENABLED=YES"
        echo "HANDLER_DISPATCH_ENABLED=NO"
        echo "REPLY_CREATION_ENABLED=NO"
        echo "BOOTSTRAP_CHANGED=NO"
    elif [[ "$OBSERVER_G" == "1" ]]; then
        echo "SCOPE=READ_ONLY_DOMAIN_PERMISSION_ACTION_RESOLUTION"
        echo "VARIANT=102739G_READ_ONLY_DOMAIN_PERMISSION_ACTION_RESOLUTION"
        echo "WRAPPER_PERSISTENT_AFTER_CTOR=YES"
        echo "ORIGINAL_POINTER_RESTORE_IN_CTOR=NO"
        echo "XPC_OBJECT_OWNERSHIP_CHANGED=NO"
        echo "ORIGINAL_RETURN_VALUE_CHANGED=NO"
        echo "SHADOW_DOMAIN_TABLE_ENABLED=YES"
        echo "PERMISSION_CHECK_ENABLED=YES"
        echo "HANDLER_DISPATCH_ENABLED=NO"
        echo "REPLY_CREATION_ENABLED=NO"
    elif [[ "$OBSERVER_F" == "1" ]]; then
        echo "SCOPE=READ_ONLY_CALLER_IDENTITY"
        echo "VARIANT=102739F_READ_ONLY_CALLER_IDENTITY"
        echo "WRAPPER_PERSISTENT_AFTER_CTOR=YES"
        echo "ORIGINAL_POINTER_RESTORE_IN_CTOR=NO"
        echo "XPC_OBJECT_OWNERSHIP_CHANGED=NO"
        echo "ORIGINAL_RETURN_VALUE_CHANGED=NO"
        echo "JBSERVER_ENABLED=NO"
        echo "HANDLER_DISPATCH_ENABLED=NO"
        echo "REPLY_CREATION_ENABLED=NO"
    elif [[ "$OBSERVER_E" == "1" ]]; then
        echo "SCOPE=READ_ONLY_POST_ORIGINAL_XPC_DICTIONARY_CLASSIFICATION"
        echo "VARIANT=102739E_READ_ONLY_DICTIONARY_CLASSIFIER"
        echo "WRAPPER_PERSISTENT_AFTER_CTOR=YES"
        echo "ORIGINAL_POINTER_RESTORE_IN_CTOR=NO"
        echo "XPC_OBJECT_OWNERSHIP_CHANGED=NO"
        echo "ORIGINAL_RETURN_VALUE_CHANGED=NO"
        echo "JBSERVER_ENABLED=NO"
    elif [[ "$PERSISTENT_Z" == "1" ]]; then
        echo "SCOPE=LAUNCHD_GOT_PERSISTENT_TRANSPARENT_WRAPPER_INSTALL_ONLY"
        echo "VARIANT=102738Z_PERSISTENT_TRANSPARENT_WRAPPER"
        echo "WRAPPER_PERSISTENT_AFTER_CTOR=YES"
        echo "ORIGINAL_POINTER_RESTORE_IN_CTOR=NO"
        echo "INVOCATION_PROOF_CLAIMED=NO"
    else
        echo "SCOPE=CONTROLLED_LAUNCHD_GOT_WRAPPER_NONBLOCKING_SINGLE_SAMPLE"
        echo "VARIANT=102738Y_NONBLOCKING_SINGLE_SAMPLE_REPAIR"
    fi
    echo "MAX_OBSERVATION_MS=0"
    echo "CONSTRUCTOR_OBSERVATION_MODE=NONBLOCKING"
    echo "FROZEN_102738X_LIFETIME_MODEL=RESTORED"
    echo "TRACE_TRANSPORT_FILENAME=.dt102737_constructor_trace"
    for file in launchdhook516.dylib libjailbreak.dylib libchoma.dylib dt_jbctl516 dt_opainject516; do
        echo "$file=$(shasum -a 256 "$OUT/$file" | awk '{print $1}')"
    done
    echo "app_framework_libjailbreak.dylib=$(shasum -a 256 "$FW_OUT/libjailbreak.dylib" | awk '{print $1}')"
} > "$MANIFEST"

expect_sha "$OUT/dt_jbctl516" "6fcede5b98ee244106b9bc0b64e9da94fb3464e0bfe671f53a99485ee466c067"
expect_sha "$OUT/dt_opainject516" "0b7dcd9c7258d33e347c94258b57817d0a04fc163af855d3b21499598f6b48fb"
expect_sha "$OUT/entitlements_launchdhook681.plist" "4d63822e924c55eae1c862dbebfe8a8c2270a915f72efd6b9276a434892e014b"
expect_sha "$OUT/libchoma.dylib" "40ee6f87dcca7af63a8be1e9e185ff74ae2046cb97c3aa2405c6af6f29ae586b"
expect_sha "$OUT/libjailbreak.dylib" "0ec9129c2b37c952794b4dd33efd5d5e2b9062cc72cf990947662baf3c519754"
expect_sha "$FW_OUT/libjailbreak.dylib" "b4f4ba62330f1637c26421c9b55c395392b156018148d321b0c3fc995e2672f0"

HOOK_STRINGS="$OBJ/hook_strings.txt"
strings "$HOOK" > "$HOOK_STRINGS"
if [[ "$OBSERVER_J" == "1" ]]; then
  nm -g "$HOOK" 2>/dev/null | rg -q '_g_dt102739j_reply_telemetry'
  rg -q 'BUILD102739_IDENTITY_TELEMETRY_EXPORTED_YES' "$HOOK_STRINGS"
elif [[ "$OBSERVER_I" == "1" ]]; then
  nm -g "$HOOK" 2>/dev/null | rg -q '_g_dt102739i_handler_telemetry'
  rg -q 'BUILD102739_IDENTITY_TELEMETRY_EXPORTED_YES' "$HOOK_STRINGS"
elif [[ "$OBSERVER_H" == "1" ]]; then
  nm -g "$HOOK" 2>/dev/null | rg -q '_g_dt102739h_argument_telemetry'
  rg -q 'BUILD102739_IDENTITY_TELEMETRY_EXPORTED_YES' "$HOOK_STRINGS"
elif [[ "$OBSERVER_G" == "1" ]]; then
  nm -g "$HOOK" 2>/dev/null | rg -q '_g_dt102739g_domain_action_telemetry'
  rg -q 'BUILD102739_IDENTITY_TELEMETRY_EXPORTED_YES' "$HOOK_STRINGS"
elif [[ "$OBSERVER_F" == "1" ]]; then
  REQUIRED_MARKERS=(
    '.dt102737_constructor_trace'
    'BUILD102738Z_PROBE_ENTER'
    'BUILD102739F_PROBE_ENTER'
    'BUILD102739F_SCOPE_READ_ONLY_CALLER_IDENTITY'
    'BUILD102739F_CALLER_IDENTITY_TELEMETRY_EXPORTED_YES'
    'BUILD102738Z_COUNTING_WRAPPER_IMPLEMENTED_YES'
    'BUILD102738Z_PERSISTENT_INSTALL_IMPLEMENTED_YES'
    'GOT_WRAPPER_INSTALL_PASS'
    'GOT_WRAPPER_PERSISTENT_INSTALL_PASS'
    'GOT_PROTECTION_RESTORE_PASS'
    'GOT_PROTECTION_RESTORE_FATAL'
  )
elif [[ "$OBSERVER_E" == "1" ]]; then
  REQUIRED_MARKERS=(
    '.dt102737_constructor_trace'
    'BUILD102738Z_PROBE_ENTER'
    'BUILD102739E_PROBE_ENTER'
    'BUILD102739E_SCOPE_READ_ONLY_DICTIONARY_CLASSIFIER'
    'BUILD102739E_DICTIONARY_TELEMETRY_EXPORTED_YES'
    'BUILD102738Z_COUNTING_WRAPPER_IMPLEMENTED_YES'
    'BUILD102738Z_PERSISTENT_INSTALL_IMPLEMENTED_YES'
    'GOT_WRAPPER_INSTALL_PASS'
    'GOT_WRAPPER_PERSISTENT_INSTALL_PASS'
    'GOT_PROTECTION_RESTORE_PASS'
    'GOT_PROTECTION_RESTORE_FATAL'
  )
elif [[ "$PERSISTENT_Z" == "1" ]]; then
  REQUIRED_MARKERS=(
    '.dt102737_constructor_trace'
    'BUILD102738Z_PROBE_ENTER'
    'BUILD102738Z_COUNTING_WRAPPER_IMPLEMENTED_YES'
    'BUILD102738Z_PERSISTENT_INSTALL_IMPLEMENTED_YES'
    'GOT_WRAPPER_INSTALL_PASS'
    'GOT_WRAPPER_PERSISTENT_INSTALL_PASS'
    'GOT_PROTECTION_RESTORE_PASS'
    'GOT_PROTECTION_RESTORE_FATAL'
  )
else
  REQUIRED_MARKERS=(
    '.dt102737_constructor_trace'
    'BUILD102738Y_PROBE_ENTER'
    'BUILD102738Y_COUNTING_WRAPPER_IMPLEMENTED_YES'
    'GOT_WRAPPER_INSTALL_PASS'
    'GOT_WRAPPER_INVOCATION_COUNT_AFTER'
    'GOT_WRAPPER_INVOKED_PASS'
    'GOT_WRAPPER_INVOCATION_PROOF_PASS'
    'GOT_ORIGINAL_RESTORE_PASS'
    'GOT_PROTECTION_RESTORE_FATAL'
  )
fi
for marker in "${REQUIRED_MARKERS[@]}"; do
    rg -q "$marker" "$HOOK_STRINGS"
done
if rg -q 'BUILD102738W_|BUILD102738X_PROBE_ENTER|GOT_SAME_VALUE_STORE_PASS|MSHookFunction|initXPCHooks|jbserver_received|JBSERVER_MACH_MAGIC' "$HOOK_STRINGS"; then
    echo "ERROR: prior probe or out-of-scope message handling leaked into Y" >&2
    exit 1
fi

nm "$HOOK" 2>/dev/null | rg -q '_dt102738y_run_got_wrapper_invocation_probe'
nm "$HOOK" 2>/dev/null | rg -q '_dt102738y_counting_wrapper'
nm "$HOOK" 2>/dev/null | rg -q '_dt102738y_atomic_store_pointer'
if [[ "$OBSERVER_A" == "1" ]]; then
  nm -g "$HOOK" 2>/dev/null | rg -q '_g_dt102739a_invocation_count'
  rg -q 'BUILD102739A_COUNTER_EXPORTED_YES' "$HOOK_STRINGS"
fi
if [[ "$OBSERVER_B" == "1" ]]; then
  nm -g "$HOOK" 2>/dev/null | rg -q '_g_dt102739b_return_telemetry'
  rg -q 'BUILD102739B_RETURN_TELEMETRY_EXPORTED_YES' "$HOOK_STRINGS"
fi
if [[ "$OBSERVER_F" == "1" ]]; then
  nm -g "$HOOK" 2>/dev/null | rg -q '_g_dt102739f_caller_identity_telemetry'
  rg -q 'BUILD102739F_CALLER_IDENTITY_TELEMETRY_EXPORTED_YES' "$HOOK_STRINGS"
elif [[ "$OBSERVER_E" == "1" ]]; then
  nm -g "$HOOK" 2>/dev/null | rg -q '_g_dt102739e_dictionary_telemetry'
  rg -q 'BUILD102739E_DICTIONARY_TELEMETRY_EXPORTED_YES' "$HOOK_STRINGS"
elif [[ "$OBSERVER_C" == "1" ]]; then
  nm -g "$HOOK" 2>/dev/null | rg -q '_g_dt102739c_output_telemetry'
  rg -q 'BUILD102739C_OUTPUT_TELEMETRY_EXPORTED_YES' "$HOOK_STRINGS"
fi
nm -u "$HOOK" 2>/dev/null | rg -q '_vm_region_recurse_64'
if nm -u "$HOOK" 2>/dev/null | rg -q '_usleep'; then
    echo "ERROR: repaired Y hook still contains constructor observation sleep" >&2
    exit 1
fi
if [[ "$PERSISTENT_Z" == "1" ]] && rg -q 'GOT_WRAPPER_INVOCATION_PROOF_PASS|GOT_WRAPPER_INVOKED_PASS|GOT_ORIGINAL_RESTORE_PASS' "$HOOK_STRINGS"; then
    echo "ERROR: cleanup/invocation-proof material leaked into persistent Z success path" >&2
    exit 1
fi

WRAPPER_DISASM="$OBJ/wrapper_disassembly.txt"
otool -tvV "$HOOK" | sed -n '/_dt102738y_counting_wrapper:/,/^_/p' > "$WRAPPER_DISASM"
rg -q $'\tldxr\t|\tldaxr\t' "$WRAPPER_DISASM"
rg -q $'\tstxr\t|\tstlxr\t' "$WRAPPER_DISASM"
rg -q $'\tldar\t' "$WRAPPER_DISASM"
if [[ "$OBSERVER_B" == "1" || "$OBSERVER_C" == "1" || "$OBSERVER_E" == "1" || "$OBSERVER_F" == "1" || "$OBSERVER_G" == "1" || "$OBSERVER_H" == "1" || "$OBSERVER_I" == "1" || "$OBSERVER_J" == "1" ]]; then
  rg -q $'\tblr\t' "$WRAPPER_DISASM"
  rg -q $'\tret' "$WRAPPER_DISASM"
  [[ "$(rg -c $'\tldxr\t|\tldaxr\t' "$WRAPPER_DISASM")" -ge 2 ]]
  [[ "$(rg -c $'\tstxr\t|\tstlxr\t' "$WRAPPER_DISASM")" -ge 2 ]]
  POST_CALL_DISASM="$OBJ/wrapper_post_call_disassembly.txt"
  sed -n '/blr[[:space:]]x8/,/ret/p' "$WRAPPER_DISASM" > "$POST_CALL_DISASM"
  [[ -s "$POST_CALL_DISASM" ]]
  if [[ "$OBSERVER_B" == "1" ]] && rg -q '(^|[^[:alnum:]_])[wx]0([^[:alnum:]_]|$)' "$POST_CALL_DISASM"; then
      echo "ERROR: 102739B post-call telemetry clobbers the original return register" >&2
      exit 1
  fi
  if [[ "$OBSERVER_C" == "1" ]]; then
      [[ "$(rg -c $'\tblr\t' "$WRAPPER_DISASM")" -eq 1 ]]
      if rg -q '_xpc_|_fprintf|_open|_mmap|_write' "$WRAPPER_DISASM"; then
          echo "ERROR: 102739C wrapper contains out-of-scope XPC, logging, or I/O calls" >&2
          exit 1
      fi
  fi
  if [[ "$OBSERVER_J" == "1" ]]; then
      [[ "$(rg -c $'\tblr\t' "$WRAPPER_DISASM")" -eq 3 ]]
      for call in _xpc_get_type _xpc_dictionary_get_value \
          _xpc_dictionary_get_uint64 _xpc_dictionary_get_string \
          _xpc_dictionary_get_int64 _xpc_dictionary_set_string \
          _xpc_dictionary_set_int64 _xpc_dictionary_create_reply \
          _xpc_pipe_routine_reply _xpc_release _strcmp \
          _xpc_dictionary_get_audit_token _audit_token_to_pid \
          _audit_token_to_euid; do
          rg -q "$call" "$WRAPPER_DISASM"
      done
      if rg -q '_xpc_retain|_fprintf|_open|_mmap|_write|_jbserver|_jbinfo|_strdup|_malloc|_free' \
          "$WRAPPER_DISASM"; then
          echo "ERROR: forbidden retain, allocation, I/O, jbinfo, or jbserver call in 102739J wrapper" >&2
          exit 1
      fi
  elif [[ "$OBSERVER_I" == "1" ]]; then
      [[ "$(rg -c $'\tblr\t' "$WRAPPER_DISASM")" -eq 3 ]]
      for call in _xpc_get_type _xpc_dictionary_get_value \
          _xpc_dictionary_get_uint64 _xpc_dictionary_get_string _strcmp \
          _xpc_dictionary_get_audit_token _audit_token_to_pid \
          _audit_token_to_euid; do
          rg -q "$call" "$WRAPPER_DISASM"
      done
      if rg -q '_xpc_(release|retain|dictionary_create_reply)|_fprintf|_open|_mmap|_write|_jbserver|_jbinfo|_strdup|_malloc|_free' \
          "$WRAPPER_DISASM"; then
          echo "ERROR: forbidden ownership, reply, allocation, I/O, jbinfo, or jbserver call in 102739I wrapper" >&2
          exit 1
      fi
  elif [[ "$OBSERVER_H" == "1" || "$OBSERVER_G" == "1" ]]; then
      [[ "$(rg -c $'\tblr\t' "$WRAPPER_DISASM")" -eq 2 ]]
      for call in _xpc_get_type _xpc_dictionary_get_value \
          _xpc_dictionary_get_uint64 _xpc_dictionary_get_string _strcmp \
          _xpc_dictionary_get_audit_token _audit_token_to_pid \
          _audit_token_to_euid; do
          rg -q "$call" "$WRAPPER_DISASM"
      done
      if rg -q '_xpc_(release|retain|dictionary_create_reply)|_fprintf|_open|_mmap|_write|_jbserver' \
          "$WRAPPER_DISASM"; then
          echo "ERROR: ownership, reply, I/O, or jbserver call leaked into 102739G/H wrapper" >&2
          exit 1
      fi
  elif [[ "$OBSERVER_F" == "1" ]]; then
      [[ "$(rg -c $'\tblr\t' "$WRAPPER_DISASM")" -eq 1 ]]
      for call in _xpc_get_type _xpc_dictionary_get_value \
          _xpc_dictionary_get_uint64 _xpc_dictionary_get_string _strcmp \
          _xpc_dictionary_get_audit_token _audit_token_to_pid \
          _audit_token_to_euid; do
          rg -q "$call" "$WRAPPER_DISASM"
      done
      if rg -q '_xpc_(release|retain|dictionary_create_reply)|_fprintf|_open|_mmap|_write|_jbserver' \
          "$WRAPPER_DISASM"; then
          echo "ERROR: ownership, reply, I/O, or jbserver call leaked into 102739F wrapper" >&2
          exit 1
      fi
  elif [[ "$OBSERVER_E" == "1" ]]; then
      [[ "$(rg -c $'\tblr\t' "$WRAPPER_DISASM")" -eq 1 ]]
      for call in _xpc_get_type _xpc_dictionary_get_value \
          _xpc_dictionary_get_uint64 _xpc_dictionary_get_string _strcmp; do
          rg -q "$call" "$WRAPPER_DISASM"
      done
      if rg -q '_xpc_(release|retain)|_fprintf|_open|_mmap|_write|_jbserver' \
          "$WRAPPER_DISASM"; then
          echo "ERROR: ownership, I/O, or jbserver call leaked into 102739E wrapper" >&2
          exit 1
      fi
  fi
  if tail -n 1 "$WRAPPER_DISASM" | rg -q $'\tbr\t'; then
      echo "ERROR: 102739B wrapper still terminates in a tail branch" >&2
      exit 1
  fi
else
  rg -q $'\tbr\t' "$WRAPPER_DISASM"
  if rg -q $'\t(bl|blr|ret)\b' "$WRAPPER_DISASM"; then
      echo "ERROR: counting wrapper contains a call/return instead of direct tail forwarding" >&2
      exit 1
  fi
fi

if [[ "$PERSISTENT_Z" == "1" ]]; then
  echo "BUILD102738Z_HOOK_ONLY_REBUILD=PASS"
  echo "BUILD102738Z_FROZEN_RESOURCES=PASS"
  echo "BUILD102738Z_SCOPE_AUDIT=PASS"
  echo "BUILD102738Z_WRAPPER_DISASSEMBLY_AUDIT=PASS"
  echo "BUILD102738Z_HOOK_SHA256=$(shasum -a 256 "$HOOK" | awk '{print $1}')"
else
  echo "BUILD102738Y_HOOK_ONLY_REBUILD=PASS"
  echo "BUILD102738Y_FROZEN_RESOURCES=PASS"
  echo "BUILD102738Y_SCOPE_AUDIT=PASS"
  echo "BUILD102738Y_WRAPPER_DISASSEMBLY_AUDIT=PASS"
  echo "BUILD102738Y_HOOK_SHA256=$(shasum -a 256 "$HOOK" | awk '{print $1}')"
fi
