# dopamin-tvOS-kfd

Minimal **Dopamine kfd + XPF** kernel R/W proof for Apple TV, built with **THEOS** and `AppleTVOS16.4.sdk`.

## Requirements

- [THEOS](https://theos.dev) at `/Users/dxcool223/theos` (or set `THEOS=…`)
- SDK: `$THEOS/sdks/AppleTVOS16.4.sdk`
- `Dopamine_Rootful-main/` alongside this folder under `tvrootshell/`
- `ldid`, Homebrew optional (not needed for minimal libjailbreak)

## Build

```bash
cd dopamin-tvOS-kfd
export THEOS=/Users/dxcool223/theos
./build.sh
# or: make basebin dylibs && make all ipa
```

Output: `../dopamin-tvOS-kfd.ipa`

## On device

1. Install IPA via **TrollStore-tvOS** (or dev sign).
2. Open **Dopamine TV kfd**.
3. Pick PUAF flavor (`landa` first on tvOS 16.x).
4. Tap **Run kfd + verify kernel R/W**.

Success log shows kernel slide, `MH_MAGIC_64`, `gPhysBase`, and no-op kwrite verify.

## What this is

| Component | Source |
|-----------|--------|
| kfd exploit | `Dopamine_Rootful-main/.../Exploits/kfd` |
| Patchfinder | XPF → `perfkrw` set |
| libjailbreak | minimal `info` + `primitives` + `translation` |
| UI | tvOS log + flavor picker |

Not included: full jailbreak, BaseBin persistence, bootstrap install.

## Notes

- Uses Dopamine bundled **XPC** headers (`BaseBin/_external/include`).
- **syscall** shim: tvOS SDK marks `syscall()` unavailable; misaka/Dopamine use it at runtime anyway.
- Kernel path: scans `/private/preboot/*/…/kernelcache`, then live cache, then bundled `kernelcache`.
