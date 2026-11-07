# iOS ports branch (`ios-ports-v122`)

This branch is LNPANDY/NX2Apple v1.2.2 (engine pin `88c7e03f`) plus the patches below, which bring seven games to the iPhone
in one shell app. Like every fork patch, they live in `patches/` (headers: `Reason:`, `Issue: HachebeDLC/NX2Apple#1`,
`Upstream-Status`); `python3 tools/engine.py sync` builds `engine/` from them.

Tested on an iPhone 17 Pro Max through LiveContainer, and on an M4 Mac (each game boots to its intro, menu or first scene):
Hades II, Bayonetta 2, Bayonetta 3, KINGDOM HEARTS II FINAL MIX (Spanish), NARUTO X BORUTO Ultimate Ninja STORM CONNECTIONS,
DRAGON BALL Sparking! ZERO, Bomb Rush Cyberfunk.

## The patches

| Patch | What it does |
|---|---|
| 0084 iOS ports | The port of the fork's earlier iOS work onto the current engine. **Storm Connections**: the GLES layer Scaleform draws its UI with, NVN textures built over GL texture names (`mtl_tex_gl`), a view of the first mip levels of a shared texture (the title's sky stayed black), the output size picked from the game's display mode table (profile `display_height`). **Sparking Zero**: Unreal `r.ScreenPercentage` set by the host (`screen_percentage`), material shaders kept inline in Unreal 4.27 packages (`uepak.py`), its SSL context created so its network layer does not panic. **Hades II**: 1080p and 120 fps on a 120 Hz screen (`present_hz`, the game steps by real time). **KINGDOM HEARTS HD 1.5+2.5**: multi-program applications, each game mounting the menu's RomFS as `rom0` (`romfs_p<N>.img`, `--program N`). **Vulkan** (KH): blend constants, attachment clears inside a pass, multisample resolve. Diagnostics (off unless set): heap tracking, TLS checks, per-core locks, crash memory dumps. The three new profile keys have their launcher settings. |
| 0085-0089 docs_patches | Every host row keyed by a build, every profile switch and every `patches.py` above classified in `docs/agents/game-patches.md` (purpose: frame rate, rendering, memory...), as the repository's patch index requires. |
| 0090 ue_malloc | Unreal's allocator finder also handles mains with no unwind entries (it takes the block after the last return) and two `GMalloc` setups close together, as in Sparking Zero (both calls are cut). |
| 0091 v1.2.2 rebase | Hades II's 1.0.141667 update registered as a build, the two-call allocator test, the meanings of the switches the ports read. |

The fork's earlier patches for Ocarina of Time (NUP standalone updates, its host services, the NDVE movie data) are gone:
upstream supports the game now. The iPhone work on Ocarina is on its own branch of the engine: see
`docs/games/ocarina-of-time-ios-hachebe.md` there.

## The shell, small enough for LiveContainer

The shell is one app with every game's engine as a framework (`dm/ios/tools/build_shell.sh`, the frameworks from
`build_ipa_from_nsp.py --shell-framework`). LiveContainer signs everything in the app and needs room to unpack it, so the
shader libraries stay out of it: the shell takes a game's shaders from `Documents/games/<title ID>/msl` before its own
(`EngineLaunchPlan.swift`). With v1.2.2 each game's shaders are one file, so the whole set is 23 files:

```
NX2Apple_Shell_v122.ipa        200 MB: the shell and the seven engines
Documents/games/<title ID>/
├── romfs.img                  the game files from your own dump (KH II also romfs_p0.img, the menu's)
├── aoc/                       add-on content (Sparking Zero, Bomb Rush)
├── msl/b-<chain>.img          the shaders (KH II: msl/vk)
└── save/                      the saves
```

A new shader chain needs the new `msl/b-<chain>.img` files; `romfs.img`, `aoc/` and `save/` stay. Installing a new shell over
the old one (same bundle ID) keeps Documents. KINGDOM HEARTS II's manifest names the Spanish Mix image's identity, so that
image is accepted.

## Building

```
python3 tools/engine.py sync
DM_NX_PROGRAM=<N> engine/scripts/build_ipa_from_nsp.py <game folder> -k prod.keys --shell-framework <out>/<game>
SHELL_DIR=<proj> DM_SHELL_PACKAGE=frontend-ios DM_SHELL_FRAMEWORKS="<the .framework paths>" DM_SHELL_NAME=NX2Apple \
  bash engine/dm/ios/tools/build_shell.sh --build
```

`DM_NX_PROGRAM` is 3 for KINGDOM HEARTS II in the HD 1.5+2.5 collection, 0 otherwise. Move each framework's `msl/` out
before `build_shell.sh` to get the small IPA. Nothing of any game is in this repository.
