# Hades II: the rewriter's patches of this game's main (dm/tools/patch_nso.py "Registered patches")
CUTS = {
  # 1.0.141667 (v655360) main: the swapchain / screen size is a constant {1280, 720} the graphics init stores into its config object (main+0x2a5920: movz/movk x8, then
  # str x8, [x19, #8] and stp xzr, x8, [x9, #8]). The game lays everything out in a 1920x1080 design space (main+0x2ab82c: 0x780 / 0x438 and 1 / 1920) and scales it to that size,
  # so 1920x1080 renders the same picture natively instead of 1280x720 stretched: checked on the Mac through the title, the Crossroads and a run in Erebus (HUD included).
  # (The profile's note of a crash with 1600x900 was on the 0.0 / 1.0.137848 builds.)
  'a862861fa2eeedea1d873c94324fca7b': [
    (0x2a5920, '08a080d2', '08f080d2', 'screen size: movz x8,#0x500 (1280) → movz x8,#0x780 (1920)'),
    (0x2a5924, '085ac0f2', '0887c0f2', 'screen size: movk x8,#0x2d0,lsl #32 (720) → movk x8,#0x438,lsl #32 (1080)'),
  ],
}
