# Title Menu Loop

`GAME_STATE_TITLE_MENU` runs `RunTitleMenu` once per frame after `MainLoop`
waits for VBlank and reads joypad input.

`RunTitleMenu` is not a one-shot initializer. Each frame it clears title/result
scratch bytes, resets the egg counter and link send queue staging, then delegates
to the Bank 1 title handlers:

- `ProcessTitleInput` updates the 1P/2P selection. Up/down/select change
  `TWO_PLAYER_FLAG`, and `GenerateNext` redraws the selection marker at rows
  `$0F` and `$10`.
- `ProcessOptionInput` handles Start and link negotiation. In 1P, Start clears
  `rSB` and enters `GAME_STATE_PREPLAY_INIT`. In 2P, the master sends `$01`;
  received `$01` sets slave role `$02`, received `$02` sets master role `$01`,
  then both paths enter `GAME_STATE_PREPLAY_INIT`.

This is why the old `InitGameVars` label was misleading: the routine is the
steady title menu update loop for state `$01`, even though it also resets several
scratch bytes before polling input.
