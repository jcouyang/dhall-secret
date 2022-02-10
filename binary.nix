with (import ./nixpkgs.nix);

haskell.lib.appendConfigureFlags
  (haskell.lib.justStaticExecutables (pkgs.haskell.lib.dontCheck (import ./default.nix {pkgs = pkgsMusl;}).dhall-secret-cabal))
  [ "--enable-executable-static"
    "--extra-lib-dirs=${pkgsMusl.ncurses.override { enableStatic = true; enableShared = true; }}/lib"
    "--extra-lib-dirs=${pkgsMusl.gmp6.override { withStatic = true; }}/lib"
    "--extra-lib-dirs=${pkgsMusl.zlib.static}/lib"
    "--extra-lib-dirs=${pkgsMusl.libsodium.overrideAttrs (old: { dontDisableStatic = true; })}/lib"
    "--extra-lib-dirs=${pkgsMusl.libffi.overrideAttrs (old: { dontDisableStatic = true; })}/lib"
  ]

