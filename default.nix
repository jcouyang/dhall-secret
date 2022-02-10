{pkgs ? import ./nixpkgs.nix, haskellPackage ? pkgs.haskell.packages.ghc8107 }:
let dhall-secret-cabal = haskellPackage.callCabal2nix "dhall-secret" ./. {};
in {
  dhall-secret = pkgs.haskell.lib.justStaticExecutables dhall-secret-cabal;
  inherit dhall-secret-cabal;
}
