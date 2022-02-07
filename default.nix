{pkgs ? import ./nixpkgs.nix, haskellPackage ? pkgs.haskell.packages.ghc8107 }:
pkgs.haskell.lib.dontCheck (haskellPackage.callCabal2nix "dhall-secret" ./. {})
