with (import ./nixpkgs.nix);

haskell.lib.buildStackProject {
  name = "dhall-secret-dev-env";
  src = ./.;
  shellHook = ''
  export AWS_REGION=ap-southeast-2
  export MY_AES_SECRET=super-secure-secret
  '';
  buildInputs = [
    stack
    zlib.dev
    haskell.compiler.ghc8107
  ];
}
