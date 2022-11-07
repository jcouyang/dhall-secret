let project = import ./default.nix;
    pkgs = project.pkgs;
    dhall-secret = project.projectCross.musl64.hsPkgs.dhall-secret.components.exes.dhall-secret;
    staticBin = pkgs.stdenv.mkDerivation {
      name =  "clean-static";
      src = dhall-secret;
      nativeBuildInputs = [pkgs.removeReferencesTo];
      installPhase = ''
      mkdir -p $out/bin
      cp "$src/bin/dhall-secret" $out/bin/
      remove-references-to -t ${dhall-secret} $out/bin/dhall-secret
      '';
    };
in pkgs.dockerTools.buildImage {
  name = "ghcr.io/jcouyang/dhall-secret";
  tag = "latest";
  created = "now";
  contents = [staticBin];
  config = {
    Entrypoint = [ "dhall-secret"];
  };
}
