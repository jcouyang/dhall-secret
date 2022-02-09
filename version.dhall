let render =
      https://raw.githubusercontent.com/Gabriel439/dhall-semver/main/render.dhall
        sha256:57d455dd9164ab6bff230e51be028b09fcdacdbfb63f6a3c087e0563a294782c

let version = ./version-expr.dhall

let build = env:GITHUB_RUN_NUMBER as Text ? "dev"

in  "v${render (version with build = [ build ])}"
