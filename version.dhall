let build = env:GITHUB_RUN_NUMBER as Text ? "dev" in "v0.1.0+${build}"
