# To build executable do
# nix-build -A otp-authenticator.components.exes -o result-otp-auth
#
# To run
# ./result-otp-auth/bin/otp-auth --help
#
# To install in the local profile
# nix-env -i ./result-otp-auth

{ # Fetch the latest haskell.nix and import its default.nix
  haskellNix ? import (builtins.fetchTarball "https://github.com/input-output-hk/haskell.nix/archive/588a1e8a045bf92a29af6c16e29ed76074f930d3.tar.gz") {}

# haskell.nix provides access to the nixpkgs pins which are used by our CI,
# hence you will be more likely to get cache hits when using these.
# But you can also just use your own, e.g. '<nixpkgs>'.
, nixpkgsSrc ? haskellNix.sources.nixpkgs-2009

# haskell.nix provides some arguments to be passed to nixpkgs, including some
# patches and also the haskell.nix functionality itself as an overlay.
, nixpkgsArgs ? haskellNix.nixpkgsArgs

# import nixpkgs with overlays
, pkgs ? import nixpkgsSrc nixpkgsArgs
}: pkgs.haskell-nix.project {
  # 'cleanGit' cleans a source directory based on the files known by git
  src = pkgs.haskell-nix.haskellLib.cleanGit {
    name = "otp-authenticator";
    src = ./.;
  };
  # Specify the GHC version to use.
  # compiler-nix-name = "ghc8102"; # Not required for `stack.yaml` based projects.
}
