{ system ? builtins.currentSystem
, src ? ../..
}:

let
  nixpkgs = builtins.fetchTarball {
    url = "https://github.com/NixOS/nixpkgs/archive/c3eea5b2156db11c7eeeada3dc737711255b253e.tar.gz";
    sha256 = "sha256-vdhpDJ3Lr24lkZ+fDCjmBRRtw9/vcSzkqGJOJyF5h2U=";
  };
  pkgs = import nixpkgs { inherit system; };
in
pkgs.rustPlatform.buildRustPackage {
  pname = "ripgrep-axiomlayer-integration";
  version = "15.2.0";
  inherit src;

  cargoLock = {
    lockFile = src + "/Cargo.lock";
  };

  nativeBuildInputs = [ pkgs.pkg-config ];
  buildInputs = [ pkgs.pcre2 ]
    ++ pkgs.lib.optionals pkgs.stdenv.hostPlatform.isDarwin [ pkgs.libiconv ];

  buildFeatures = [ "pcre2" ];
  cargoBuildFlags = [ "--workspace" ];
  cargoTestFlags = [ "--workspace" ];
  doCheck = true;
  strictDeps = true;

  postInstall = ''
    version="$($out/bin/rg --version | head -n 1)"
    case "$version" in
      "ripgrep 15.2.0"*) ;;
      *) echo "unexpected version: $version" >&2; exit 1 ;;
    esac
  '';
}
