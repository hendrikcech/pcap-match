{
  description = "pcap-match project";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    crane = {
      url = "github:ipetkov/crane";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, nixpkgs, flake-utils, crane, ... }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs {
          inherit system;
        };

        craneLib = crane.mkLib pkgs;

        pcapOrCsvFilter = path: type:
          (builtins.match ".*pcap$" path != null) ||
          (builtins.match ".*csv$" path != null);
        pcapOrCsvOrCargo = path: type:
          (pcapOrCsvFilter path type) || (craneLib.filterCargoSources path type);

        commonArgs = {
          src = pkgs.lib.cleanSourceWith {
            src = craneLib.path ./.;
            filter = pcapOrCsvOrCargo;
          };

          nativeBuildInputs = [
            pkgs.pkg-config
          ];

          buildInputs = [
            pkgs.libpcap
          ];
        };

        # Build *just* the cargo dependencies, so we can cache
        # them all while also keeping a lean docker image
        cargoArtifacts = craneLib.buildDepsOnly commonArgs;

        # Build the actual crate itself
        my-crate = craneLib.buildPackage (commonArgs // {
          inherit cargoArtifacts;
        });

      in
      {
        checks = {
          # Build the crate as part of `nix flake check`
          inherit my-crate;
        };

        packages.default = my-crate;

        apps.default = flake-utils.lib.mkApp {
          drv = my-crate;
        };

        devShells.default = craneLib.devShell {
          # Inherit inputs from checks.
          checks = self.checks.${system};

          # Extra inputs can be added here
          packages = [
            pkgs.pkg-config
            pkgs.libpcap
          ];
        };
      });
}
