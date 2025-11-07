{
  description = "Akuvox Home Assistant integration development environment";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-24.05";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs { inherit system; };
      in
      {
        devShells.default = pkgs.mkShell {
          packages = with pkgs; [
            uv
            python311
            ruff
          ];

          shellHook = ''
            export UV_PYTHON=${pkgs.python311}/bin/python3
            export UV_PROJECT_ENVIRONMENT=".venv"
          '';
        };
      });
}
