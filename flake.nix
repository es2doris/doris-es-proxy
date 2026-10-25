{
  description = "doris-es-proxy - Elasticsearch & OpenSearch HTTP REST / Query DSL wire-compatible proxy backed by Apache Doris";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs { inherit system; };
      in
      {
        devShells.default = pkgs.mkShell {
          buildInputs = with pkgs; [
            go_1_25
            gh
            git
            gnumake
            gopls
            golangci-lint
            govulncheck
            gosec
            gitleaks
            actionlint
            editorconfig-checker
            pre-commit
            lefthook
          ];

          shellHook = ''
            export GOWORK=off
            echo "doris-es-proxy dev shell"
            echo "  go: $(go version)"
            lefthook install >/dev/null 2>&1 || true
          '';
        };
      });
}
