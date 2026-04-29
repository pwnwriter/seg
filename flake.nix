{
  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";
  };

  outputs =
    { nixpkgs, ... }:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "x86_64-darwin"
        "aarch64-darwin"
      ];

      forAllSystems =
        function: nixpkgs.lib.genAttrs systems (system: function (import nixpkgs { inherit system; }));
    in
    {
      devShells = forAllSystems (pkgs: {
        default = pkgs.mkShell {
          packages =
            with pkgs;
            [
              bintools
              pwntools
            ]
            ++ lib.optionals stdenv.isLinux [
              checksec
            ];

          buildInputs = with pkgs; [
            pkg-config
          ];

          shellHook = ''
            echo "DevShell🚀: initiated"

            # add cargo build output to PATH
            export PATH="$PWD/target/debug:$PATH"
          '';
        };
      });
    };
}
