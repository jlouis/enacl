{ pkgs ? import <nixpkgs> {} }:

pkgs.mkShell {
  buildInputs = [
    pkgs.hello

    # keep this line if you use bash
    pkgs.bashInteractive
    pkgs.erlang
    pkgs.libsodium
  ];
}
