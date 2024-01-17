with import <nixpkgs> {};

mkShell {
  name = "mirrortest-shell";
  buildInputs = [
    (python3.withPackages (pypkgs: with pypkgs; [
      requests jinja2
    ]))
  ];
}
