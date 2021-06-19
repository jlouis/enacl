package actions

// Versions for simplicity
_versions: {
	// The versions here have an underlying Debian/Ubuntu which support enough of
	// libsodium to handle what enacl provides. Older versions will fail to compile
	otp: ["22.3", "23.3", "24.0"]
	rebar3: "3.16.1"
}

_branch: "master"

jobs: ci: steps:
[
	{
		uses: "actions/checkout@v2"
	},
	{
		uses: "erlef/setup-beam@v1"
		with: {
			"otp-version":    "${{matrix.otp_vsn}}"
			"rebar3-version": _versions.rebar3
		}
	},
	{
		name: "Update apt-get database"
		run:  "sudo apt-get update"
	},
	{
		name: "Install libsodium"
		run:  "sudo apt-get install -y libsodium-dev"
	},
	{
		name: "Compile source code"
		run:  "make compile"
	},
	{
		name: "Run the tests"
		run:  "make tests"
	}]
