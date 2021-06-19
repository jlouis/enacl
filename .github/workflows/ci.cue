package actions

// Versions for simplicity
_versions: {
	latest: ["24.0"]
	// The versions here have an underlying Debian/Ubuntu which support enough of
	// libsodium to handle what enacl provides. Older versions will fail to compile
	all: ["22.3", "23.3", "24.0"]
	rebar3: "3.16.1"
}

_branch: "master"

#Name: string
#Branches: branches: [...string]
#Tags: tags: [...string]

#On: {
	push?:         #Branches
	pull_request?: #Branches
	page_build?:   #Branches
}

#Action: "actions/checkout@v2" | "erlef/setup-beam@v1"
#Uses: {
	uses: #Action
	with?: {
		...
	}
}
#Run: {
	name: string
	run:  string
}
#Steps: #Uses | #Run

#OS_Version: *"ubuntu-latest" | "macos-latest" | "windows_latest"

#Jobs: ci: {
	name:      string
	"runs-on": string
	strategy:
		matrix: {
			otp_vsn: [...string]
			os: [...#OS_Version]
		}
	steps: [...#Steps]
}

name: #Name & "build"
on:   #On & {
	push: branches: [
		_branch,
	]
	pull_request: branches: [
		_branch,
	]
}
jobs: #Jobs
jobs: ci: {
	name:      "Run checks and tests over ${{matrix.otp_vsn}} and ${{matrix.os}}"
	"runs-on": "${{matrix.os}}"
	strategy: matrix: {
		otp_vsn: _versions.all
		os: ["ubuntu-latest"]
	}
}
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
