// Versions for simplicity
_versions: {
	latest: ["24.0"]
	// Older versions than 22.3 use Debian stretch, and it only has libsodium 0.18
	// In turn, we can't compile for the newer libsodium functions on this image,
	// and it fails. Hence these versions.
	all: ["22.3", "23.3", "24.0"]
	rebar3: "3.16.1"
}

#Name: string
#Branches: branches: [string, ...]
#Tags: tags: [string, ...]

#On: {
	push?:         #Branches
	pull_request?: #Branches
	page_build?:   #Branches
}

#Action: "actions/checkout@v2" | "erlef/setup-beam@v1"
#Uses : {
	uses: #Action
	with?: {
		...
	}
}
#Run: {
	name: string
	run: string
}
#Steps: #Uses | #Run

#OS_Version: "ubuntu-latest" | "macos-latest" | "windows_latest"

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
		"master",
	]
	pull_request: branches: [
		"master",
	]
}
jobs: #Jobs & {
	ci: {
		name:      "Run checks and tests over ${{matrix.otp_vsn}} and ${{matrix.os}}"
		"runs-on": "${{matrix.os}}"
		strategy: matrix: {
			otp_vsn: _versions.all
			// This entry is a lie. The container images are Debian containers, but
			// one has to specify where those containers are hosted.
			os: ["ubuntu-latest"]
		}
		steps: [
			{
				uses: "actions/checkout@v2"
			},
			{
				name: "Update apt-get database"
				run:  "sudo apt-get update"
			},
			{
				uses: "erlef/setup-beam@v1"
				with: {
					"otp-version":    "${{matrix.otp_vsn}}"
					"rebar3-version": _versions.rebar3
				}
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
	}}
