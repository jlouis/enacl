// Versions for simplicity
_versions: {
	latest: ["24.0"]
	// Older versions than 22.3 use Debian stretch, and it only has libsodium 0.18
	// In turn, we can't compile for the newer libsodium functions on this image,
	// and it fails. Hence these versions.
	all: ["22.3", "23.3", "24.0"]
}

#Name: string
#Branches: branches: [string]

#On: {
	push:         #Branches
	pull_request: #Branches
}
#Steps: {
	uses: "actions/checkout@v2"
} | {
	name: string
	run:  string
}

#Jobs: ci: {
	name:      string
	"runs-on": string
	container: image: string
	strategy:
		matrix: {
			otp_vsn: [string, ...]
			os: ["ubuntu-latest"]
		}
	steps: [#Steps, ...]
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
		container: image: "erlang:${{matrix.otp_vsn}}"
		strategy: matrix: {
			otp_vsn: _versions.all
			// This entry is a lie. The container images are Debian containers, but
			// one has to specify where those containers are hosted.
			os: ["ubuntu-latest"]
		}
		steps: [
			{uses: "actions/checkout@v2"},
			{
				name: "Update apt-get database"
				run:  "apt-get update"
			},
			{
				name: "Install libsodium"
				run:  "apt-get install -y libsodium-dev"
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
