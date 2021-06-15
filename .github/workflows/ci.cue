let OTP_Versions = {
	latest: [24.0]
	// Older versions than 22.3 use Debian stretch, and it only has libsodium 0.18
	// In turn, we can't compile for the newer libsodium functions on this image,
	// and it fails. Hence these versions.
	all: [22.3, 23.3, 24.0]
}

name: "build"
on: {
	push: branches: [
		"master",
	]
	pull_request: branches: [
		"master",
	]
}
jobs: ci: {
	name:      "Run checks and tests over ${{matrix.otp_vsn}} and ${{matrix.os}}"
	"runs-on": "${{matrix.os}}"
	container: image: "erlang:${{matrix.otp_vsn}}"
	strategy: matrix: {
		otp_vsn: OTP_Versions.all
		// This entry is a lie. The container images are Debian containers, but
		// one has to specify where those containers are hosted.
		os: ["ubuntu-latest"]
	}
	steps: [
		{uses: "actions/checkout@v2"},
		{name: "Update apt-get database",
		 run: "apt-get update"},
	    {name: "Install libsodium",
		 run: "apt-get install -y libsodium-dev"},
		{name: "Compile source code",
		 run: "make compile"},
		{name: "Run the tests",
		 run: "make tests"}]
}
