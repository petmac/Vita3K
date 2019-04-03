set -ex
rm -f Vita3K.trace
../apitrace/build/apitrace trace build-macos/bin/Debug/Vita3K.app/Contents/MacOS/Vita3K
