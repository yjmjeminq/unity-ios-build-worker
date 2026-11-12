# Unity iOS build worker

The manual workflow compiles a prepared Unity Xcode export on a standard macOS runner. The probe checks the Xcode and iPhone SDK versions.

For a build, the worker uses a repository-scoped SSH deploy key to fetch the input from a private Git branch. It verifies the archive hash before running the prepared build and returns the IPA, checksum, and diagnostics on a private result branch.
