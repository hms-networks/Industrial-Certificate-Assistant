# Bundled OpenSSL Runtime

This directory is intentionally source-controlled without OpenSSL executables
or DLLs. A release maintainer may place a vetted Windows OpenSSL runtime here
before building the Windows executable.

Required files when `openssl.exe` is present:

- `openssl.exe` and its required runtime DLLs
- `LICENSE.txt` copied from the exact OpenSSL distribution
- `NOTICE.txt` containing the upstream/distributor notices applicable to that
  binary distribution
- `VERSION.txt` recording the precise OpenSSL version and download source
- `SHA256SUMS.txt` containing hashes for every redistributed executable and DLL

The Windows build script refuses to bundle OpenSSL if these compliance files
are absent.

