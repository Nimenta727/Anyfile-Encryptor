# MOSAIC-HDT desktop preview / 桌面软件实验版

The desktop app uses Python Tk/ttk and the existing HDT core, unchanged. It is local and bilingual. It does not send files or credentials over a network. It is not independently audited or production-approved.

## Run / 启动
Python 3.10+ with Tk installed:
```
python -m pip install --only-binary=cryptography,argon2-cffi-bindings,cffi -c constraints-runtime.txt -r requirements.txt
python -m desktop.app
```
For Windows x64 preview, use the Desktop preview workflow's artifact after a successful build. The ZIP includes the unsigned MOSAIC-HDT.exe and SHA256SUMS.txt. It is a portable build, not a signed installer. Verify the checksum; do not bypass OS security warnings. Build does not yet imply a packaged-executable launch test.

## Encrypt / 加密
1. Choose a regular local file. The source is never removed.
2. Choose two distinct, new destinations. Defaults append .hdt and .mkey; put the keyfile in a separate trusted directory or offline storage when possible.
3. Input and confirm alpha/beta/gamma, or generate independent random secrets locally. Record all three before starting. Minimum eight characters per distinct segment is only a usability floor, not an entropy measure.
4. Select a suite; 256 MiB HMAC commitment is the default. SHA-512 candidates are explicitly research suites. Begin; the GUI clears input fields and runs the job in one background thread with indeterminate activity and stage text, not invented percent completion.
5. Both the ciphertext and keyfile must be saved. The keyfile is generated and published first, and retained even when encryption fails. The pair cannot be atomically published across arbitrary directories; the UI explicitly reports partial success and does not overwrite or delete outputs. No secrets are written into keyfile or app settings.

## Decrypt / 解密
Choose ciphertext, existing matching keyfile, new output, the same normalized three secrets, and a local memory cap. The core authenticates before publishing. No fallback or recovery bypass. Losing any required credential may mean permanent loss. Keep separate verified backups. File sizes and external filenames are not hidden.

## Limitations
One regular file per operation, no drag-and-drop or folder recursion yet, no cancel button; ordinary window close is disabled while a job runs. Hard-link-capable trusted directories required. Python/Tk/native library memory cannot be guaranteed erased. No secure deletion, no global memory limit across separate app instances, no defense against compromised hosts. On post-publication I/O failure the GUI distinguishes complete visible output from ordinary failure; inspect and verify before retrying. Forced process termination may leave private temporary plaintext. Use the core residual listing CLI for manual inspection. New suite IDs 257–260 retain research status. Do not use for irreplaceable/sensitive files until independent review.

## Evidence
Linux local Python 3.13.5, Tk 8.6, cryptography 46.0.4. Exact Stage 3 core blob ea669539162ecd9bb82203d58935451c6e3118b5. Four desktop orchestration tests passed. Real Tk window under Xvfb: mocked file-picker/modal interactions only; invoked actual GUI button, generated real key and ciphertext, restored >1 MiB public fixture, validated bytes, masked/cleared secrets and mode change. Windows packaged build and smoke on physical Windows not yet established. CI runs Linux GUI integration and Windows build on future workflow runs; actual status must be verified.
