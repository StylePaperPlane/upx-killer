# Real-sample regression baseline

Baseline source commit: `c59aa1a3a874ffa12f8955895e827a6ef82125e0`

All samples are external test data under
`D:\Users\31007\Desktop\TXHook.Server`. They are never committed or modified;
each run uses a complete temporary copy. The table records the green behavior
immediately before the multi-format backend refactor.

| Target | SHA-256 | Baseline result | Baseline artifact SHA-256 |
|---|---|---|---|
| `Math.exe` | `421814C185D116E57DFC9D76520DD00B4A6FB2FEE9D655DF5704DB29BB03BE26` | Completed; dumped stdout, stderr, and exit code exactly match source (exit 0) | `99E451E324DE342B88CC01F0BB80887F42F346984DC4B223C389C5137180A09F` |
| `nizhou.exe` | `126C022D3AD16C018F78262573652E25542F25B6FBA1FE640A5441E04BD068F3` | Completed; loader validation passed | `92C0B9EAC9CC55669F2989D0352329AC1FB60EAE5C5839BE6E925ED3A6388437` |
| `TXHook.exe` | `FF6F767D7BA0C5EDC7F0816CF7386AD06CECD69FF3AC033E47B6A0103987CCB9` | Completed; fixed-preferred-base behavior preserved | `608043722512576DB532369372F2A36C8B6CD98D2400C796AAB182CB3C59A0A2` |
| `xy_quiz.exe` | `AF3BA833233A4F1B9BB6CA88C2837CAE7345B309D5D362B3354551E9D0D25EA8` | Completed; 19 import descriptors restored; repaired process remains alive beyond validation window | `B1DBC91442C1F098A3ED7B92876FE454015417673E30A855243F100F20595A2C` |
| `main\Server.dll` | `4200CA27A4D742DC1CDC05442B505D442B2AA632F17E68D9DBD5C9AEA8E289A3` | Completed; isolated DLL load/unload validation passed with `zlib.dll` available from the copied dependency directory | `7752E44B03DA63983F687A3143FE2C47A6F3BB8E0A9B2AD57043BF03783615E` |
| `main\zlib.dll` | `DFEED6848C1CC1F46493960B2C83E0B557BE1793962326E5E3CEAB201CFED96B` | Completed; isolated DLL load/unload validation passed | `11240B72FA779D2AA2BC5B6469449FB8B94D17B894E308B1A927F6F03F6379B8` |

The baseline build was `Release|x64`; all native tests passed and the unpackaged
WinUI executable remained alive after direct launch from its release directory.
GUI applications were validated by bounded process survival and Job cleanup;
only `Math.exe` has deterministic console output suitable for byte-for-byte
stdout/stderr comparison.

Artifact hashes above identify the files captured during that baseline run;
they are not golden hashes. Repeated runs of the same build can differ because
the repaired image contains values observed from independently loaded processes.
Equivalence is therefore decided by outcome, structural/loader validation, and
observable program behavior rather than output-file byte identity.

## Post-refactor comparison

Tested on 2026-08-30 with Engine Host protocol v6:

| Target | Result compared with baseline |
|---|---|
| `Math.exe` | Completed; console output is exactly equal and both source and repaired image return 0 |
| `nizhou.exe` | Completed; loader validation passed |
| `TXHook.exe` | Completed; fixed-preferred-base path preserved |
| `xy_quiz.exe` | Completed; loader/process validation passed without `0xC0000005` |
| `main\Server.dll` | Completed; dependency-aware isolated load/unload validation passed |
| `main\zlib.dll` | Completed; isolated load/unload validation passed |

All six post-refactor jobs used temporary copies and returned protocol category
`None` with native code 0.

Post-refactor results must use these exact source hashes. A hash mismatch stops
the comparison and requires a new baseline instead of being reported as a pass.
