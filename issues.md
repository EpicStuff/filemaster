# Filemaster open issues

## Minor / pre-existing

### ISSUE-3: dead const `unknownExe` in `prompt.go`

`const unknownExe = ""` is declared but unused. Harmless; remove it when
next touching that file.

### ISSUE-4: unchecked `scanner.Err()` in `socket_source.go`

The `bufio.Scanner` loop in `socketSource.Run` doesn't check `scanner.Err()`
after the loop. The test/dev-only source makes this low impact, but it should
return or log the final scanner error for cleanliness.
