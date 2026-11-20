# Test fixes after the CSV change

- templates.test reads the .txt table the template now leaves (no CSV).
- sv44.test copies a real sleep file: under ksh93 and busybox `command -v sleep` is only a name.
