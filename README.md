# pwinit_unstrip-libc
To unstrip any version of libc integrated with your binary files..
---
# Compile

```bash
gcc pwninit.c fieldId.c -o pwninit
# you can also set it global command by copying to bin folder
```


# Run 

* pwninit 	`<binary file > ` # that directory must contain with the associated libc.so and linker file for the binary.