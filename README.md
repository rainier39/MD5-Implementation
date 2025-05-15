# MD5-Implementation
A simple C header file which provides a function for computing the MD5 hash of a given string. Designed to be easy to use and as readable as possible.

# Usage
Place the md5.h file in the same directory as your C source files. Simply include the header file at the top of your C program like so:
`#include "md5.h"`
After that, you may call the md5 function, giving it a string (character array) as an input. It will return a string (character array) representing the hexadecimal digits of the resulting md5 hash. E.g:
```
char test[] = "test";
printf("%s\n", md5(test));
```
When compiled and executed, this prints the string `098f6bcd4621d373cade4e832627b4f6` which is the md5 hash of the "test" string.

# Version Information
Successfully compiled with gcc (Debian 12.2.0-14) 12.2.0. Should work with most C compilers, on most platforms. Would be trivially easy to modify so that it works in C++.
