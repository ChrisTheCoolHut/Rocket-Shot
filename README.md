# Rocket Shot

Backwards program slice stitching for automatic CTF problem solving.

Rocket Shot uses [angr](https://github.com/angr/angr) to concolically analyze basic blocks in a given program, running from the start of the block to the end, looking for interactions with a file descriptor. When reaching that condition, the basic block's control flow graph predessor's are "stitched" into the exploration path and then n-predessor based paths are explored attempting to reveal more modified file descriptor contents. This process continually iterates until terminated with Ctrl+C.

This technique is inspired in part by angr's [Backward Slice analyzer](https://docs.angr.io/built-in-analyses/backward_slice). 

[![asciicast](https://asciinema.org/a/208750.png)](https://asciinema.org/a/208750)

## Installing
Rocket Shot has been tested on Ubuntu 16.04 and the install script is setup for Ubuntu 12.04 to Ubuntu 18.04

    ./install.sh
    
## Usage
Rocket Shot is a python script which accepts a binary as an argument with optional basic block timeout settings, and an optional required string match input.

```
(rocket_shot) chris@ubuntu:~/Tools/auto-re$ python rocket_shot.py -h
usage: rocket_shot.py [-h] [--timeout TIMEOUT] [--string STRING] FILE

positional arguments:
  FILE

optional arguments:
  -h, --help            show this help message and exit
  --timeout TIMEOUT, -t TIMEOUT
  --string STRING, -s STRING
```
## Examples
Checkout the samples.sh file. The file contains a small handful of challenges.

Or any of the reverseing based angr example problems at [here](https://github.com/angr/angr-doc/tree/master/examples) or [here](https://github.com/angr/angr-doc/blob/master/docs/more-examples.md)
```
#!/bin/bash
#PicoCTF 2014 Reverseing
python rocket_shot.py challenges/bitpuzzle -t 15 -s flag
#UMDCTF 2017 Reverseing
python rocket_shot.py challenges/lockpicksim -t 15 -s Flag
```
