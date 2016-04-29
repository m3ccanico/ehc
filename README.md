# Introduction

Extract HTTP Content (EHC) extracts content from HTTP streams in PCAP files. It supports compressed and chunked content. It only extracts HTML, JS, and SWF content from streams on TCP ports 80, 8000, and 8080. Both is very easy to extend if required.

# Installation

EHC requires python, the pynids library, and the hexdump library.

## Ubuntu

Xgusix describes in his [blog](http://xgusix.com/blog/installing-pynids-in-ubuntu-12-10-x64/) how to install pynids on Ubuntu.

```bash
pip install hexdump
```

## Mac OSX

Get the library from [Jon Oberheide](https://jon.oberheide.org/pynids/). Unpack the archive and install it with

```bash
python setup.py build
sudo python setup.py install

pip install hexdump
```

# Usage

```bash
python ehc.py <file.pcap>
```

Select an output folder instead of the current working directory.
```bash
python ehc.py -o out <file.pcap>
```

Enable debugging when there are parsing issues (dumps the content as hexdump).
```bash
python ehc.py -d <file.pcap>
```
