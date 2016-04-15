# Introduction

Extract HTTP Content (EHC) extracts content from HTTP streams in PCAP files.

# Installation

EHC only needs python and the pynids library.

## Ubuntu

Xgusix describes in his [blog](http://xgusix.com/blog/installing-pynids-in-ubuntu-12-10-x64/) how to install pynids on Ubuntu.

## Mac OSX

Get the library from [Jon Oberheide](https://jon.oberheide.org/pynids/). Unpack the archive and install it with

```bash
python setup.py build
sudo python setup.py install
```

# Execution

```bash
python ehc.py <file.pcap>
```

