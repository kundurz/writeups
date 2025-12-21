# Security Writeups & Binary Exploitation Analysis

This repository contains technical writeups focused on binary exploitation, low-level program analysis, and common vulnerability classes in C/C++ programs.

In many of these writeups, the emphasis is on **understanding root causes**,  **compiler and ABI behaviour**, and **defensive reasoning**, rather than publishing full exploit payloads or step-by-step solutions.

## Scope and Intent
* Writeups focus on **vulnerabiility analysis**, not exploit automation
* In certain cases, platform-specific details are intentionally abstracted
* Payloads, offsets, and exploit scripts may be omitted by design
* The goal is transferable understanding, not challenge completion

This repository is also intended as a **learning and analysis portfolio**

---

## Repository Structure
* `pico/` - Writeups derived from CTF challenges on `picoctf.org`
* `ctf-practice` - Platform-agnostic analysis of pwn-style challenges and vulnerability patterns.

Each writeup is self-contained and typically includes:
* Initial static and dynamic analysis
* Root-cause vulnerability explanation
* Impact discussion
* Defensive considerations

---

## Tooling
* `gdb`
* `checksec`
* `file`
* `objdump`

Specific tools are noted within individual writeups where relevant.

*This repository is updated incrementally as part of ongoing learning.*
