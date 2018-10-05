# IFRExtractor RS

Rust utility to extract UEFI IFR data found in a binary file into human-readable text.

# What is this IFR thing about?
UEFI Internal Form Representation (IFR) is a binary format that UEFI Human Interface Infrastructure (HII) subsystem uses to store strings, forms, images, animations and other things that eventually supposed to end up on BIOS Setup screen. In many cases there are multiple settings that are still present in IFR data, but not visible from BIOS Setup for various reasons, and IFR data can also help in finding which byte of which non-volatile storage available to UEFI corresponds to which firmware setting.
