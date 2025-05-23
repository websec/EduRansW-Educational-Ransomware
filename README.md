# EduRansW-Simulation

EduRansW is an innovative educational tool aimed at providing a practical learning experience in understanding, decrypting, and combating ransomware threats. Developed by WebSec B.V., it simulates real-world ransomware behavior, allowing users to engage in reverse engineering and decryption activities without any risk to personal data or systems.

## Getting Started

### Prerequisites
- Windows 10 or newer
- C++ Reds (If the application doesn't work for any reason)
- MFC libraries x86 & x64 (From Visual Studio Installer, you can download it under Individual Components)

### Installation
1. Visit [https://websec.nl/downloads](https://websec.nl/downloads) to download the latest version of EduRansW.
2. Extract the downloaded ZIP file to your preferred location.
3. Run `RansWSimulator.exe` to start the simulation.

## How It Works

EduRansW creates a secure, simulated environment where a directory named "CryptPath" is automatically generated. This directory acts as the target for the simulated ransomware attack, where files are encrypted. The challenge for users is to reverse-engineer the application, decrypt the encrypted files, and understand the mechanisms of ransomware attacks.

## PDB File

Note: a PDB file would pretty much never be present with real-life malware scenario's, we only included it in this repo so that you can understand what it this (What the differences are between debugging with PDB and without PDB)

## Features

- Simulated ransomware encryption within a controlled environment
- No risk to actual user data or system integrity
- Enhances understanding of ransomware operation and decryption techniques

## Disclaimer

EduRansW is developed strictly for educational purposes. Users must agree to use this tool and sourcecode responsibly and acknowledge its intent to promote cybersecurity education. WebSec B.V. assumes no liability for misuse of this software or any damages resulting from its use.

## Support and Feedback

For support, feedback, or more information, please visit [WebSec B.V.](https://websec.nl) or contact contact@websec.nl.

Giving this repo a star also helps us get statistics about how much people like the project, allot of stars usually motivate us to release an even better version :-)

## License

This project is licensed under the Creative Commons Attribution-NonCommercial-ShareAlike (CC BY-NC-SA) LICENSE file for details.


## About WebSec B.V.

WebSec B.V. is committed to advancing cybersecurity knowledge and tools. For more information about our projects and initiatives, visit our [website](https://websec.nl/en).
