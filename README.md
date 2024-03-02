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

## Features

- Simulated ransomware encryption within a controlled environment
- No risk to actual user data or system integrity
- Enhances understanding of ransomware operation and decryption techniques

## Disclaimer

EduRansW is developed strictly for educational purposes. Users must agree to use this tool and sourcecode responsibly and acknowledge its intent to promote cybersecurity education. WebSec B.V. assumes no liability for misuse of this software or any damages resulting from its use.

## Support and Feedback

For support, feedback, or more information, please visit [WebSec B.V.](https://websec.nl) or contact support@websec.nl.

Giving this repo a star also helps is get statistics about how much people like the project, allot of stars usually motivate us to release an even better version :-)

## License

This project is licensed under the Creative Commons Attribution-NonCommercial-ShareAlike (CC BY-NC-SA) LICENSE file for details.

## Reversing the Binary with IDA and decrypt the files (Spoiler)

While there are several methods to exploit this educational ransomware and achieve the same result, here is one way to do so: 

<details>
  <summary>Spoiler: Decrypting through Function Hooking</summary>
  
  Detailed explanation and insights can be found in the discussion on [security.forum](https://security.forum/index.php?threads/eduransw-writeup-1-how-to-decrypt-ransomware-with-api-call-hooking.4/#post-4).
</details>


## About WebSec B.V.

WebSec B.V. is committed to advancing cybersecurity knowledge and tools. For more information about our projects and initiatives, visit our [website](https://websec.nl/en).
