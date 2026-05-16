# Digital Signature Android App

This Android application demonstrates how to implement secure data encryption and digital signatures using the **Android Keystore System**. It uses **AES-GCM** for encryption and **ECDSA** (Elliptic Curve Digital Signature Algorithm) for signing data.

## Features

- **Key Generation**: Generates and securely stores keys in the hardware-backed Android Keystore.
    - **AES-256-GCM**: Used for symmetric encryption of sensitive data.
    - **EC (secp256r1)**: Used for generating public/private key pairs for digital signatures.
- **Data Encryption**: Encrypts plaintext using AES-GCM with system-generated Initialization Vectors (IVs) to ensure randomized encryption.
- **Digital Signatures**: Signs the encrypted payload (IV + Ciphertext) using the private EC key to ensure data integrity and authenticity.
- **Verification & Decryption**: Includes local tests for verifying the signature with the public key and decrypting the data back to plaintext.

## Project Structure

- `CryptoManager.kt`: The core logic for encryption, decryption, signing, and verification.
- `KeysManger.kt`: Handles the generation and retrieval of keys from the Android Keystore.
- `MainActivity.kt`: Demonstrates the end-to-end flow:
    1. Key generation.
    2. Encrypting a JSON payload.
    3. Signing the encrypted result.
    4. Verifying the signature locally.
    5. Decrypting the data.

## Security Best Practices Implemented

- **Hardware-backed security**: Keys are stored in the Android Keystore, making them difficult to extract from the device.
- **Randomized Encryption**: Uses system-generated IVs for AES-GCM, preventing patterns in encrypted data.
- **Integrity Protection**: Signing the ciphertext ensures that any tampering with the encrypted data will be detected during verification.
- **Base64 Encoding**: Properly handles binary data (IVs, Ciphertext, Signatures) for safe transmission or storage.

## Requirements

- Android Studio Koala or newer.
- Minimum SDK: 24 (Android 7.0).
- Hardware support for Keystore (standard on most modern Android devices).

## Getting Started

1. Clone the repository.
2. Open the project in Android Studio.
3. Run the app on an emulator or physical device.
4. Check the **Logcat** (tag: `MainActivity`) to see the encryption, signature, and decryption results.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
