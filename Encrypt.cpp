#include <iostream>
#include <fstream>
#include <string>
#include <cryptopp/aes.h>
#include <cryptopp/filters.h>
#include <cryptopp/hex.h>
#include <cryptopp/modes.h>
#include <cryptopp/files.h>
using namespace std;
using namespace CryptoPP;


int main() {
    // Input variables
    string inputFilename, outputFilename, keyHex, ivHex;

    // Accept inputs
    cout << "Enter the image filename to encrypt: ";
    cin >> inputFilename;
    cout << "Enter the output filename for encrypted image: ";
    cin >> outputFilename;
    cout << "Enter the encryption key (in hex): ";
    cin >> keyHex;
    cout << "Enter the IV (in hex): ";
    cin >> ivHex;

    // Convert key and IV from hex to byte arrays
    SecByteBlock key(AES::DEFAULT_KEYLENGTH);
    SecByteBlock iv(AES::BLOCKSIZE);
    StringSource(keyHex, true, new HexDecoder(new ArraySink(key, key.size())));
    StringSource(ivHex, true, new HexDecoder(new ArraySink(iv, iv.size())));

    try {
        // Encrypt the image
        CBC_Mode<AES>::Encryption encryption;
        encryption.SetKeyWithIV(key, key.size(), iv);

        FileSource(inputFilename.c_str(), true,
            new StreamTransformationFilter(encryption,
                new FileSink(outputFilename.c_str())
            )
        );

        cout << "Encryption successful! Encrypted image saved as " << outputFilename << endl;
    } catch (const CryptoPP::Exception& e) {
        cerr << e.what() << endl;
        return 1;
    }

    return 0;
}

