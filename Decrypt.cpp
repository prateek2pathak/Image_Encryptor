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
    cout << "Enter the encrypted image filename to decrypt: ";
    cin >> inputFilename;
    cout << "Enter the output filename for decrypted image: ";
    cin >> outputFilename;
    cout << "Enter the decryption key (in hex): ";
    cin >> keyHex;
    cout << "Enter the IV (in hex): ";
    cin >> ivHex;

    // Convert key and IV from hex to byte arrays
    SecByteBlock key(AES::DEFAULT_KEYLENGTH);
    SecByteBlock iv(AES::BLOCKSIZE);
    StringSource(keyHex, true, new HexDecoder(new ArraySink(key, key.size())));
    StringSource(ivHex, true, new HexDecoder(new ArraySink(iv, iv.size())));

    try {
        // Decrypt the image
        CBC_Mode<AES>::Decryption decryption;
        decryption.SetKeyWithIV(key, key.size(), iv);

        FileSource(inputFilename.c_str(), true,
            new StreamTransformationFilter(decryption,
                new FileSink(outputFilename.c_str())
            )
        );

        cout << "Decryption successful! Decrypted image saved as " << outputFilename << endl;
    } catch (const CryptoPP::Exception& e) {
        cerr << e.what() << endl;
        return 1;
    }

    return 0;
}

