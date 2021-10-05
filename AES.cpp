#include <iostream>
#include <iomanip>
#include "AES.h"

using namespace std;

//Sources include:
/*
https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf
https://www.ijser.org/researchpaper/Implementation-of-Advanced-Encryption-Standard-Algorithm.pdf
https://formaestudio.com/rijndaelinspector/archivos/Rijndael_Animation_v4_eng-html5.html
http://www.moserware.com/2009/09/stick-figure-guide-to-advanced.html
https://www.samiam.org/rijndael.html
https://www.youtube.com/watch?v=dRYHSf5A4lw

and various Wiki articles:
https://en.wikipedia.org/wiki/Advanced_Encryption_Standard
https://en.wikipedia.org/wiki/Rijndael_MixColumns
https://en.wikipedia.org/wiki/Finite_field

And more, however these were the primary articles.
The primary source document is the NIST official FIPS PUB 197 standard definition.
All other sources were supplementary.
*/

//TODO: Fix cout flags to not remain static, but save the existing flag, change it when needed, then revert it.
//TODO: Allow for inputting from, encryption of, and outputting to files
//TODO: Implement 192 and 256 bit keys
//TODO: Create a command line interface and handling program
//TODO: Create a proper API/Interface for use in future code
//TODO: Remove STD Namespace
//TODO: Make code production-ready by analyzing known vectors of attack on insecure implementations
//TODO: Add proper block slicing and padding
//TODO: Implement CBC
//TODO: Implement Equivalent Inverse Cipher

void AES::subBytes(unsigned char inputBlock[16], unsigned char (&outputBlock)[16])
{
    unsigned char b;
    unsigned char c;
    for(int a = 0; a < Nb; a++)
    {
        b = inputBlock[a] >> 4;
        c = inputBlock[a] & (8|4|2|1);
        outputBlock[a] = sbox[b][c];
    };
}

void AES::shiftRows(unsigned char inputBlock[16], unsigned char (&outputBlock)[16])
{
    for(int i = 0; i < 4; i++)
    {
        for(int j = 0; j < 4; j++)
        {
            outputBlock[(i+(4*j))%Nb] = inputBlock[(i+(4*j)+(i*4))%Nb];
        }
    }
}

void AES::mixColumns(unsigned char inputBlock[16], unsigned char (&outputBlock)[16])
{
    unsigned char a[4];
    unsigned char b[4];
    unsigned char c;
    unsigned char h;

    for(int d = 0; d < Nb; d+=4)
    {
        for(c = 0; c < 4; c++)
        {
            a[c] = inputBlock[c+d];
            h = (inputBlock[c+d] >> 7 & 1);
            b[c] = inputBlock[c+d] << 1;
            b[c] ^= h * 0x1b;
        }

        outputBlock[d] = b[0] ^ a[3] ^ a[2] ^ b[1] ^ a[1];
        outputBlock[d+1] = b[1] ^ a[0] ^ a[3] ^ b[2] ^ a[2];
        outputBlock[d+2] = b[2] ^ a[1] ^ a[0] ^ b[3] ^ a[3];
        outputBlock[d+3] = b[3] ^ a[2] ^ a[1] ^ b[0] ^ a[0];
    }
}

void AES::rotWord(unsigned char (&word)[4])
{
    unsigned char temp[4];
    memcpy(temp, word, 4);
    for(int i = 4; i > 0; i--)
    {
        temp[i-1] = word[(i)%4];
        
    };
    memcpy(word, temp, 4);
}

void AES::subWord(unsigned char (&word)[4])
{
    unsigned char temp[4];
    unsigned char b;
    unsigned char c;
    memcpy(temp, word, 4);
    for(int a = 0; a < 4; a++)
    {
        b = temp[a] >> 4;
        c = temp[a] & (8|4|2|1);
        word[a] = sbox[b][c];
    };
}

void AES::addRoundKey(unsigned char inputBlock[16], unsigned char (&outputBlock)[16])
{
    for(int i = 0; i < 16; i+=4)
    {
        for(int j = 0; j < 4; j++)
        {
            outputBlock[i+j] = Ks[(r*16)+i+j] ^ inputBlock[i+j];
        }
    }
}

void AES::invShiftRows(unsigned char inputBlock[16], unsigned char (&outputBlock)[16])
{
    for(int i = 0; i < 4; i++)
    {
        for(int j = 0; j < 4; j++)
        {
            outputBlock[(i+(4*j))%Nb] = inputBlock[((i+(4*j)-(i*4))+Nb)%Nb];
        }
    }
}

//Look up inverse of the affine transformation and multiplicative inverse in GF(2^8)
void AES::invSubBytes(unsigned char inputBlock[16], unsigned char (&outputBlock)[16])
{
    unsigned char b;
    unsigned char c;
    for(int a = 0; a < Nb; a++)
    {
        b = inputBlock[a] >> 4;
        c = inputBlock[a] & (8|4|2|1);
        outputBlock[a] = inv_sbox[b][c];
    };
}

unsigned char AES::gMul(unsigned char a, unsigned char b)
{
    unsigned char p = 0;
	unsigned char i;
	unsigned char h;
	for(i = 0; i < 8; i++) {
		if((b & 1) == 1) 
			p ^= a;
		h = (a & 0x80);
		a <<= 1;
		if(h == 0x80) 
			a ^= 0x1b;		
		b >>= 1;
	}
	return p;
}

void AES::invMixColumns(unsigned char inputBlock[16], unsigned char (&outputBlock)[16])
{
    unsigned char a[4];

    unsigned char c;
    unsigned char h;

    for(int d = 0; d < Nb; d+=4)
    {
        for(c = 0; c < 4; c++)
        {
            a[c] = inputBlock[c+d];
        }
        outputBlock[d] = gMul(a[0],0xe) ^ gMul(a[3],0x9) ^ gMul(a[2],0xd) ^ gMul(a[1],0xb);
        outputBlock[d+1] = gMul(a[1],0xe) ^ gMul(a[0],0x9) ^ gMul(a[3],0xd) ^ gMul(a[2],0xb);
        outputBlock[d+2] = gMul(a[2],0xe) ^ gMul(a[1],0x9) ^ gMul(a[0],0xd) ^ gMul(a[3],0xb);
        outputBlock[d+3] = gMul(a[3],0xe) ^ gMul(a[2],0x9) ^ gMul(a[1],0xd) ^ gMul(a[0],0xb);
    }
}



void AES::printKey(unsigned char round)
{
    string s;
    switch(inv)
    {
        case 0:
            s = "].k_sch \t";
            break;
        case 1:
            s ="].ik_sch \t";
            break;
    }
    cout << "round[" << dec << setw(2) << setfill(' ') << (unsigned int)round << hex << s;
    for(int j = 0; j < 16; j+=4)
    {
        for(int k = 0; k < 4; k++)
        {
            cout << setw(2) << setfill('0') << (unsigned int)Ks[(r*16)+j+k];
        }
    }
    cout << endl;
}


void AES::printOutput(unsigned char inputBlock[16], unsigned char type, unsigned char round)
{  
    cout << hex;
    string s;
    if(!inv)
    {
        switch(type)
        {
            case 0:
                s = "].input \t";
                break;
            case 2:
                s = "].start \t";
                break;
            case 3:
                s = "].s_box \t";
                break;
            case 4:
                s = "].s_row \t";
                break;
            case 5:
                s = "].m_col \t";
                break;
            case 6:
                s = "].output \t";
                break;
        };
    }else{
        switch(type)
        {
            case 7:
                s = "].iinput \t";
                break;
            case 9:
                s = "].istart \t";
                break;
            case 10:
                s = "].is_row \t";
                break;
            case 11:
                s = "].is_box \t";
                break;
            case 12:
                s = "].ik_add \t";
                break;
            case 13:
                s = "].ioutput \t";
                break;
        }
    }
    cout << "round[" << dec << setw(2) << setfill(' ') << (unsigned int)round << hex << s;

    for(int i = 0; i < 16; i+=4)
    {
        for(int j = 0; j < 4; j++)
        {
            cout << setw(2) << setfill('0') << (unsigned int)inputBlock[j+i];
        };
    };
    cout << endl;
}

void AES::keySchedule()
{
    unsigned char temp[4] = {0, 0, 0, 0};
    for(int i = 0; i < Nk[Kl]*4; i++)
    {
        Ks[i] = K[i];
    }
    for(int i = 1; i < Nr[Kl]+1; i++)
    {
        for(int j = 0; j < 4; j++)
        {
            for(int k = 0; k < 4; k++)
            {
                temp[k]=Ks[k+(i*Nb)+((j-1)*4)];
            }
            if(j == 0)
            {
                rotWord(temp);
                subWord(temp);
            }
            for(int k = 0; k < 4; k++)
            {
                temp[k]=Ks[k+(i*Nb)+((j-4)*4)] ^ temp[k];
                
                if(k==0&&j==0)
                {
                    temp[k] = temp[k] ^ Rcon[i-1];
                } else if(j==0) {
                    temp[k] = temp[k] ^ 0;
                }

                Ks[k+(i*Nb)+(j*4)]=temp[k];
            }

        }
    }
}

unsigned char* AES::Cipher(unsigned char testBlock[16], bool print)
{
    unsigned char testOutput[16];

    r = 0;
    keySchedule();

    if(print) printOutput(testBlock, 0, r);

    addRoundKey(testBlock, testOutput);
    memcpy(testBlock, testOutput, 16);
    if(print) printKey(r);

    r++;

    for(;r < Nr[Kl]; r++)
    {
        if(print) printOutput(testBlock, 2, r);

        subBytes(testBlock, testOutput);
        memcpy(testBlock, testOutput, 16);
        if(print) printOutput(testBlock, 3, r);

        shiftRows(testBlock, testOutput);
        memcpy(testBlock, testOutput, 16);
        if(print) printOutput(testBlock, 4, r);

        mixColumns(testBlock, testOutput);
        memcpy(testBlock, testOutput, 16);
        if(print) printOutput(testBlock, 5, r);

        addRoundKey(testBlock, testOutput);
        memcpy(testBlock, testOutput, 16);
        if(print) printKey(r);

    }

    if(print) printOutput(testBlock, 2, r);

    subBytes(testBlock, testOutput);
    memcpy(testBlock, testOutput, 16);
    if(print) printOutput(testBlock, 3, r);

    shiftRows(testBlock, testOutput);
    memcpy(testBlock, testOutput, 16);
    if(print) printOutput(testBlock, 4, r);

    addRoundKey(testBlock, testOutput);
    memcpy(testBlock, testOutput, 16);
    if(print) printKey(r);

    if(print) printOutput(testBlock,6,r);

    inv = 0;
    r = 0;
    return testBlock;
}

unsigned char* AES::invCipher(unsigned char testBlock[16], bool print)
{
    unsigned char testOutput[16];
    inv = 1;
    r = 10;
    int counter = 0;
    keySchedule();

    if(print) printOutput(testBlock, 7, counter);

    addRoundKey(testBlock, testOutput);
    memcpy(testBlock, testOutput, 16);
    if(print) printKey(counter);

    r--;
    counter++;

    for(;counter < Nr[Kl]; counter++)
    {

        printOutput(testBlock, 9, counter);

        invShiftRows(testBlock, testOutput);
        memcpy(testBlock, testOutput, 16);
        if(print) printOutput(testBlock, 10, counter);

        invSubBytes(testBlock, testOutput);
        memcpy(testBlock, testOutput, 16);
        if(print) printOutput(testBlock, 11, counter);

        addRoundKey(testBlock, testOutput);
        memcpy(testBlock, testOutput, 16);
        if(print) printKey(counter);

        if(print) printOutput(testBlock, 12, counter);

        invMixColumns(testBlock, testOutput);
        memcpy(testBlock, testOutput, 16);
        

        r--;

    }

    if(print) printOutput(testBlock, 9, counter);
    invShiftRows(testBlock, testOutput);
    memcpy(testBlock, testOutput, 16);
    if(print) printOutput(testBlock, 10, counter);

    invSubBytes(testBlock, testOutput);
    memcpy(testBlock, testOutput, 16);
    if(print) printOutput(testBlock, 11, counter);

    addRoundKey(testBlock, testOutput);
    memcpy(testBlock, testOutput, 16);
    if(print) printKey(counter);

    if(print) printOutput(testBlock, 13, counter);

    inv = 0;
    r = 0;
    return testBlock;
}

int main()
{

    cout << hex;

    cout << "PLAINTEXT:\t\tfff1a233443566377865aabac4ddaeff\nKEY:\t\t\t000102030405060708090a0b0c0d0e0f\n\n";

    unsigned char test[16] =
    {
        0xff, 0xf1, 0xa2, 0x33,
        0x44, 0x35, 0x66, 0x37,
        0x78, 0x65, 0xaa, 0xba,
        0xc4, 0xdd, 0xae, 0xff
    };
    unsigned char test2[16] =
    {
        0xff, 0xf1, 0xa2, 0x33,
        0x44, 0x35, 0x66, 0x37,
        0x78, 0x65, 0xaa, 0xba,
        0xc4, 0xdd, 0xae, 0xff
    };

    unsigned char* output;

    AES instance;
    
    cout << "CIPHER (ENCRYPT):\n";

    output = instance.Cipher(test, true);

    memcpy(test, output, 16);

    cout << "\n\nINVERSE CIPHER (DECRYPT):\n";

    output = instance.invCipher(test, true);

    memcpy(test, output, 16);

    cout << "\nPLAINTEXT:\t\tfff1a233443566377865aabac4ddaeff\nKEY:\t\t\t000102030405060708090a0b0c0d0e0f\n\n";

    return 0;
}