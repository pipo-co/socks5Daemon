#include "base64.h"

static char encodingTable[] = {
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
    'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
    'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
    'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
    'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
    'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
    'w', 'x', 'y', 'z', '0', '1', '2', '3',
    '4', '5', '6', '7', '8', '9', '+', '/'
};

static char decodingTable[128];

static bool decodingTableBuilt;

static void build_decoding_table();


size_t base64_encode(uint8_t in[], size_t len, char out[], bool trail) {

    size_t inIter = 0;
    size_t outIter = 0;
    int trailingCount = 3 - (len % 3);

    if(trailingCount == 3)
        trailingCount = 0;

    while(inIter + 2 < len) {

        out[outIter++] = encodingTable[(in[inIter] & 0xFC) >> 2];
        inIter++;

        out[outIter++] = encodingTable[((in[inIter - 1] & 0x03) << 4) | ((in[inIter] & 0xF0) >> 4)];
        inIter++;

        out[outIter++] = encodingTable[((in[inIter - 1] & 0x0F) << 2) | ((in[inIter] & 0xC0) >> 6)];
        inIter++;

        out[outIter++] = encodingTable[in[inIter - 1] & 0x3F];
    }

    if(inIter < len) {
        out[outIter++] = encodingTable[(in[inIter] & 0xFC) >> 2];
        inIter++;

        if(inIter < len) {
            out[outIter++] = encodingTable[((in[inIter - 1] & 0x03) << 4) | ((in[inIter] & 0xF0) >> 4)];
            out[outIter++] = encodingTable[(in[inIter] & 0x0F) << 2];
        }
        
        else {
            out[outIter++] = encodingTable[(in[inIter - 1] & 0x03) << 4];
        }
    }

    if(trail) {
        for(int i = 0; i < trailingCount; i++)
            out[outIter++] = '=';
    }

    out[outIter] = 0;

    return outIter;
}

size_t base64_decode(char in[], uint8_t out[]) {

    if(!decodingTableBuilt)
        build_decoding_table();

    size_t inIter = 0;
    size_t outIter = 0;


    while(in[inIter] != 0 && in[inIter] != '=') {

        out[outIter] = (decodingTable[ (int)in[inIter]] & 0x3F) << 2;
        inIter++;

        if(in[inIter] == 0 || in[inIter] == '=') {
            outIter++;
            break;
        }

        out[outIter++] |= (decodingTable[ (int)in[inIter]] & 0x30) >> 4;

        out[outIter] = (decodingTable[ (int)in[inIter]] & 0x0F) << 4;
        inIter++;

        if(in[inIter] == 0 || in[inIter] == '=') {
            outIter++;
            break;
        }

        out[outIter++] |= (decodingTable[ (int)in[inIter]] & 0x3C) >> 2;

        out[outIter] = (decodingTable[ (int)in[inIter]] & 0x03) << 6;
        inIter++;

        if(in[inIter] == 0 || in[inIter] == '=') {
            outIter++;
            break;
        }

        out[outIter++] |= decodingTable[ (int)in[inIter]] & 0x3F;
        inIter++;
    }

    return outIter;
}

static void build_decoding_table() {

    decodingTableBuilt = true;

    for (int i = 0; i < 64; i++)
        decodingTable[(int)encodingTable[i]] = i;
}
