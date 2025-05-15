/* Custom MD5 hashing algorithm implementation. */

#include <stdlib.h>

// Auxilliary functions needed by the algorithm.
unsigned int F(unsigned int X, unsigned int Y, unsigned int Z) {
  return (((X) & (Y)) | ((~X) & (Z)));
}
unsigned int G(unsigned int X, unsigned int Y, unsigned int Z) {
  return (((X) & (Z)) | ((Y) & (~Z)));
}
unsigned int H(unsigned int X, unsigned int Y, unsigned int Z) {
  return ((X) ^ (Y) ^ (Z));
}
unsigned int I(unsigned int X, unsigned int Y, unsigned int Z) {
  return ((Y) ^ ((X) | (~Z)));
}
unsigned int ROTATE_LEFT(unsigned int x, unsigned int n) {
  return (((x) << (n)) | ((x) >> (32 - (n))));
}

// Allocate a memory space to hold the result hash.
char hash[33];

char* md5(unsigned char* plaintext) {
  /* -------------------- Process the input plaintext string. -------------------- */
  // Get the string length of the plaintext, in bits.
  register unsigned long long slen = 0;
  for (register unsigned long long i = 0; plaintext[i] != '\0'; i++) slen+=8;
  
  register unsigned long long ptlen = slen;
  
  // Copy the given string into a new array.
  unsigned char* X = malloc(64*(((slen+65)/512)+(((slen+65)%512) ? 1 : 0)));
  for (register unsigned long long i = 0; plaintext[i] != '\0'; i++) X[i] = plaintext[i];
  
  // Put in the required padding bit (technically byte).
  X[ptlen/8] = 0x80;
  ptlen+=8;
  
  // Pad the plaintext string if necessary.
  while ((ptlen<448) || (((ptlen+64) % 512) || (((ptlen+64)/512) != (((slen+65)/512)+(((slen+65)%512) ? 1 : 0))))) {
    X[ptlen/8] = 0;
	ptlen+=8;
  }
  
  // Add the 64-bit length to the end of the string.
  X[ptlen/8] = (slen&0xFF);
  X[(ptlen/8)+1] = ((slen >> 8)&0xFF);
  X[(ptlen/8)+2] = ((slen >> 16)&0xFF);
  X[(ptlen/8)+3] = ((slen >> 24)&0xFF);
  X[(ptlen/8)+4] = ((slen >> 32)&0xFF);
  X[(ptlen/8)+5] = ((slen >> 40)&0xFF);
  X[(ptlen/8)+6] = ((slen >> 48)&0xFF);
  X[(ptlen/8)+7] = (slen >> 56);
  
  // Update the string's length for the last time.
  ptlen+=64;
  
  // Put each 32-bit chunk into the correct byte order.
  for (register unsigned int i = 0; i < (ptlen/8); i+=4) {
    X[i] ^= X[i+3];
    X[i+3] ^= X[i];
    X[i] ^= X[i+3];
    X[i+1] ^= X[i+2];
    X[i+2] ^= X[i+1];
    X[i+1] ^= X[i+2];
  }
  
  /* -------------------- Initialization. -------------------- */
  // Initialize the 4 word buffer.
  register unsigned int A = 0x67452301;
  register unsigned int B = 0xefcdab89;
  register unsigned int C = 0x98badcfe;
  register unsigned int D = 0x10325476;
  
  register unsigned int AT = A;
  register unsigned int BT = B;
  register unsigned int CT = C;
  register unsigned int DT = D;
  
  unsigned int* Xt = malloc(sizeof(unsigned int)*16);
  
  /* -------------------- Perform the rounds. -------------------- */
  // For each 512 bit block in the string...
  for (register unsigned int i = 0; (i*8) < ptlen; i+=64) {
    // Break the block into 16 32-bit words.
    for (register unsigned int j = 0; j < 16; j++) {
      Xt[j] = ((((unsigned int)X[i+(j*4)])<<24) + (((unsigned int)X[i+(j*4)+1])<<16) + (((unsigned int)X[i+(j*4)+2])<<8) + ((unsigned int)X[i+(j*4)+3]));
    }

    // Initialize the buffer for this chunk.
    AT = A;
    BT = B;
    CT = C;
    DT = D;
	  
    // Round 1.
    A = B + ROTATE_LEFT((A + F(B,C,D) + Xt[0] + 0xd76aa478), 7);
    D = A + ROTATE_LEFT((D + F(A,B,C) + Xt[1] + 0xe8c7b756), 12);
    C = D + ROTATE_LEFT((C + F(D,A,B) + Xt[2] + 0x242070db), 17);
    B = C + ROTATE_LEFT((B + F(C,D,A) + Xt[3] + 0xc1bdceee), 22);

    A = B + ROTATE_LEFT((A + F(B,C,D) + Xt[4] + 0xf57c0faf), 7);
    D = A + ROTATE_LEFT((D + F(A,B,C) + Xt[5] + 0x4787c62a), 12);
    C = D + ROTATE_LEFT((C + F(D,A,B) + Xt[6] + 0xa8304613), 17);
    B = C + ROTATE_LEFT((B + F(C,D,A) + Xt[7] + 0xfd469501), 22);
	  
    A = B + ROTATE_LEFT((A + F(B,C,D) + Xt[8] + 0x698098d8), 7);
    D = A + ROTATE_LEFT((D + F(A,B,C) + Xt[9] + 0x8b44f7af), 12);
    C = D + ROTATE_LEFT((C + F(D,A,B) + Xt[10] + 0xffff5bb1), 17);
    B = C + ROTATE_LEFT((B + F(C,D,A) + Xt[11] + 0x895cd7be), 22);

    A = B + ROTATE_LEFT((A + F(B,C,D) + Xt[12] + 0x6b901122), 7);
    D = A + ROTATE_LEFT((D + F(A,B,C) + Xt[13] + 0xfd987193), 12);
    C = D + ROTATE_LEFT((C + F(D,A,B) + Xt[14] + 0xa679438e), 17);
    B = C + ROTATE_LEFT((B + F(C,D,A) + Xt[15] + 0x49b40821), 22);

    // Round 2.
    A = B + ROTATE_LEFT((A + G(B,C,D) + Xt[1] + 0xf61e2562), 5);
    D = A + ROTATE_LEFT((D + G(A,B,C) + Xt[6] + 0xc040b340), 9);
    C = D + ROTATE_LEFT((C + G(D,A,B) + Xt[11] + 0x265e5a51), 14);
    B = C + ROTATE_LEFT((B + G(C,D,A) + Xt[0] + 0xe9b6c7aa), 20);

    A = B + ROTATE_LEFT((A + G(B,C,D) + Xt[5] + 0xd62f105d), 5);
    D = A + ROTATE_LEFT((D + G(A,B,C) + Xt[10] + 0x02441453), 9);
    C = D + ROTATE_LEFT((C + G(D,A,B) + Xt[15] + 0xd8a1e681), 14);
    B = C + ROTATE_LEFT((B + G(C,D,A) + Xt[4] + 0xe7d3fbc8), 20);

    A = B + ROTATE_LEFT((A + G(B,C,D) + Xt[9] + 0x21e1cde6), 5);
    D = A + ROTATE_LEFT((D + G(A,B,C) + Xt[14] + 0xc33707d6), 9);
    C = D + ROTATE_LEFT((C + G(D,A,B) + Xt[3] + 0xf4d50d87), 14);
    B = C + ROTATE_LEFT((B + G(C,D,A) + Xt[8] + 0x455a14ed), 20);

    A = B + ROTATE_LEFT((A + G(B,C,D) + Xt[13] + 0xa9e3e905), 5);
    D = A + ROTATE_LEFT((D + G(A,B,C) + Xt[2] + 0xfcefa3f8), 9);
    C = D + ROTATE_LEFT((C + G(D,A,B) + Xt[7] + 0x676f02d9), 14);
    B = C + ROTATE_LEFT((B + G(C,D,A) + Xt[12] + 0x8d2a4c8a), 20);

    // Round 3.
    A = B + ROTATE_LEFT((A + H(B,C,D) + Xt[5] + 0xfffa3942), 4);
    D = A + ROTATE_LEFT((D + H(A,B,C) + Xt[8] + 0x8771f681), 11);
    C = D + ROTATE_LEFT((C + H(D,A,B) + Xt[11] + 0x6d9d6122), 16);
    B = C + ROTATE_LEFT((B + H(C,D,A) + Xt[14] + 0xfde5380c), 23);

    A = B + ROTATE_LEFT((A + H(B,C,D) + Xt[1] + 0xa4beea44), 4);
    D = A + ROTATE_LEFT((D + H(A,B,C) + Xt[4] + 0x4bdecfa9), 11);
    C = D + ROTATE_LEFT((C + H(D,A,B) + Xt[7] + 0xf6bb4b60), 16);
    B = C + ROTATE_LEFT((B + H(C,D,A) + Xt[10] + 0xbebfbc70), 23);

    A = B + ROTATE_LEFT((A + H(B,C,D) + Xt[13] + 0x289b7ec6), 4);
    D = A + ROTATE_LEFT((D + H(A,B,C) + Xt[0] + 0xeaa127fa), 11);
    C = D + ROTATE_LEFT((C + H(D,A,B) + Xt[3] + 0xd4ef3085), 16);
    B = C + ROTATE_LEFT((B + H(C,D,A) + Xt[6] + 0x04881d05), 23);

    A = B + ROTATE_LEFT((A + H(B,C,D) + Xt[9] + 0xd9d4d039), 4);
    D = A + ROTATE_LEFT((D + H(A,B,C) + Xt[12] + 0xe6db99e5), 11);
    C = D + ROTATE_LEFT((C + H(D,A,B) + Xt[15] + 0x1fa27cf8), 16);
    B = C + ROTATE_LEFT((B + H(C,D,A) + Xt[2] + 0xc4ac5665), 23);

    // Round 4.
    A = B + ROTATE_LEFT((A + I(B,C,D) + Xt[0] + 0xf4292244), 6);
    D = A + ROTATE_LEFT((D + I(A,B,C) + Xt[7] + 0x432aff97), 10);
    C = D + ROTATE_LEFT((C + I(D,A,B) + Xt[14] + 0xab9423a7), 15);
    B = C + ROTATE_LEFT((B + I(C,D,A) + Xt[5] + 0xfc93a039), 21);

    A = B + ROTATE_LEFT((A + I(B,C,D) + Xt[12] + 0x655b59c3), 6);
    D = A + ROTATE_LEFT((D + I(A,B,C) + Xt[3] + 0x8f0ccc92), 10);
    C = D + ROTATE_LEFT((C + I(D,A,B) + Xt[10] + 0xffeff47d), 15);
    B = C + ROTATE_LEFT((B + I(C,D,A) + Xt[1] + 0x85845dd1), 21);

    A = B + ROTATE_LEFT((A + I(B,C,D) + Xt[8] + 0x6fa87e4f), 6);
    D = A + ROTATE_LEFT((D + I(A,B,C) + Xt[15] + 0xfe2ce6e0), 10);
    C = D + ROTATE_LEFT((C + I(D,A,B) + Xt[6] + 0xa3014314), 15);
    B = C + ROTATE_LEFT((B + I(C,D,A) + Xt[13] + 0x4e0811a1), 21);

    A = B + ROTATE_LEFT((A + I(B,C,D) + Xt[4] + 0xf7537e82), 6);
    D = A + ROTATE_LEFT((D + I(A,B,C) + Xt[11] + 0xbd3af235), 10);
    C = D + ROTATE_LEFT((C + I(D,A,B) + Xt[2] + 0x2ad7d2bb), 15);
    B = C + ROTATE_LEFT((B + I(C,D,A) + Xt[9] + 0xeb86d391), 21);

    // Add the current chunk's buffer to the running total buffer.
    A += AT;
    B += BT;
    C += CT;
    D += DT;
  }
  
  /* -------------------- Return the result. -------------------- */
  
  // Properly order the output hash.
  A = ((A&0x000000FF)<<24) + ((A&0x0000FF00)<<8) + ((A&0x00FF0000)>>8) + ((A&0xFF000000)>>24);
  B = ((B&0x000000FF)<<24) + ((B&0x0000FF00)<<8) + ((B&0x00FF0000)>>8) + ((B&0xFF000000)>>24);
  C = ((C&0x000000FF)<<24) + ((C&0x0000FF00)<<8) + ((C&0x00FF0000)>>8) + ((C&0xFF000000)>>24);
  D = ((D&0x000000FF)<<24) + ((D&0x0000FF00)<<8) + ((D&0x00FF0000)>>8) + ((D&0xFF000000)>>24);
  
  hash[0] = ((A>>28) > 9) ? ((A>>28)-10)+'a' : (A>>28)+'0';
  hash[1] = ((A>>24&0x000f) > 9) ? ((A>>24&0x000f)-10)+'a' : (A>>24&0x000f)+'0';
  hash[2] = ((A>>20&0x000f) > 9) ? ((A>>20&0x000f)-10)+'a' : (A>>20&0x000f)+'0';
  hash[3] = ((A>>16&0x000f) > 9) ? ((A>>16&0x000f)-10)+'a' : (A>>16&0x000f)+'0';
  hash[4] = ((A>>12&0x000f) > 9) ? ((A>>12&0x000f)-10)+'a' : (A>>12&0x000f)+'0';
  hash[5] = ((A>>8&0x000f) > 9) ? ((A>>8&0x000f)-10)+'a' : (A>>8&0x000f)+'0';
  hash[6] = ((A>>4&0x000f) > 9) ? ((A>>4&0x000f)-10)+'a' : (A>>4&0x000f)+'0';
  hash[7] = ((A&0x000f) > 9) ? ((A&0x000f)-10)+'a' : (A&0x000f)+'0';
  
  hash[8] = ((B>>28) > 9) ? ((B>>28)-10)+'a' : (B>>28)+'0';
  hash[9] = ((B>>24&0x000f) > 9) ? ((B>>24&0x000f)-10)+'a' : (B>>24&0x000f)+'0';
  hash[10] = ((B>>20&0x000f) > 9) ? ((B>>20&0x000f)-10)+'a' : (B>>20&0x000f)+'0';
  hash[11] = ((B>>16&0x000f) > 9) ? ((B>>16&0x000f)-10)+'a' : (B>>16&0x000f)+'0';
  hash[12] = ((B>>12&0x000f) > 9) ? ((B>>12&0x000f)-10)+'a' : (B>>12&0x000f)+'0';
  hash[13] = ((B>>8&0x000f) > 9) ? ((B>>8&0x000f)-10)+'a' : (B>>8&0x000f)+'0';
  hash[14] = ((B>>4&0x000f) > 9) ? ((B>>4&0x000f)-10)+'a' : (B>>4&0x000f)+'0';
  hash[15] = ((B&0x000f) > 9) ? ((B&0x000f)-10)+'a' : (B&0x000f)+'0';
  
  hash[16] = ((C>>28) > 9) ? ((C>>28)-10)+'a' : (C>>28)+'0';
  hash[17] = ((C>>24&0x000f) > 9) ? ((C>>24&0x000f)-10)+'a' : (C>>24&0x000f)+'0';
  hash[18] = ((C>>20&0x000f) > 9) ? ((C>>20&0x000f)-10)+'a' : (C>>20&0x000f)+'0';
  hash[19] = ((C>>16&0x000f) > 9) ? ((C>>16&0x000f)-10)+'a' : (C>>16&0x000f)+'0';
  hash[20] = ((C>>12&0x000f) > 9) ? ((C>>12&0x000f)-10)+'a' : (C>>12&0x000f)+'0';
  hash[21] = ((C>>8&0x000f) > 9) ? ((C>>8&0x000f)-10)+'a' : (C>>8&0x000f)+'0';
  hash[22] = ((C>>4&0x000f) > 9) ? ((C>>4&0x000f)-10)+'a' : (C>>4&0x000f)+'0';
  hash[23] = ((C&0x000f) > 9) ? ((C&0x000f)-10)+'a' : (C&0x000f)+'0';
  
  hash[24] = ((D>>28) > 9) ? ((D>>28)-10)+'a' : (D>>28)+'0';
  hash[25] = ((D>>24&0x000f) > 9) ? ((D>>24&0x000f)-10)+'a' : (D>>24&0x000f)+'0';
  hash[26] = ((D>>20&0x000f) > 9) ? ((D>>20&0x000f)-10)+'a' : (D>>20&0x000f)+'0';
  hash[27] = ((D>>16&0x000f) > 9) ? ((D>>16&0x000f)-10)+'a' : (D>>16&0x000f)+'0';
  hash[28] = ((D>>12&0x000f) > 9) ? ((D>>12&0x000f)-10)+'a' : (D>>12&0x000f)+'0';
  hash[29] = ((D>>8&0x000f) > 9) ? ((D>>8&0x000f)-10)+'a' : (D>>8&0x000f)+'0';
  hash[30] = ((D>>4&0x000f) > 9) ? ((D>>4&0x000f)-10)+'a' : (D>>4&0x000f)+'0';
  hash[31] = ((D&0x000f) > 9) ? ((D&0x000f)-10)+'a' : (D&0x000f)+'0';
  
  hash[32] = '\0';
  
  free(X);
  free(Xt);
  
  return hash;
}
