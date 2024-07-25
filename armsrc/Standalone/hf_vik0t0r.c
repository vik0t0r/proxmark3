#include "standalone.h" // standalone definitions
#include "proxmark3_arm.h"
#include "appmain.h"
#include "fpgaloader.h"
#include "util.h"
#include "dbprint.h"
#include "ticks.h"
#include "string.h"
#include "commonutil.h"
#include "iso14443a.h"
#include "mifarecmd.h"
#include "crc16.h"
#include "BigBuf.h"
#include "mifaresim.h"  // mifare1ksim
#include "mifareutil.h"

static uint8_t vik0t0r_uid[10];
static uint32_t vik0t0r_cuid;
static iso14a_card_select_t vik0t0r_p_card;


// maresenne twisted

#define STATE_VECTOR_LENGTH 624
#define STATE_VECTOR_M      397 /* changes to STATE_VECTOR_LENGTH also require changes to this */

typedef struct tagMTRand {
  uint32_t mt[STATE_VECTOR_LENGTH];
  int32_t index;
} MTRand;

#define UPPER_MASK		0x80000000
#define LOWER_MASK		0x7fffffff
#define TEMPERING_MASK_B	0x9d2c5680
#define TEMPERING_MASK_C	0xefc60000

inline static void m_seedRand(MTRand* rand, uint32_t seed) {
  /* set initial seeds to mt[STATE_VECTOR_LENGTH] using the generator
   * from Line 25 of Table 1 in: Donald Knuth, "The Art of Computer
   * Programming," Vol. 2 (2nd Ed.) pp.102.
   */
  rand->mt[0] = seed & 0xffffffff;
  for(rand->index=1; rand->index<STATE_VECTOR_LENGTH; rand->index++) {
    rand->mt[rand->index] = (6069 * rand->mt[rand->index-1]) & 0xffffffff;
  }
}

/**
* Creates a new random number generator from a given seed.
*/
MTRand seedRand(uint32_t seed) {
  MTRand rand;
  m_seedRand(&rand, seed);
  return rand;
}

/**
 * Generates a pseudo-randomly generated long.
 */
uint32_t genRandLong(MTRand* rand) {

  uint32_t y;
  static uint32_t mag[2] = {0x0, 0x9908b0df}; /* mag[x] = x * 0x9908b0df for x = 0,1 */
  if(rand->index >= STATE_VECTOR_LENGTH || rand->index < 0) {
    /* generate STATE_VECTOR_LENGTH words at a time */
    int32_t kk;
    if(rand->index >= STATE_VECTOR_LENGTH+1 || rand->index < 0) {
      m_seedRand(rand, 4357);
    }
    for(kk=0; kk<STATE_VECTOR_LENGTH-STATE_VECTOR_M; kk++) {
      y = (rand->mt[kk] & UPPER_MASK) | (rand->mt[kk+1] & LOWER_MASK);
      rand->mt[kk] = rand->mt[kk+STATE_VECTOR_M] ^ (y >> 1) ^ mag[y & 0x1];
    }
    for(; kk<STATE_VECTOR_LENGTH-1; kk++) {
      y = (rand->mt[kk] & UPPER_MASK) | (rand->mt[kk+1] & LOWER_MASK);
      rand->mt[kk] = rand->mt[kk+(STATE_VECTOR_M-STATE_VECTOR_LENGTH)] ^ (y >> 1) ^ mag[y & 0x1];
    }
    y = (rand->mt[STATE_VECTOR_LENGTH-1] & UPPER_MASK) | (rand->mt[0] & LOWER_MASK);
    rand->mt[STATE_VECTOR_LENGTH-1] = rand->mt[STATE_VECTOR_M-1] ^ (y >> 1) ^ mag[y & 0x1];
    rand->index = 0;
  }
  y = rand->mt[rand->index++];
  y ^= (y >> 11);
  y ^= (y << 7) & TEMPERING_MASK_B;
  y ^= (y << 15) & TEMPERING_MASK_C;
  y ^= (y >> 18);
  return y;
}

// Function to convert a single hex character to its decimal value
int hexCharToDecimal(char hexChar) {
    if (hexChar >= '0' && hexChar <= '9') {
        return hexChar - '0';
    } else if (hexChar >= 'A' && hexChar <= 'F') {
        return hexChar - 'A' + 10;
    } else if (hexChar >= 'a' && hexChar <= 'f') {
        return hexChar - 'a' + 10;
    } else {
        return -1; // Invalid character
    }
}

// Function to convert a hexadecimal string to a char array
void hexStringToByteArray(const char *hexString, char *byteArray) {
    for (int i = 0; i < 16; i++) {
        byteArray[i] = (hexCharToDecimal(hexString[2 * i]) << 4) 
                        | hexCharToDecimal(hexString[2 * i + 1]);
    }
}

static int saMifareCSetBlock(uint32_t needWipe0, uint32_t workFlags1, uint32_t blockNo2, uint8_t *datain) {
    // params
    uint8_t needWipe = needWipe0;
    // bit 0 - need get UID
    // bit 1 - need wupC
    // bit 2 - need HALT after sequence
    // bit 3 - need init FPGA and field before sequence
    // bit 4 - need reset FPGA and LED
    uint8_t workFlags = workFlags1;
    uint8_t blockNo = blockNo2;

    // card commands
    uint8_t wupC1[] = {0x40};
    uint8_t wupC2[] = {0x43};
    uint8_t wipeC[] = {0x41};

    // variables
    uint8_t isOK = 0;
    uint8_t d_block[18] = {0x00};

    uint8_t receivedAnswer[MAX_MIFARE_FRAME_SIZE];
    uint8_t receivedAnswerPar[MAX_MIFARE_PARITY_SIZE];

    // reset FPGA and LED
    if (workFlags & 0x08) {
        iso14443a_setup(FPGA_HF_ISO14443A_READER_LISTEN);
        set_tracing(false);
    }

    while (true) {
        // get UID from chip
        if (workFlags & 0x01) {
            if (!iso14443a_select_card(vik0t0r_uid, &vik0t0r_p_card, &vik0t0r_cuid, true, 0, true)) {
                DbprintfEx(FLAG_NEWLINE, "Can't select card");
                break;
            };

            if (mifare_classic_halt(NULL)) {
                DbprintfEx(FLAG_NEWLINE, "Halt error");
                break;
            };
        };

        // reset chip
        if (needWipe) {
            ReaderTransmitBitsPar(wupC1, 7, 0, NULL);
            if (!ReaderReceive(receivedAnswer, receivedAnswerPar) || (receivedAnswer[0] != 0x0a)) {
                DbprintfEx(FLAG_NEWLINE, "wupC1 error");
                break;
            };

            ReaderTransmit(wipeC, sizeof(wipeC), NULL);
            if (!ReaderReceive(receivedAnswer, receivedAnswerPar) || (receivedAnswer[0] != 0x0a)) {
                DbprintfEx(FLAG_NEWLINE, "wipeC error");
                break;
            };

            if (mifare_classic_halt(NULL)) {
                DbprintfEx(FLAG_NEWLINE, "Halt error");
                break;
            };
        };

        // chaud
        // write block
        if (workFlags & 0x02) {
            ReaderTransmitBitsPar(wupC1, 7, 0, NULL);
            if (!ReaderReceive(receivedAnswer, receivedAnswerPar) || (receivedAnswer[0] != 0x0a)) {
                DbprintfEx(FLAG_NEWLINE, "wupC1 error");
                break;
            };

            ReaderTransmit(wupC2, sizeof(wupC2), NULL);
            if (!ReaderReceive(receivedAnswer, receivedAnswerPar) || (receivedAnswer[0] != 0x0a)) {
                DbprintfEx(FLAG_NEWLINE, "wupC2 errorv");
                break;
            };
        }

        if ((mifare_sendcmd_short(NULL, CRYPT_NONE, 0xA0, blockNo, receivedAnswer, receivedAnswerPar, NULL) != 1) || (receivedAnswer[0] != 0x0a)) {
            DbprintfEx(FLAG_NEWLINE, "write block send command error");
            break;
        };

        memcpy(d_block, datain, 16);
        AddCrc14A(d_block, 16);
        ReaderTransmit(d_block, sizeof(d_block), NULL);
        if ((ReaderReceive(receivedAnswer, receivedAnswerPar) != 1) || (receivedAnswer[0] != 0x0a)) {
            DbprintfEx(FLAG_NEWLINE, "write block send data error");
            break;
        };

        if (workFlags & 0x04) {
            if (mifare_classic_halt(NULL)) {
                DbprintfEx(FLAG_NEWLINE, "Halt error");
                break;
            };
        }

        isOK = 1;
        break;
    }

    if ((workFlags & 0x10) || (!isOK)) {
        FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
    }

    return isOK;
}

void ModInfo(void) {
    DbpString("  CHANGE UID OF GEN 1A CARDS to something random");
}

void RunMod(void) {
    // led show
    StandAloneMode();

    // Do you target LF or HF?
    uint64_t mfKey = 0xffffffffffff;

    LED_A_OFF();
    LED_B_OFF();
    LED_C_OFF();
    LED_D_OFF();

    // main loop
    for (;;) {
        WDT_HIT();

        // exit from standalone mode, just send a usbcommand
        if (data_available()) break;

        //int button_pressed = BUTTON_HELD(1000);

        //if (button_pressed == BUTTON_SINGLE_CLICK){




            Dbprintf("button pressed, start processing");
            iso14443a_setup(FPGA_HF_ISO14443A_READER_MOD);
            set_tracing(false);
            
            // wait for card
            LED_B_ON();

            while (iso14443a_select_card(NULL, &vik0t0r_p_card, NULL, true, 0, true) == false) {
                //Dbprintf("No card found");
                SpinDelay(500);
            }
            LED_B_OFF();
            // card in field
            Dbprintf("Found card with SAK: %02X, ATQA: %02X %02X, UID: ", vik0t0r_p_card.sak, vik0t0r_p_card.atqa[0], vik0t0r_p_card.atqa[1]);
            Dbhexdump(vik0t0r_p_card.uidlen, vik0t0r_p_card.uid, 0);
            if (vik0t0r_p_card.uidlen != 4){
                Dbprintf("7 byte uid not supported");
                continue;
            }
            FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);

            // generate data to write
            uint8_t block0[16]; 
            char* block0String = "AAAAAAAABB08040004A15CB4EA021C90";
            hexStringToByteArray(block0String, (char*) &block0);


            uint16_t uid_sum = vik0t0r_p_card.uid[0]*100;
            uid_sum += vik0t0r_p_card.uid[1] *  1;
            uid_sum += vik0t0r_p_card.uid[2] * 10;
            uid_sum += vik0t0r_p_card.uid[3] * 1;

            uint16_t lowerBytesTickCount = (uint16_t)(GetTickCount() & 0xFFFF);


            uint32_t seed = ((uint32_t)uid_sum << 16) | (uint32_t)lowerBytesTickCount;
            
            MTRand prng = seedRand(seed);


            // set UID
            block0[0] = genRandLong(&prng) & 0xFF;

            block0[1] = genRandLong(&prng) & 0xFF;

            block0[2] = genRandLong(&prng) & 0xFF;

            block0[3] = genRandLong(&prng) & 0xFF;


            // set BCC
            block0[4] = block0[0] ^ block0[1] ^ block0[2] ^ block0[3];

            Dbprintf("BLOCK0: ");
            Dbhexdump(16, block0, 0);

            // WRITE DATA
            int flags = 0x08 + 0x02 + 0x04 + 0x10;
            saMifareCSetBlock(0, flags & 0xFE, 0, block0);

            // cleanup

            FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);

            SpinDelay(1000);
            SpinDelay(1000);
            SpinDelay(1000);
            SpinDelay(1000);
            SpinDelay(1000);
       // }
    }
}