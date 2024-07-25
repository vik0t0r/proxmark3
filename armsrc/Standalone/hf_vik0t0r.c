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

static int saMifareCSetBlock(uint32_t arg0, uint32_t arg1, uint32_t arg2, uint8_t *datain) {
    // params
    uint8_t needWipe = arg0;
    // bit 0 - need get UID
    // bit 1 - need wupC
    // bit 2 - need HALT after sequence
    // bit 3 - need init FPGA and field before sequence
    // bit 4 - need reset FPGA and LED
    uint8_t workFlags = arg1;
    uint8_t blockNo = arg2;

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
    FpgaDownloadAndGo(FPGA_BITSTREAM_HF);
    uint64_t mfKey = 0xffffffffffff;

    // main loop
    for (;;) {
        WDT_HIT();

        // exit from standalone mode, just send a usbcommand
        if (data_available()) break;

        // wait for card to appear

        if (iso14443a_select_card(NULL, &vik0t0r_p_card, NULL, true, 0, true) == false) {
            FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
            LED_D_OFF();
            SpinDelay(500);
            continue;
        } else {
            Dbprintf("Found card with SAK: %02X, ATQA: %02X %02X, UID: ", vik0t0r_p_card.sak, vik0t0r_p_card.atqa[0], vik0t0r_p_card.atqa[1]);
            Dbhexdump(vik0t0r_p_card.uidlen, card.uid, 0);

        }

        // do your standalone stuff..
        Dbprintf("Looping");

    }
}