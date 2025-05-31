#include <pspkernel.h>
#include <pspdebug.h>
#include <pspctrl.h>
#include <psprtc.h>
#include <string.h>
#include <stdio.h>
#include <pspiofilemgr.h>
#include <pspdisplay.h>
#include "tictactoe.h"

#define printf pspDebugScreenPrintf

char board[3][3];               //Griglia 3x3 del gioco
int current_player = 1;         //1 = X, 2 = O
int wins_x = 0, wins_o = 0, draws = 0;  //Statistiche
int cheat_mode = 0;             //Flag attivazione cheat


static void init_board() {
    memset(board, ' ', sizeof(board));  //Riempie la griglia con spazi vuoti
}


void cheat_input() {
    pspDebugScreenClear(); //Pulisce lo schermo
    pspDebugScreenSetXY(10, 14);
    pspDebugScreenSetTextColor(0xFFFF00FF);
    printf("Controllo cheat code da file...");

    SceUID fd = sceIoOpen("ms0:/cheat.txt", PSP_O_RDONLY, 0777);
    if (fd < 0) {
        //File non trovato
        pspDebugScreenSetXY(10, 16);
        pspDebugScreenSetTextColor(0xFFFF0000);
        printf("File cheat.txt non trovato.");
        cheat_mode = 0;
    } else {
        //Legge contenuto e verifica presenza di "WIN"
        char buffer[64] = {0};
        int bytes = sceIoRead(fd, buffer, sizeof(buffer) - 1);
        sceIoClose(fd);

        if (bytes > 0 && strstr(buffer, "WIN")) {
            cheat_mode = 1;
            pspDebugScreenSetXY(10, 16);
            pspDebugScreenSetTextColor(0xFF00FF00);
            printf("Cheat attivato!");
        } else {
            cheat_mode = 0;
            pspDebugScreenSetXY(10, 16);
            pspDebugScreenSetTextColor(0xFFFF0000);
            printf("Codice non valido.");
        }
    }

    sceDisplayWaitVblankStart();
    sceKernelDelayThread(2000000);  //Attende 2 secondi
}


void trigger_format_vulnerability() {
    SceUID fd = sceIoOpen("ms0:/format.txt", PSP_O_RDONLY, 0777);
    if (fd >= 0) {
        char vuln_buf[64];
        memset(vuln_buf, 0, sizeof(vuln_buf));
        sceIoRead(fd, vuln_buf, sizeof(vuln_buf) - 1);
        sceIoClose(fd);

        pspDebugScreenSetXY(5, 19);
        pspDebugScreenSetTextColor(0xFFFFFF00);
        printf(vuln_buf);  //VULNERABILITÀ: format string! Corretto;printf("%s",vuln_buf);
        pspDebugScreenSetTextColor(0xFFFFFFFF);

        sceDisplayWaitVblankStart();
        sceKernelDelayThread(2000000);
    }
}




int check_winner() {
    //Controllo righe e colonne
    for (int i = 0; i < 3; i++) {
        if (board[i][0] != ' ' && board[i][0] == board[i][1] && board[i][1] == board[i][2])
            return board[i][0];
        if (board[0][i] != ' ' && board[0][i] == board[1][i] && board[1][i] == board[2][i])
            return board[0][i];
    }
    //Controllo diagonali
    if (board[0][0] != ' ' && board[0][0] == board[1][1] && board[1][1] == board[2][2])
        return board[0][0];
    if (board[0][2] != ' ' && board[0][2] == board[1][1] && board[1][1] == board[2][0])
        return board[0][2];
    return 0;  //Nessun vincitore
}


int is_draw() {
    //Se c'è almeno uno spazio vuoto, non è pareggio
    for (int i = 0; i < 3; i++)
        for (int j = 0; j < 3; j++)
            if (board[i][j] == ' ')
                return 0;
    return 1;
}


void draw_static_elements() {
    pspDebugScreenClear();
    pspDebugScreenSetXY(23, 1);
    pspDebugScreenSetTextColor(0xFFFF00FF);
    printf("== TIC TAC TOE ==");
    pspDebugScreenSetTextColor(0xFFFFFFFF);
}



void draw_board_state(int cursor_x, int cursor_y, int blink_on) {
    //Calcola posizione della griglia al centro dello schermo
    int screen_width = 60;
    int grid_width = 13;
    int bx = (screen_width - grid_width) / 2;
    int by = 4;

    //Disegna griglia 3x3 con evidenziazione cursore
    for (int i = 0; i < 3; i++) {
        for (int j = 0; j < 3; j++) {
            int px = bx + j * 4 + 1;
            int py = by + i * 2;
            pspDebugScreenSetXY(px, py);

            char c = board[i][j];
            if (i == cursor_y && j == cursor_x) {
                if (blink_on) printf("[%c]", c == ' ' ? ' ' : c);
                else printf(" %c ", c);
            } else {
                printf(" %c ", c);
            }

            if (j < 2) {
                pspDebugScreenSetXY(px + 3, py);
                printf("|");
            }
        }

        if (i < 2) {
            pspDebugScreenSetXY(bx + 1, by + i * 2 + 1);
            printf("---+---+---");
        }
    }

    //Istruzioni, turno, stats
    const char *instructions = "Use D-Pad to move, X to place, START to exit";
    const char *current_lbl   = "Current:";
    char stats[64];
    snprintf(stats, sizeof(stats), "X: %d  O: %d  Pareggi: %d", wins_x, wins_o, draws);

    int instr_x = (screen_width - strlen(instructions)) / 2;
    int current_x = (screen_width - strlen(current_lbl) - 2) / 2;
    int stats_x = (screen_width - strlen(stats)) / 2;

    pspDebugScreenSetTextColor(0xFFFFFFFF);
    pspDebugScreenSetXY(instr_x, by + 7);
    printf("%s", instructions);

    pspDebugScreenSetXY(current_x, by + 8);
    pspDebugScreenSetTextColor(0xFF00FF00);
    printf("Current: %c", current_player == 1 ? 'X' : 'O');

    pspDebugScreenSetXY(stats_x, by + 9);
    pspDebugScreenSetTextColor(0xFFDD99FF);
    printf("%s", stats);

    if (cheat_mode) {
        const char *cheat = "\n!!! CHEAT MODE ATTIVO !!!";
        int cheat_x = (screen_width - strlen(cheat)) / 2;
        pspDebugScreenSetXY(cheat_x, by + 10);
        pspDebugScreenSetTextColor(0xFF2222FF);
        printf("%s", cheat);
    }

    pspDebugScreenSetTextColor(0xFFFFFFFF);
}


void tictactoe_run() {
    //Setup input
    sceCtrlSetSamplingCycle(0);
    sceCtrlSetSamplingMode(PSP_CTRL_MODE_DIGITAL);
    init_board();

    cheat_input();                  //Controlla cheat
    trigger_format_vulnerability(); //Esegue vulnerabilità format string

    int x = 0, y = 0;
    SceCtrlData pad;
    u64 last_input_time = 0, last_blink_time = 0;
    int blink_on = 1;

    draw_static_elements();

    while (1) {
        //Gestione cursore lampeggiante ogni secondo
        ScePspDateTime time;
        u64 tick;
        sceRtcGetCurrentClockLocalTime(&time);
        sceRtcGetTick(&time, &tick);
        if ((tick - last_blink_time) > 1000000) {
            blink_on = !blink_on;
            last_blink_time = tick;
        }

        draw_board_state(x, y, blink_on);
        sceDisplayWaitVblankStart();
        sceCtrlReadBufferPositive(&pad, 1);

        //Input debounce 150ms
        if ((tick - last_input_time) > 150000) {
            if (pad.Buttons & PSP_CTRL_START) break;
            if (pad.Buttons & PSP_CTRL_UP)    { y = (y + 2) % 3; last_input_time = tick; }
            if (pad.Buttons & PSP_CTRL_DOWN)  { y = (y + 1) % 3; last_input_time = tick; }
            if (pad.Buttons & PSP_CTRL_LEFT)  { x = (x + 2) % 3; last_input_time = tick; }
            if (pad.Buttons & PSP_CTRL_RIGHT) { x = (x + 1) % 3; last_input_time = tick; }

            if ((pad.Buttons & PSP_CTRL_CROSS) && board[y][x] == ' ') {
                board[y][x] = cheat_mode ? 'X' : (current_player == 1 ? 'X' : 'O');

                //Vittoria
                if (check_winner()) {
                    draw_board_state(x, y, 1);
                    pspDebugScreenSetXY(22, 18);
                    pspDebugScreenSetTextColor(0xFFFF0000);
                    printf("Player %c wins!", current_player == 1 ? 'X' : 'O');
                    if (current_player == 1) wins_x++; else wins_o++;
                    sceKernelDelayThread(3000000);
                    draw_static_elements();
                    init_board();
                    continue;
                }
                //Pareggio
                else if (is_draw()) {
                    draw_board_state(x, y, 1);
                    pspDebugScreenSetXY(24, 18);
                    pspDebugScreenSetTextColor(0xFFFFFF00);
                    printf("Pareggio!");
                    draws++;
                    sceKernelDelayThread(3000000);
                    draw_static_elements();
                    init_board();
                    continue;
                } else {
                    current_player = 3 - current_player;
                }

                last_input_time = tick;
            }
        }

        sceKernelDelayThread(5000);  //Sleep breve per evitare uso CPU
    }
}
