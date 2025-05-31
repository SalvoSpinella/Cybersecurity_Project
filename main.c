#include <pspkernel.h>
#include <pspgu.h>
#include <pspgum.h>
#include <pspctrl.h>
#include <pspdisplay.h>
#include <pspiofilemgr.h>
#include <pspnet_inet.h>
#include <string.h>
#include <ctype.h>
#include <stdio.h>
#include <psprtc.h>
#include "tictactoe.h"


PSP_MODULE_INFO("NetSniffer", 0, 1, 0);
PSP_MAIN_THREAD_ATTR(THREAD_ATTR_USER | THREAD_ATTR_VFPU);

#define LOG_FILE "ms0:/log.txt"
#define MAX_LOG_LEN 128
#define MAX_PAYLOAD_LEN 128
#define MAX_PACKETS 1024
#define MAX_VISIBLE_PACKETS 10

#define UI_ORIGIN_X 60
#define UI_ORIGIN_Y 40
extern void run_runner_mode();

typedef struct {
    char summary[MAX_LOG_LEN];
    char protocol[8];
    char description[32];
    char src_ip[16];
    char dst_ip[16];
    char payload[MAX_PAYLOAD_LEN];
    int src_port;
    int dst_port;
    int length;
    int is_suspicious;
    int handled;
} PacketInfo;

PacketInfo packet_log[MAX_PACKETS];

int packet_count = 0;
int selected_index = 0;
int scroll_offset = 0;
int detailed_view = 0;
int stats_view = 0;
int button_pressed_last_frame = 0;
int current_screen = 0; // 0 = menu, 1 = sniffer, 2 = CTF
int menu_selected_index = 0;
int ctf_score = 0;
int ctf_errors = 0;
int ctf_handled = 0;
int ctf_total_suspicious = 0;
int ctf_done = 0;
int ctf_initialized = 0;
int ctf_failed=0;
void* fb = (void*)0x8800000;




const char *menu_items[] = {"Modalita' Sniffer","Modalita' CTF", "Tic Tac Toe","Esci"};
int menu_items_count = sizeof(menu_items) / sizeof(menu_items[0]);

unsigned int __attribute__((aligned(16))) list[262144];

typedef struct {
    short x, y, w, h;
    unsigned int color;
} GuiBox;

//Disegna un box con un colore specifico sulla schermata usando le primitive GU
void draw_box(GuiBox box) {
    //Struttura per i vertici con coordinate texture, colore e coordinate spaziali
    struct Vertex {
        float u, v;
        unsigned int color;
        float x, y, z;
    } __attribute__((aligned(4)));

    //Alloca spazio nella memoria grafica per 2 vertici
    struct Vertex* vertices = (struct Vertex*)sceGuGetMemory(2 * sizeof(struct Vertex));

    //Disattiva le texture e abilita il blending per semitrasparenza
    sceGuDisable(GU_TEXTURE_2D);
    sceGuEnable(GU_BLEND);
    sceGuBlendFunc(GU_ADD, GU_SRC_ALPHA, GU_ONE_MINUS_SRC_ALPHA, 0, 0);

    //Definisce due vertici per disegnare un rettangolo GU_SPRITES
    vertices[0] = (struct Vertex){0, 0, box.color, box.x, box.y, 0.0f};
    vertices[1] = (struct Vertex){0, 0, box.color, box.x + box.w, box.y + box.h, 0.0f};

    //Disegna il box come una sprite rettangolare con i vertici
    sceGuDrawArray(GU_SPRITES, GU_COLOR_8888 | GU_VERTEX_32BITF, 2, 0, vertices);

    // Disabilita il blending
    sceGuDisable(GU_BLEND);
}


// Inizializza il sistema grafico GU e imposta i buffer di disegno
void startGu() {
    //void* fb = (void*)0x8800000;

    //Inizializza il sistema grafico
    sceGuInit();
    sceGuStart(GU_DIRECT, list);
    //Imposta i buffer di disegno, display e profondità
    sceGuDrawBuffer(GU_PSM_8888, fb, 512);
    sceGuDispBuffer(480, 272, fb, 512);
    sceGuDepthBuffer((void*)0x110000, 512);
    //Imposta offset e viewport per centrare il sistema di coordinate
    sceGuOffset(2048 - (480 / 2), 2048 - (272 / 2));
    sceGuViewport(2048, 2048, 480, 272);
    sceGuDepthRange(65535, 0);
    //Abilita lo scissor test (limita il disegno all'area visibile)
    sceGuScissor(0, 0, 480, 272);
    sceGuEnable(GU_SCISSOR_TEST);
    //Disabilita il test di profondità (non serve per GUI 2D)
    sceGuDepthMask(1);
    sceGuDisable(GU_DEPTH_TEST);

    //Termina e sincronizza la configurazione GU
    sceGuFinish();
    sceGuSync(0, 0);
    sceDisplayWaitVblankStart();
    sceGuDisplay(GU_TRUE);

    //Inizializza schermo per il testo
    pspDebugScreenSetOffset(0);
    pspDebugScreenSetBase(fb);
    pspDebugScreenSetXY(0, 0);
    pspDebugScreenSetTextColor(0xFFFFFFFF);
    pspDebugScreenInit();
}


//Funzione hookata che salva ogni messaggio inviato via rete su file log.txt
size_t my_sceNetInetSend(int s, const void *msg, size_t len, int flags) {
    //Apre il file log in modalità append
    SceUID fd = sceIoOpen(LOG_FILE, PSP_O_WRONLY | PSP_O_CREAT | PSP_O_APPEND, 0777);
    if (fd >= 0) {
        //Scrive il messaggio e un ritorno a capo
        sceIoWrite(fd, msg, len);
        sceIoWrite(fd, "\n", 1);
        sceIoClose(fd);
    }

    //Chiama la funzione originale per inviare effettivamente il pacchetto
    return sceNetInetSend(s, msg, len, flags);
}


// Disegna la schermata principale con la lista dei pacchetti catturati
void draw_packet_list() {
    //Inizia un nuovo frame grafico
    sceGuStart(GU_DIRECT, list);
    sceGuClearColor(0xFF000033);  
    sceGuClearDepth(0);
    sceGuClear(GU_COLOR_BUFFER_BIT | GU_DEPTH_BUFFER_BIT);

    //Reimposta lo schermo testuale
    pspDebugScreenSetXY(0, 0);
    pspDebugScreenInit();

    //Disegna lo sfondo della lista pacchetti
    GuiBox bg = {
        .x = UI_ORIGIN_X - 8,
        .y = UI_ORIGIN_Y - 8,
        .w = 368,
        .h = 140 + (MAX_VISIBLE_PACKETS - 5) * 10,
        .color = 0x60101010  
    };
    draw_box(bg);

    //Titolo
    int title_x = UI_ORIGIN_X / 8;
    int title_y = UI_ORIGIN_Y / 10;
    pspDebugScreenSetXY(title_x, title_y);
    pspDebugScreenSetTextColor(0x88000000);
    pspDebugScreenPrintf("PSP NET SNIFFER");
    pspDebugScreenSetXY(title_x - 1, title_y - 1);
    pspDebugScreenSetTextColor(0xFFFF3030);
    pspDebugScreenPrintf("PSP NET SNIFFER");

    //Conteggio pacchetti
    char count_str[32];
    snprintf(count_str, sizeof(count_str), "Pacchetti: %d", packet_count);
    int str_len = strlen(count_str);
    int x_centered = (480 / 2 - (str_len * 8) / 2) / 8;
    pspDebugScreenSetXY(x_centered, (UI_ORIGIN_Y / 10) + 1);
    pspDebugScreenSetTextColor(0xFF00FF00);
    pspDebugScreenPrintf("%s", count_str);

    //Percentuale buffer usato
    int percentage = (packet_count * 100) / MAX_PACKETS;
    pspDebugScreenSetXY(UI_ORIGIN_X / 8, (UI_ORIGIN_Y / 10 + 2));
    pspDebugScreenSetTextColor(0xFFAAAAFF);
    pspDebugScreenPrintf("Buffer: %d%% pieno", percentage);

    //Mostra la lista pacchetti, evidenzia quello selezionato
    if (packet_count > 0) {
        for (int i = 0; i < MAX_VISIBLE_PACKETS; i++) {
            int index = scroll_offset + i;
            if (index >= packet_count) break;

            int screen_y = (UI_ORIGIN_Y / 10 + 3) + i;
            if (index == selected_index) {
                //Evidenzia il pacchetto selezionato
                GuiBox box = {
                    .x = UI_ORIGIN_X - 4,
                    .y = UI_ORIGIN_Y + 30 + i * 10 - 2,
                    .w = 360,
                    .h = 12,
                    .color = 0x40FFFFFF
                };
                draw_box(box);
                //Colore speciale se sospetto
                pspDebugScreenSetTextColor(packet_log[index].is_suspicious ? 0xFFFF5555 : 0xFFFFFF00);
            } else {
                pspDebugScreenSetTextColor(packet_log[index].is_suspicious ? 0xFFFF5555 : 0xFFFFFFFF);
            }

            //Stampa il pacchetto
            pspDebugScreenSetXY(UI_ORIGIN_X / 8, screen_y);
            pspDebugScreenPrintf("[%2d] %s", index + 1, packet_log[index].summary);
        }
    } else {
        //Nessun pacchetto da mostrare
        pspDebugScreenSetXY(UI_ORIGIN_X / 8, (UI_ORIGIN_Y / 10 + 3));
        pspDebugScreenSetTextColor(0xFFFF0000);
        pspDebugScreenPrintf("Nessun pacchetto disponibile.");
    }

    //Mostra i comandi
    pspDebugScreenSetXY(UI_ORIGIN_X / 8, (UI_ORIGIN_Y / 10 + 3 + MAX_VISIBLE_PACKETS + 1));
    pspDebugScreenSetTextColor(0xFFAAAAAA);
    pspDebugScreenPrintf("[TRI]Su [X]Giu [O]Dettaglio [SELECT]Stats [START]Esci");

    //Termina il frame
    sceGuFinish();
    sceGuSync(0, 0);
    sceDisplayWaitVblankStart();
}



//Disegna la schermata con i dettagli del pacchetto selezionato
void draw_packet_detail() {
    //Inizio disegno del frame
    sceGuStart(GU_DIRECT, list);
    sceGuClearColor(0xFF000000); 
    sceGuClearDepth(0);
    sceGuClear(GU_COLOR_BUFFER_BIT | GU_DEPTH_BUFFER_BIT);

    //Reimposta schermo testuale
    pspDebugScreenSetXY(0, 0);
    pspDebugScreenInit();

    //Disegna box di sfondo per i dettagli
    GuiBox bg = { .x = 10, .y = 10, .w = 460, .h = 252, .color = 0x80101010 };
    draw_box(bg);

    //Recupera pacchetto selezionato
    PacketInfo *pkt = &packet_log[selected_index];

    //Titolo
    pspDebugScreenSetXY(2, 2);
    pspDebugScreenSetTextColor(0xFFFF00FF);
    pspDebugScreenPrintf("Pacchetto #%d (dettaglio):", selected_index + 1);

    //Informazioni principali
    pspDebugScreenSetXY(2, 4);
    pspDebugScreenSetTextColor(0xFFFFFFFF);
    pspDebugScreenPrintf("Origine     : %s:%d", pkt->src_ip, pkt->src_port);
    pspDebugScreenSetXY(2, 5);
    pspDebugScreenPrintf("Destinazione: %s:%d", pkt->dst_ip, pkt->dst_port);
    pspDebugScreenSetXY(2, 6);
    pspDebugScreenPrintf("Protocollo  : %s", pkt->protocol);
    pspDebugScreenSetXY(2, 7);
    pspDebugScreenPrintf("Descrizione : %s", pkt->description);
    pspDebugScreenSetXY(2, 8);
    pspDebugScreenPrintf("Payload Len.: %d byte", pkt->length);

    //Allarme in caso di pacchetto sospetto
    if (pkt->is_suspicious) {
        pspDebugScreenSetXY(2, 9);
        pspDebugScreenSetTextColor(0xFFFF3333);
        pspDebugScreenPrintf("⚠ Attività sospetta: %s", pkt->description);
    }

    //Mostra il payload del pacchetto
    pspDebugScreenSetXY(2, 11);
    pspDebugScreenSetTextColor(0xFFAAAAFF);
    pspDebugScreenPrintf("Payload:\n%s", pkt->payload);

    //Comando per tornare al menu
    pspDebugScreenSetXY(2, 19);
    pspDebugScreenSetTextColor(0xFFCCCCCC);
    pspDebugScreenPrintf("[CIRCLE] Torna");

    //Fine frame
    sceGuFinish();
    sceGuSync(0, 0);
    sceDisplayWaitVblankStart();
}


//Disegna la schermata con le statistiche dei pacchetti catturati
void draw_statistics_screen() {
    int tcp = 0, udp = 0, icmp = 0;
    int port_usage[65536] = {0};  //Frequenza uso delle porte
    int max_port = 0, max_port_val = 0;

    //Calcola statistiche sui protocolli e sulle porte
    for (int i = 0; i < packet_count; i++) {
        if (strcmp(packet_log[i].protocol, "TCP") == 0) tcp++;
        else if (strcmp(packet_log[i].protocol, "UDP") == 0) udp++;
        else if (strcmp(packet_log[i].protocol, "ICMP") == 0) icmp++;

        port_usage[packet_log[i].dst_port]++;
        if (port_usage[packet_log[i].dst_port] > max_port_val) {
            max_port_val = port_usage[packet_log[i].dst_port];
            max_port = packet_log[i].dst_port;
        }
    }

    //Inizio frame
    sceGuStart(GU_DIRECT, list);
    sceGuClearColor(0xFF002200); 
    sceGuClearDepth(0);
    sceGuClear(GU_COLOR_BUFFER_BIT | GU_DEPTH_BUFFER_BIT);

    pspDebugScreenSetXY(0, 0);
    pspDebugScreenInit();

    //Titolo
    pspDebugScreenSetTextColor(0xFFFFFF00);
    pspDebugScreenPrintf("STATISTICHE PACCHETTI\n\n");

    //Statistiche protocolli
    pspDebugScreenSetTextColor(0xFFFFFFFF);
    pspDebugScreenPrintf("TCP : %d\n", tcp);
    pspDebugScreenPrintf("UDP : %d\n", udp);
    pspDebugScreenPrintf("ICMP: %d\n", icmp);

    //Porta più attiva
    pspDebugScreenPrintf("\nPorta piu' attiva: %d (%d pacchetti)\n", max_port, max_port_val);

    //Comando per tornare
    pspDebugScreenSetTextColor(0xFFCCCCCC);
    pspDebugScreenPrintf("\n[CIRCLE] Torna");

    //Fine frame
    sceGuFinish();
    sceGuSync(0, 0);
    sceDisplayWaitVblankStart();
}



const char *protocols[] = {"TCP", "UDP", "ICMP", "ARP", "SMTP", "POP3"};
const char *descriptions[] = {
    "HTTP GET", "DNS Query", "ACK", "Ping", "SYN", "FIN",
    "Mail Send", "Login Attempt", "ARP Who-Has", "TLS Handshake"
};
int dst_ports[] = {80, 53, 25, 110, 443, 23, 8080, 21};

//Genera pacchetti finti (simulazione) da mostrare nella UI
void generate_fake_packet(PacketInfo *pkt, int count) {
    //IP e porte generate pseudo-casualmente
    int src_a = 192, src_b = 168, src_c = 1, src_d = 10 + (count % 20);
    int dst_a = 8, dst_b = 8, dst_c = 8, dst_d = 8 + (count % 4);
    int src_port = 1024 + (count * 7) % 4000;
    int dst_port = dst_ports[count % (sizeof(dst_ports) / sizeof(int))];

    //Seleziona protocollo e descrizione fittizi
    const char *proto = protocols[count % (sizeof(protocols) / sizeof(protocols[0]))];
    const char *desc = descriptions[count % (sizeof(descriptions) / sizeof(descriptions[0]))];

    //Popola la struttura con i dati
    snprintf(pkt->src_ip, sizeof(pkt->src_ip), "%d.%d.%d.%d", src_a, src_b, src_c, src_d);
    snprintf(pkt->dst_ip, sizeof(pkt->dst_ip), "%d.%d.%d.%d", dst_a, dst_b, dst_c, dst_d);
    pkt->src_port = src_port;
    pkt->dst_port = dst_port;
    pkt->length = 20 + (count % 50);
    snprintf(pkt->protocol, sizeof(pkt->protocol), "%s", proto);
    snprintf(pkt->description, sizeof(pkt->description), "%s", desc);

    //Costruisce un payload simulato
    snprintf(pkt->payload, sizeof(pkt->payload),
             "%s /data%d HTTP/1.1\r\nHost: %s\r\n\r\n",
             strcmp(proto, "TCP") == 0 ? "GET" : "DATA", count % 100, pkt->dst_ip);

    //Mark pacchetti sospetti ogni 7 pacchetti
    pkt->is_suspicious = (count % 7 == 0);

    //Sintesi del pacchetto per la lista
    snprintf(pkt->summary, sizeof(pkt->summary),
             "%s:%d -> %s:%d [%s] %s%s",
             pkt->src_ip, pkt->src_port, pkt->dst_ip, pkt->dst_port,
             pkt->protocol, pkt->description,
             pkt->is_suspicious ? " [!]" : "");

    //Incrementa contatore globale CTF
    if (pkt->is_suspicious) {
        ctf_total_suspicious++;
    }
}


//Disegna il menu principale dell'applicazione
void draw_main_menu() {
    // Inizio frame
    sceGuStart(GU_DIRECT, list);
    sceGuClearColor(0xFF000000); 
    sceGuClearDepth(0);
    sceGuClear(GU_COLOR_BUFFER_BIT | GU_DEPTH_BUFFER_BIT);

    pspDebugScreenSetXY(0, 0);
    pspDebugScreenInit();

    //Titolo del progetto
    pspDebugScreenSetTextColor(0xFFFF00FF);
    pspDebugScreenPrintf("== CYBERSECURITY PROJECT ==\n\n");

    //Menu dinamico
    for (int i = 0; i < menu_items_count; i++) {
        if (i == menu_selected_index) {
            //Evidenzia voce selezionata
            pspDebugScreenSetTextColor(0xFFFFFF00);
            pspDebugScreenPrintf(" > %s\n", menu_items[i]);
        } else {
            pspDebugScreenSetTextColor(0xFFFFFFFF);
            pspDebugScreenPrintf("   %s\n", menu_items[i]);
        }
    }

    //Istruzioni comando
    pspDebugScreenSetTextColor(0xFFAAAAAA);
    pspDebugScreenPrintf("\n[TRI/X] Naviga  [CROSS] Seleziona");

    //Fine frame
    sceGuFinish();
    sceGuSync(0, 0);
    sceDisplayWaitVblankStart();
}



//Disegna la schermata della modalità CTF (Capture the Flag)
void draw_ctf_mode() {
    sceGuStart(GU_DIRECT, list);
    sceGuClearColor(0xFF000033); 
    sceGuClearDepth(0);
    sceGuClear(GU_COLOR_BUFFER_BIT | GU_DEPTH_BUFFER_BIT);

    pspDebugScreenSetXY(0, 0);
    pspDebugScreenInit();

    //Intestazione e spiegazione
    pspDebugScreenSetTextColor(0xFFFFFF00);
    pspDebugScreenPrintf("== MODALITA' CTF ==\n");
    pspDebugScreenPrintf("Trova e neutralizza i pacchetti sospetti!\n\n");

    //Score attuale
    pspDebugScreenSetTextColor(0xFF00FF00);
    pspDebugScreenPrintf("Score: %d   Errori: %d\n", ctf_score, ctf_errors);

    //Stato avanzamento
    pspDebugScreenSetTextColor(0xFFAAAAFF);
    pspDebugScreenPrintf("Pacchetti trovati: %d/%d\n\n", ctf_handled, ctf_total_suspicious);

    //Lista pacchetti visualizzati
    for (int i = 0; i < MAX_VISIBLE_PACKETS; i++) {
        int index = scroll_offset + i;
        if (index >= packet_count) break;

        PacketInfo *pkt = &packet_log[index];
        int y = 6 + i;

        if (index == selected_index) {
            //Evidenzia pacchetto selezionato
            GuiBox box = {.x = UI_ORIGIN_X - 4, .y = UI_ORIGIN_Y + 50 + i * 10 - 2, .w = 360, .h = 12, .color = 0x40FFFFFF};
            draw_box(box);
            pspDebugScreenSetTextColor(pkt->is_suspicious ? 0xFFFF5555 : 0xFFFFFF00);
        } else {
            pspDebugScreenSetTextColor(pkt->is_suspicious ? 0xFFFF5555 : 0xFFFFFFFF);
        }

        pspDebugScreenSetXY(UI_ORIGIN_X / 8, y);
        pspDebugScreenPrintf("[%2d] %s", index + 1, pkt->summary);
    }

    //Comandi
    pspDebugScreenSetTextColor(0xFFAAAAAA);
    pspDebugScreenSetXY(2, 20);
    pspDebugScreenPrintf("[TRI]Su [X]Giu [QUAD]Neutralizza  [START]Menu");

    //Messaggio di vittoria e FLAG
    if (ctf_done) {
        pspDebugScreenSetTextColor(0xFF00FF00);
        pspDebugScreenSetXY(2, 22);
        pspDebugScreenPrintf("  Hai trovato tutti i pacchetti sospetti!\n");
        pspDebugScreenPrintf("  FLAG: CCIT{w0w_s3i_un_g3n10_d3l_m4l3}");
    }

    sceGuFinish();
    sceGuSync(0, 0);
    sceDisplayWaitVblankStart();
}



int main(int argc, char *argv[]) {
    startGu();  //Inizializza grafica
    sceCtrlSetSamplingCycle(0);   //Modalità semplice lettura input
    sceCtrlSetSamplingMode(PSP_CTRL_MODE_DIGITAL);

    SceCtrlData pad;
    int invii_totali = 0;

    while (1) {
        //Legge input dal controller PSP
        sceCtrlReadBufferPositive(&pad, 1);
        int buttons = pad.Buttons;

        // ====== SCHERMATA MENU PRINCIPALE ======
        if (current_screen == 0) {
            //Navigazione su/giù
            if ((buttons & PSP_CTRL_TRIANGLE) && menu_selected_index > 0)
                menu_selected_index--;
            if ((buttons & PSP_CTRL_CROSS) && menu_selected_index < menu_items_count - 1)
                menu_selected_index++;

            // Selezione voce menu
            if ((buttons & PSP_CTRL_CIRCLE) && !(button_pressed_last_frame & PSP_CTRL_CIRCLE)) {
                if (menu_selected_index == 0) {         //Modalità Sniffer
                    current_screen = 1;
                    detailed_view = 0;
                    stats_view = 0;
                } else if (menu_selected_index == 1) {  //Modalità CTF
                    current_screen = 2;
                    ctf_score = 0;
                    ctf_errors = 0;
                    ctf_handled = 0;
                    ctf_total_suspicious = 0;
                    ctf_done = 0;
                    packet_count = 0;
                    invii_totali = 0;
                } else if (menu_selected_index == 2) {  //Modalità TicTacToe
                    detailed_view = 0;
                    stats_view = 0;
                    scroll_offset = 0;
                    selected_index = 0;
                    current_screen = 3;
                } else if (menu_selected_index == 3) {
                    break; //Esce dal programma
                }
            }

            draw_main_menu();
            button_pressed_last_frame = buttons;
            sceKernelDelayThread(150000);
            continue;
        }

        // ====== MODALITÀ SNIFFER ======
        if (current_screen == 1) {
            //Generazione pacchetti finti e log automatico
            if (!detailed_view && !stats_view && packet_count < MAX_PACKETS) {
                generate_fake_packet(&packet_log[packet_count], invii_totali);
                my_sceNetInetSend(0, packet_log[packet_count].summary, strlen(packet_log[packet_count].summary), 0);
                packet_count++;
                invii_totali++;
            }

            //Mostra dettaglio o statistiche
            if ((buttons & PSP_CTRL_CIRCLE) && !(button_pressed_last_frame & PSP_CTRL_CIRCLE)) {
                if (detailed_view || stats_view)
                    detailed_view = stats_view = 0;
                else
                    detailed_view = 1;
            }

            if ((buttons & PSP_CTRL_SELECT) && !(button_pressed_last_frame & PSP_CTRL_SELECT)) {
                stats_view = !stats_view;
                detailed_view = 0;
            }

            //Navigazione lista pacchetti
            if (!detailed_view && !stats_view) {
                if ((buttons & PSP_CTRL_TRIANGLE) && selected_index > 0) {
                    selected_index--;
                    if (selected_index < scroll_offset) scroll_offset = selected_index;
                }
                if ((buttons & PSP_CTRL_CROSS) && selected_index < packet_count - 1) {
                    selected_index++;
                    if (selected_index >= scroll_offset + MAX_VISIBLE_PACKETS)
                        scroll_offset = selected_index - MAX_VISIBLE_PACKETS + 1;
                }
            }

            //Torna al menu
            if ((buttons & PSP_CTRL_START) && !(button_pressed_last_frame & PSP_CTRL_START)) {
                current_screen = 0;
            }

            //Disegna la schermata corretta
            if (detailed_view) draw_packet_detail();
            else if (stats_view) draw_statistics_screen();
            else draw_packet_list();

            button_pressed_last_frame = buttons;
            sceKernelDelayThread(100000 + (invii_totali % 7) * 100000); //Delay variabile
        }

        // ====== MODALITÀ CTF ======
        if (current_screen == 2) {
            //Prima inizializzazione
            if (!ctf_initialized) {
                packet_count = 0;
                invii_totali = 0;
                for (int i = 0; i < 30; i++)
                    generate_fake_packet(&packet_log[i], invii_totali++);
                packet_count = 30;
                ctf_initialized = 1;
            }

            //Troppi errori: sfida fallita
            if (ctf_failed) {
                sceGuStart(GU_DIRECT, list);
                sceGuClearColor(0xFF000000);
                sceGuClear(GU_COLOR_BUFFER_BIT);
                pspDebugScreenSetXY(0, 0);
                pspDebugScreenInit();
                pspDebugScreenSetTextColor(0xFF00FF00);
                pspDebugScreenPrintf("Hai fallito la sfida.\nTroppi errori...\n\nTorno al menu...");
                sceGuFinish();
                sceGuSync(0, 0);
                sceDisplayWaitVblankStart();
                sceKernelDelayThread(3000000);

                //Reset stato
                current_screen = 0;
                ctf_initialized = 0;
                ctf_failed = 0;
                continue;
            }

            //Navigazione pacchetti
            if ((buttons & PSP_CTRL_TRIANGLE) && selected_index > 0) {
                selected_index--;
                if (selected_index < scroll_offset) scroll_offset = selected_index;
            }
            if ((buttons & PSP_CTRL_CROSS) && selected_index < packet_count - 1) {
                selected_index++;
                if (selected_index >= scroll_offset + MAX_VISIBLE_PACKETS)
                    scroll_offset = selected_index - MAX_VISIBLE_PACKETS + 1;
            }

            //Neutralizza pacchetto
            if ((buttons & PSP_CTRL_SQUARE) && !packet_log[selected_index].handled) {
                packet_log[selected_index].handled = 1;

                if (packet_log[selected_index].is_suspicious) {
                    ctf_score++;
                    ctf_handled++;
                } else {
                    ctf_errors++;
                }

                if (ctf_errors >= 3)
                    ctf_failed = 1;

                if (ctf_handled >= ctf_total_suspicious && !ctf_done)
                    ctf_done = 1;
            }

            //Torna al menu
            if ((buttons & PSP_CTRL_START) && !(button_pressed_last_frame & PSP_CTRL_START)) {
                current_screen = 0;
                ctf_initialized = 0;
            }

            draw_ctf_mode();
            button_pressed_last_frame = buttons;
            sceKernelDelayThread(150000);
        }

        // ====== MODALITÀ TICTACTOE ======
        if (current_screen == 3) {
            tictactoe_run();         //Esegue gioco
            current_screen = 0;      //Torna al menu
            continue;
        }
    }

    //Pulizia finale
    sceGuTerm();
    pspDebugScreenPrintf("\n\n                         Uscita dal programma.\n");
    sceKernelDelayThread(2000000);
    return 0;
}



