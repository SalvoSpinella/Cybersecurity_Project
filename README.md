
Un progetto didattico per PSP che simula uno sniffer di rete con modalità:
- Visualizzazione pacchetti
- Statistiche in tempo reale
- Modalità CTF (gioco educativo)
- Tic Tac Toe con vulnerabilità simulate

## Requisiti
- PSP SDK (`pspdev`)
- Emulatori (es. PPSSPP)
- Makefile compatibile PSP

## Compilazione
Utilizzare un container docker contenente tutte le applicazioni utili alla compilazione e analisi di moduli psp

sudo docker run -it --rm --name pspdev \
  -v "$HOME/<nome-cartella>":/pspdev \
  ghcr.io/pspdev/pspdev bash

