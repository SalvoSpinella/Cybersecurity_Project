TARGET = net_sniffer
OBJS = main.o tictactoe.o

INCDIR =
CFLAGS = -O2 -G0 -Wall
CXXFLAGS = $(CFLAGS)
ASFLAGS = $(CFLAGS)
LDFLAGS =

LIBDIR =
LIBS = -lpspkernel -lpspuser -lpspdebug -lpspdisplay -lpspctrl -lpspgu -lpspgum -lpspnet -lpspnet_inet



EXTRA_TARGETS = EBOOT.PBP
PSP_EBOOT_TITLE = Net Sniffer
PSP_EBOOT_ICON = ICON0.PNG

BUILD_PRX = 0
#PRX_EXPORTS = exports.exp

PSPSDK=$(shell psp-config --pspsdk-path)
include $(PSPSDK)/lib/build.mak

