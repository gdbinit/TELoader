# Change the following paths
#SDKPATH=CHANGME_AND_POINT_TO_THE_SDK_DIR
#LIBRARYPATH=CHANGEME_AND_POINT_TO_THE_IDAQ.APP_MACOS_FOLDER
# Sample path configuration
SDKPATH=/Applications/IDA\ Pro\ 6.8/idasdk68
LIBRARYPATH=/Applications/IDA\ Pro\ 6.8/idaq.app/Contents/MacOS/

SRC=teloader.cpp
OBJS=teloader.o
CC=g++
LD=g++

# binary is always i386
CFLAGS=-arch i386 -D__IDP__ -D__PLUGIN__ -c -D__MAC__ -I$(SDKPATH)/include $(SRC)
LDFLAGS=-arch i386 --shared $(OBJS) -L$(SDKPATH) -L$(SDKPATH)/bin -Wl -L$(LIBRARYPATH)

all: 32bits 64bits

32bits:
	$(CC) $(CFLAGS)
	$(LD) $(LDFLAGS) -lida -o teloader.lmc

64bits:
	$(CC) $(CFLAGS)	-D__EA64__
	$(LD) $(LDFLAGS) -lida64 -o teloader64.lmc64
