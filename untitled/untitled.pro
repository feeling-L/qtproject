TEMPLATE = app
CONFIG += console
CONFIG -= app_bundle
CONFIG -= qt

SOURCES += \
        Debug/dictionary.c \
        Debug/iniparser.c \
        main.c


unix|win32: LIBS += -lpcap

DISTFILES += \
    Debug/llz.ini

HEADERS += \
    Debug/dictionary.h \
    Debug/iniparser.h
