#ifndef CLSIDS_H
#define CLSIDS_H

// CLSIDS with ShellFolder subkey
// enumerated from HKEY_CLASSES_ROOT\CLSID
// each one implements IShellFolder and can process SHITEMID.abID[] payload data

#include <stdint.h>

static const uint8_t KNOWN_SHELL_CLSIDS[][16] = {

};

#endif