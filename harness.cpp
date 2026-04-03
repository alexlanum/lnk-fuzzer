// AFL++ harness — feeds mutated LNK files to CShellLink::Load (IPersistFile)
// and CShellLink::Resolve (IShellLinkW), both implemented in shell32.dll

#include <windows.h>
#include <shlobj.h>

// TODO: figure out how to connect Linux AFL++ harness to Windows