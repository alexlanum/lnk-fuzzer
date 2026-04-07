# Stuxnet

Code execution became possible merely by displaying the icon of a `.lnk` file.

The LinkTargetIDList contained three `SHITEMID` structures:

```
[SHITEMID]
	. cb 		  	= 20
	. abID[0] 	  	= 0x1F (root/CLSID)
	. abID[1]  	  	= 0x50 (sort order)
	. abID[2..17] 	= 20D04FE0-3AEA-1069-A2D8-08002B30309D (CLSID_MyComputer)
	
[SHITEMID]
	. cb 		  	= 20
	. abID[0]     	= 0x1F (root/CLSID)
	. abID[1]  	  	= 0x50 (sort order)
	. abID[2..17] 	= 21EC2020-3AEA-1069-A2DD-08002B30309D (CLSID_ControlPanel)

[SHITEMID]
	. cb 		    = 2096
	. abID[0]	    = UNKNOWN – ANCESTOR-BASED – Interpreted by CControlPanelFolder
	. abID[1..2093] = .cpl applet descriptor:
		. L"\\.\STORAGE#Volume#....\~WTR4141.tmp"
		. applet index
```

The parent of the malicious item was `CLSID_ControlPanel`. Shell Items are parsed according to their parent's class type byte, so the malicious lead invocation to the Control Panel namespace, where it was able to trigger the `.cpl` loading mechanism.

The `.cpl` applet loading protocol works as follows. When the `CControlPanelFolder` COM object in SHELL32 processes a `SHITEMID`, it needs to know which `.cpl` file to load and which applet index within that file to open. The internal descriptor that the Control Panel handler reads from the `abID[]` payload contains:

```
abID[0] = ?
abID[1..2093] =
	. CPL module path (Unicode string)
	. Applet index (0-based integer, selects which sub-applet in the CPL to invoke)
	. CPLINFO / NEWCPLINFO metadata
		. idIcon: resource ID for icon
		. idName: resource ID for display name
		. idInfo: resource ID for description
		. lData:  applet-specific data
	. Possible applet GUID
	. Possible display name string
	. Possible description string (CPL_NEWINQUIRE path)
```

The CPL module path field is of importance. When the Control Panel handler processes this item:

1. `CControlPanelFolder::ParseDisplayName` receives `SHITEMID` #3
2. `CControlPanelFolder::_GetPidlFromAppletId` extracts path from descriptor
3. `CPL_LoadCPLModule` calls  `LoadLibraryW(L"\\.\STORAGE#Volume#...\\~WTR4141.tmp")`
4. `DllMain` runs immediately (code execution)

The vulnerability: `CControlPanelFolder` called `LoadLibraryW` on the CPL path without validating whether it was a registered Control Panel applet. Any DLL path that reached this code path got loaded and executed. Microsoft's fix (`_IsRegisteredCPLApplet`) added a whitelist check so that only approved CPL files could load.

```c
// BEFORE PATCH (CVE-2010-2568 vulnerable):
// In CControlPanelFolder::GetUIObjectOf
HRESULT CControlPanelFolder::GetUIObjectOf(..., LPCITEMIDLIST pidl, ...) {
    // extract CPL path from pidl
    WCHAR szModule[MAX_PATH];
    _ExtractModulePath(pidl, szModule);
    
    // load it directly — no validation
    HMODULE hMod = LoadLibraryW(szModule);  // VULNERABLE
    // get icon from loaded module
    ...
}

// AFTER PATCH (MS10-046):
// Added CControlPanelFolder::_IsRegisteredCPLApplet
BOOL CControlPanelFolder::_IsRegisteredCPLApplet(LPCWSTR pszModule) {
    // check if the CPL path matches a registered applet:
    //   1. is it in %SystemRoot%\System32?
    //   2. is it registered in HKLM\...\Control Panel\Cpls?
    //   3. is it in the cached list of known CPL modules?
    // return TRUE only if it's on the whitelist
}

HRESULT CControlPanelFolder::GetUIObjectOf(..., LPCITEMIDLIST pidl, ...) {
    WCHAR szModule[MAX_PATH];
    _ExtractModulePath(pidl, szModule);
    
    // New whitelist check before loading
    if (!_IsRegisteredCPLApplet(szModule))
        return E_ACCESSDENIED;  // block unregistered CPL
    
    HMODULE hMod = LoadLibraryW(szModule);
    ...
}
```

Before patch: malicious DLL not registered anywhere on victim computer can be loaded as applet.

After patch: only registered CPL files can be loaded, such as:

- files in `%SystemRoot%\System32\` like `appwiz.cpl`, `desk.cpl`, or `sysdm.cpl`
- files listed in `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Control Panel\Cpls`
- files enumerated by the Shell's CPL cache during Control Panel initialization.



# CVE-2015-0096

The whitelist check from the Stuxnet patch was incomplete. An attacker could still craft an LNK file with a link path of exactly 257 characters containing embedded unescaped spaces + two target files (one with spaces, one without). The path parsing logic mishandled the spaces and resolved the malicious DLL, bypassing the whitelist. Same attack surface and `LoadLibraryW` call, just a different way past the check.

Microsoft patched this by tightening the path validation logic.


# CVE-2017-8464

The ExtraData section contained a `SpecialFolderDataBlock` which had a `SpecialFolderID = 3` (`CSIDL_CONTROLS`), which forced namespace resolution through the Control Panel handler, bypassing the CPL whitelist.

Specifically, the first child segment offset pointed to the `SHITEMID` in the LinkTargetIDList PIDL that contained the CPL path. The `SpecialFolderDataBlock` caused the Shell to think the item belonged to Control Panel, which changed resolution context and bypassed the whitelist.

The `SpecialFolderDataBlock` set `CSIDL_CONTROLS`and the `KnownFolderDataBlock` set the Control Panel `KNOWNFOLDERID` GUID. Both pointed to Control Panel to reinforce the namespace context switch.

Microsoft fixed this by hardening ExtraData block processing.

The CVE-2017-8464 attack surface is covered across three operators working together:
- `MUTATE_EXTRA_INJECT` — inject SpecialFolderDataBlock/KnownFolderDataBlock with unexpected folder IDs or GUIDs
- `MUTATE_OFFSET_ZERO`/`PAST_EOF`/`DESYNC` — corrupt the PIDL index offset inside those blocks so they point to wrong items
- `apply_specialfolder` / `apply_knownfolder` — corrupt the SpecialFolderID and KnownFolderID values directly (these are your upcoming `GROUP_SPECIALFOLDER` and `GROUP_KNOWNFOLDER` operators)