/*
 *   _____    ___
 *  |_   _|  | __|
 *    | |    | _|
 *   _|_|_   |___|
 * _|"""""|_|"""""|
 * "`-0-0-'"`-0-0-'
 *   _                         _
 *  | |      ___    __ _    __| |    ___      _ _
 *  | |__   / _ \  / _` |  / _` |   / -_)    | '_|
 *  |____|  \___/  \__,_|  \__,_|   \___|   _|_|_
 * _|"""""|_|"""""|_|"""""|_|"""""|_|"""""|_|"""""|
 * "`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'
 *
 * (c) 2015, fG! - reverser@put.as - http://reverse.put.as
 * 
 * An IDA loader for TE binaries from SEC/PEI EFI phases
 * IDA 6.8 or older can't properly load these binaries
 *
 * The first time you use this software you are required to write the following sentence
 * somewhere (text editor is fine):
 * 
 * "Ilfak is a douchebag!"
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 * derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * teloader.cpp
 *
 */

#include <ida.hpp>
#include <fpro.h>
#include <idp.hpp>
#include <loader.hpp>
#include <name.hpp>
#include <bytes.hpp>
#include <offset.hpp>
#include <segment.hpp>
#include <srarea.hpp>
#include <fixup.hpp>
#include <entry.hpp>
#include <auto.hpp>
#include <diskio.hpp>
#include <kernwin.hpp>

#include "idaldr.h"
#include "guids.h"

#define VERSION "1.0"

#pragma pack(push, 1)

// Basic types
#define UINT8  uint8_t
#define UINT16 uint16_t
#define UINT32 uint32_t
#define UINT64 uint64_t
#define UINTN  unsigned int
#define VOID   void

// Only I386 images are supported now
#define IMAGE_FILE_MACHINE_I386     0x014c
#define IMAGE_FILE_MACHINE_X64      0x8664

#define EFI_IMAGE_DOS_SIGNATURE     0x5A4D     // MZ
#define EFI_IMAGE_PE_SIGNATURE      0x00004550 // PE
#define EFI_IMAGE_TE_SIGNATURE      0x5A56     // VZ

// COFF file header (object and image)
typedef struct _EFI_IMAGE_FILE_HEADER {
    UINT16  Machine;
    UINT16  NumberOfSections;
    UINT32  TimeDateStamp;
    UINT32  PointerToSymbolTable;
    UINT32  NumberOfSymbols;
    UINT16  SizeOfOptionalHeader;
    UINT16  Characteristics;
} EFI_IMAGE_FILE_HEADER;

// Characteristics
#define EFI_IMAGE_FILE_RELOCS_STRIPPED      0x0001  // Relocation info stripped from file
#define EFI_IMAGE_FILE_EXECUTABLE_IMAGE     0x0002  // File is executable  (i.e. no unresolved external references)
#define EFI_IMAGE_FILE_LINE_NUMS_STRIPPED   0x0004  // Line numbers stripped from file
#define EFI_IMAGE_FILE_LOCAL_SYMS_STRIPPED  0x0008  // Local symbols stripped from file
#define EFI_IMAGE_FILE_BYTES_REVERSED_LO    0x0080  // Bytes of machine word are reversed
#define EFI_IMAGE_FILE_32BIT_MACHINE        0x0100  // 32 bit word machine
#define EFI_IMAGE_FILE_DEBUG_STRIPPED       0x0200  // Debugging info stripped from file in .DBG file
#define EFI_IMAGE_FILE_SYSTEM               0x1000  // System File
#define EFI_IMAGE_FILE_DLL                  0x2000  // File is a DLL
#define EFI_IMAGE_FILE_BYTES_REVERSED_HI    0x8000  // Bytes of machine word are reversed

// Header Data Directories.
typedef struct _EFI_IMAGE_DATA_DIRECTORY {
    UINT32  VirtualAddress;
    UINT32  Size;
} EFI_IMAGE_DATA_DIRECTORY;

// Directory Entries
#define EFI_IMAGE_DIRECTORY_ENTRY_EXPORT      0
#define EFI_IMAGE_DIRECTORY_ENTRY_IMPORT      1
#define EFI_IMAGE_DIRECTORY_ENTRY_RESOURCE    2
#define EFI_IMAGE_DIRECTORY_ENTRY_EXCEPTION   3
#define EFI_IMAGE_DIRECTORY_ENTRY_SECURITY    4
#define EFI_IMAGE_DIRECTORY_ENTRY_BASERELOC   5
#define EFI_IMAGE_DIRECTORY_ENTRY_DEBUG       6
#define EFI_IMAGE_DIRECTORY_ENTRY_COPYRIGHT   7
#define EFI_IMAGE_DIRECTORY_ENTRY_GLOBALPTR   8
#define EFI_IMAGE_DIRECTORY_ENTRY_TLS         9
#define EFI_IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG 10

#define EFI_IMAGE_NUMBER_OF_DIRECTORY_ENTRIES 16

// Section Table. This table immediately follows the optional header.
typedef struct _EFI_IMAGE_SECTION_HEADER {
    UINT8 Name[8];
    union {
        UINT32  PhysicalAddress;
        UINT32  VirtualSize;
    } Misc;
    UINT32  VirtualAddress;
    UINT32  SizeOfRawData;
    UINT32  PointerToRawData;
    UINT32  PointerToRelocations;
    UINT32  PointerToLinenumbers;
    UINT16  NumberOfRelocations;
    UINT16  NumberOfLinenumbers;
    UINT32  Characteristics;
} EFI_IMAGE_SECTION_HEADER;

// Header format for TE images, defined in the PI Specification 1.0.
typedef struct {
    UINT16                    Signature;            // The signature for TE format = "VZ"
    UINT16                    Machine;              // From original file header
    UINT8                     NumberOfSections;     // From original file header
    UINT8                     Subsystem;            // From original optional header
    UINT16                    StrippedSize;         // Number of bytes we removed from header
    UINT32                    AddressOfEntryPoint;  // Offset to entry point -- from original optional header
    UINT32                    BaseOfCode;           // From original image -- required for ITP debug
    UINT64                    ImageBase;            // From original file header (ORLY?)
    EFI_IMAGE_DATA_DIRECTORY  DataDirectory[2];     // Only base relocation and debug directories
} EFI_IMAGE_TE_HEADER;

// Data directory indexes in TE image header
#define EFI_IMAGE_TE_DIRECTORY_ENTRY_BASERELOC  0
#define EFI_IMAGE_TE_DIRECTORY_ENTRY_DEBUG      1

const char *efi_types =
"struct EFI_IMAGE_DATA_DIRECTORY {\n"
"    unsigned int  VirtualAddress;\n"
"    unsigned int  Size;\n"
"};\n"
"struct EFI_IMAGE_TE_HEADER { \n"
"unsigned short                    Signature;\n"
"unsigned short                   Machine;\n"
"unsigned char                     NumberOfSections;\n"
"unsigned char                     Subsystem;\n"
"unsigned short                    StrippedSize;\n"
"unsigned int                    AddressOfEntryPoint;\n"
"unsigned int                    BaseOfCode;\n"
"unsigned long long                    ImageBase;\n"
"struct EFI_IMAGE_DATA_DIRECTORY  DataDirectory[2];\n"
"};\n"
"struct EFI_IMAGE_SECTION_HEADER {\n"
"    unsigned char Name[8];\n"
"    unsigned int  VirtualSize;\n"
"    unsigned int  VirtualAddress;\n"
"    unsigned int  SizeOfRawData;\n"
"    unsigned int  PointerToRawData;\n"
"    unsigned int  PointerToRelocations;\n"
"    unsigned int  PointerToLinenumbers;\n"
"    unsigned short  NumberOfRelocations;\n"
"    unsigned short  NumberOfLinenumbers;\n"
"    unsigned int  Characteristics;\n"
"};\n";

static tid_t efi_image_data_directory_struct;
static tid_t efi_image_te_header_struct;
static tid_t efi_image_section_header_struct;

static bool idaapi init_loader_options(linput_t*) {
    //set the processor type
//    set_processor_type("metapc", SETPROC_ALL|SETPROC_FATAL);
    return true;
}

void
add_types(void)
{
    til_t *t = new_til("efi.til", "efi header types");
    parse_decls(t, efi_types, msg, HTI_PAK1);
    sort_til(t);
    efi_image_data_directory_struct = import_type(t, -1, "EFI_IMAGE_DATA_DIRECTORY");
    efi_image_te_header_struct = import_type(t, -1, "EFI_IMAGE_TE_HEADER");
    efi_image_section_header_struct = import_type(t, -1, "EFI_IMAGE_SECTION_HEADER");
    free_til(t);
}

/*
 * helper function to find GUIDs in data segment and label them
 */
void
find_guids(ea_t start, ea_t end)
{
    uint32_t table_size = sizeof(guid_table)/sizeof(*guid_table);
    ea_t current_addr = start;
    int match = 0;
    /* go over all the data segment searching for GUIDs */
    while (current_addr < end)
    {
        /* match against table entries */
        for (uint32_t i = 0; i < table_size; i++)
        {
            EFI_GUID tmp;
            get_many_bytes(current_addr, &tmp, sizeof(EFI_GUID));
            if (tmp.Data1 == guid_table[i].guid.Data1 &&
                tmp.Data2 == guid_table[i].guid.Data2 &&
                tmp.Data3 == guid_table[i].guid.Data3 &&
                memcmp(tmp.Data4, guid_table[i].guid.Data4, sizeof(tmp.Data4)) == 0)
            {
                set_name(current_addr, (const char*)guid_table[i].name, SN_CHECK);
                doDwrd(current_addr, 4);
                doDwrd(current_addr+4, 4);
                doDwrd(current_addr+8, 4);
                doDwrd(current_addr+12, 4);
                static char string[256] = {0};
                qsnprintf(string, sizeof(string), "%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X",
                         guid_table[i].guid.Data1, guid_table[i].guid.Data2, guid_table[i].guid.Data3,
                         guid_table[i].guid.Data4[0], guid_table[i].guid.Data4[1], guid_table[i].guid.Data4[2], guid_table[i].guid.Data4[3],
                         guid_table[i].guid.Data4[4], guid_table[i].guid.Data4[5], guid_table[i].guid.Data4[6], guid_table[i].guid.Data4[7]);
                set_cmt(current_addr, string, 0);
                match = 1;
                break;
            }
        }
        /* no need to check all 16 bytes if we found a match */
        if (match)
        {
            current_addr += sizeof(EFI_GUID);
            match = 0;
        }
        else
        {
            current_addr++;
        }
    }
}

/* verify if we can process the target file
 * return true if yes
 * false otherwise
 */
int idaapi
accept_file(linput_t *li, char fileformatname[MAX_FILE_FORMAT_NAME], int n)
{
    if (n != 0)
    {
        return 0;
    }
    qlseek(li, 0);
    EFI_IMAGE_TE_HEADER teHeader = {0};
    if (qlread(li, &teHeader, sizeof(EFI_IMAGE_TE_HEADER)) == sizeof(EFI_IMAGE_TE_HEADER) &&
        teHeader.Signature == EFI_IMAGE_TE_SIGNATURE)
    {
        msg("Signature: 0x%hx\n", teHeader.Signature);
        msg("Machine: 0x%hx\n", teHeader.Machine);
        msg("Number of Sections: 0x%hhx\n", teHeader.NumberOfSections);
        msg("Subsystem: 0x%hhx\n", teHeader.Subsystem);
        msg("Stripped size: 0x%hx\n", teHeader.StrippedSize);
        msg("Address of EntryPoint: 0x%0x\n", teHeader.AddressOfEntryPoint);
        msg("Base of code: 0x%x\n", teHeader.BaseOfCode);
        msg("Image base: 0x%llx\n", teHeader.ImageBase);
        qstrncpy(fileformatname, "TE put.as Loader", MAX_FILE_FORMAT_NAME);
        return true;
    }
    return 0;
}

/*
 * this is where we finally load the file and create segments and other processing
 */
void idaapi
load_file(linput_t *li, ushort neflags, const char *fileformatname)
{
    /* reset file position to 0 - accept_file changed it? */
    qlseek(li, 0);
    /* add header structures */
    add_types();
    create_filename_cmt();
    /* process header and create its own segment */
    EFI_IMAGE_TE_HEADER teHeader = {0};
    if (qlread(li, &teHeader, sizeof(EFI_IMAGE_TE_HEADER)) != sizeof(EFI_IMAGE_TE_HEADER))
    {
        warning("Failed to read TE header\n");
        return;
    }
    /* read the data to the database */
    /* header starts at 0 */
    ea_t delta = teHeader.StrippedSize - sizeof(EFI_IMAGE_TE_HEADER);
    ea_t header_start = teHeader.ImageBase - delta;
    /* header total size is the TE header plus all sections that follow */
    ea_t header_end = teHeader.ImageBase - delta + sizeof(EFI_IMAGE_TE_HEADER) + teHeader.NumberOfSections * sizeof(EFI_IMAGE_SECTION_HEADER);
#if 1
    msg("Header start: 0x%llx\n", header_start);
    msg("Header end: 0x%llx\n", header_end);
    msg("Delta: 0x%llx\n", delta);
#endif
    file2base(li, 0, header_start, header_end, 1);
    /* create the HEADER segment */
    add_segm(0, header_start, header_end, "HEADER", "DATA");
    /* set header structures */
    doStruct(teHeader.ImageBase - delta, sizeof(EFI_IMAGE_TE_HEADER), efi_image_te_header_struct);
    for (uint8_t i = 0; i < teHeader.NumberOfSections; i++)
    {
        doStruct(teHeader.ImageBase - delta + sizeof(EFI_IMAGE_TE_HEADER) + i * sizeof(EFI_IMAGE_SECTION_HEADER), sizeof(EFI_IMAGE_SECTION_HEADER), efi_image_section_header_struct);
    }
    
    int headerPosition = sizeof(EFI_IMAGE_TE_HEADER);

    /* read sections */
    for (uint8_t i = 0; i < teHeader.NumberOfSections; i++)
    {
        qlseek(li, headerPosition);
        EFI_IMAGE_SECTION_HEADER sectionHeader = {0};
        qlread(li, &sectionHeader, sizeof(EFI_IMAGE_SECTION_HEADER));
        msg("Section name: %s\n", sectionHeader.Name);
        /* ok */
        uint32_t position = sectionHeader.PointerToRawData - delta;
        msg("Position %x\n", position);
        qlseek(li, position);
        ea_t section_start = sectionHeader.VirtualAddress + teHeader.ImageBase - delta;
        ea_t section_end = 0;
        if (sectionHeader.Misc.VirtualSize > sectionHeader.SizeOfRawData)
        {
            section_end = sectionHeader.VirtualAddress + teHeader.ImageBase - delta + sectionHeader.Misc.VirtualSize;
        }
        else
        {
            section_end = sectionHeader.VirtualAddress + teHeader.ImageBase - delta + sectionHeader.SizeOfRawData;
        }
        msg("Section start: 0x%llx\n", section_start);
        msg("Section end: 0x%llx\n", section_end);
        file2base(li, position, section_start, section_end, 1);
        int bitness = -1;
        switch (teHeader.Machine) {
            case IMAGE_FILE_MACHINE_I386:
                bitness = 1;
                break;
            case IMAGE_FILE_MACHINE_X64:
                bitness = 2;
                break;
            default:
                bitness = 0;
        }
        const char *classType;
        if (qstrcmp((const char*)sectionHeader.Name, ".text") == 0)
        {
            classType = "CODE";
        }
        else
        {
            classType = "DATA";
        }
        add_segm(0, section_start, section_end, (const char*)sectionHeader.Name, classType);
        set_segm_addressing(get_segm_by_name((const char *)sectionHeader.Name), bitness);

        /* try to find the GUIDs in data section */
        if (qstrcmp((const char *)sectionHeader.Name, ".data") == 0)
        {
            find_guids(section_start, section_end);
        }

        /* advance to next section */
        headerPosition += sizeof(EFI_IMAGE_SECTION_HEADER);
    }
    /* configure the entrypoint address */
    add_entry(teHeader.AddressOfEntryPoint + teHeader.ImageBase - delta, teHeader.AddressOfEntryPoint + teHeader.ImageBase - delta, "_start", 1);

    /* all done */
}


loader_t LDSC =
{
    IDP_INTERFACE_VERSION,
    0,
    accept_file,
    load_file,
    NULL,
    NULL
};
