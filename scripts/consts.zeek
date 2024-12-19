##! consts.zeek
##!
##! Binpac BSAP (BSAP) Analyzer - Defines BSAP Constants for main.zeek
##!
##! Author:  Devin Vollmer
##! Contact: devin.vollmer@inl.gov
##!
##! Copyright (c) 2023 Battelle Energy Alliance, LLC.  All rights reserved.

module Bsap;

export {
    const UINT32_MAX = 0xFFFFFFFF;

    #############################################################
    #########            BSAP MESSAGE TYPE              #########
    #########  These are values that are not in         #########
    #########  bsap programmers reference guide.        #########
    #########  They do make sense with data flow        #########
    #########  from plc. These were implemented         #########
    #########  by BYU-I students.                       #########
    #############################################################
    const msg_types = {
        [0x0000] = "POLL",
        [0x0001] = "RESPONSECNT",
        [0x0005] = "RESPONSE",
        [0x0006] = "REQUEST",
        [0x0084] = "REQUEST",
        [0x0086] = "REQUEST",
    } &default = function(n: count): string {return fmt("Unknown Message Type-0x%02x", n); };


    #############################################################
    #########           BSAP APPFUNC CODES              #########
    #########  The application function codes are       ######### 
    #########  referenced in the bsap reference         ######### 
    #########  guide. Looking into the dll for          ######### 
    #########  openBSI it looks like the RDB func       ######### 
    #########  codes are the only ones that are         ######### 
    #########  implemented for BSAP_IP.                 #########
    #############################################################
    const app_functions = {
        [0x03] = "PEI_PC",
        [0xA0] = "RDB",
        [0xA1] = "RDB_EXTENSION",
    } &default = function(n: count): string {return fmt("Unknown APP Func-0x%02x", n); };

    ###############################################################################################
    #########################        BSAP RDB Command codes              ##########################
    ###############################################################################################
    const rdb_functions = {
        [0x00] = "READ_SIGNAL_BY_ADDRESS",
        [0x02] = "READ_LOGICAL_BY_ADDRESS",
        [0x04] = "READ_SIGNAL_BY_NAME",
        [0x06] = "READ_LOGICAL_BY_NAME",
        [0x0C] = "READ_SIGNAL_BY_LIST_START",
        [0x0D] = "READ_SIGNAL_BY_LIST_CONTINUE",
        [0x0E] = "READ_LOGICAL_BY_LIST_START",
        [0x0F] = "READ_LOGICAL_BY_LIST_CONTINUE",

        [0x50] = "RSP_READ_SIGNAL_BY_ADDRESS",                  #func code + 0x50 this is for formatting log file only not specified in documents
        [0x52] = "RSP_READ_LOGICAL_BY_ADDRESS",                 #func code + 0x50 this is for formatting log file only not specified in documents
        [0x54] = "RSP_READ_SIGNAL_BY_NAME",                     #func code + 0x50 this is for formatting log file only not specified in documents
        [0x56] = "RSP_READ_LOGICAL_BY_NAME",                    #func code + 0x50 this is for formatting log file only not specified in documents
        [0x5C] = "RSP_READ_SIGNAL_BY_LIST_START",               #func code + 0x50 this is for formatting log file only not specified in documents
        [0x5D] = "RSP_READ_SIGNAL_BY_LIST_CONTINUE",            #func code + 0x50 this is for formatting log file only not specified in documents
        [0x5E] = "RSP_READ_LOGICAL_BY_LIST_START",              #func code + 0x50 this is for formatting log file only not specified in documents
        [0x5F] = "RSP_READ_LOGICAL_BY_LIST_CONTINUE",           #func code + 0x50 this is for formatting log file only not specified in documents


        [0x80] = "WRITE_SIGNAL_BY_ADDRESS",
        [0x84] = "WRITE_SIGNAL_BY_NAME",
        [0x8C] = "WRITE_SIGNAL_BY_LIST_START",
        [0x8D] = "WRITE_SIGNAL_BY_LIST_CONTINUE",


        [0xD0] = "RSP_WRITE_SIGNAL_BY_ADDRESS",                 #func code + 0x50 this is for formatting log file only not specified in documents
        [0xD4] = "RSP_WRITE_SIGNAL_BY_NAME",                    #func code + 0x50 this is for formatting log file only not specified in documents
        [0xDC] = "RSP_WRITE_SIGNAL_BY_LIST_START",              #func code + 0x50 this is for formatting log file only not specified in documents
        [0xDD] = "RSP_WRITE_SIGNAL_BY_LIST_CONTINUE",           #func code + 0x50 this is for formatting log file only not specified in documents
    } &default = function(n: count): string {return fmt("Unknown RDB Func-0x%02x", n); };


    const rdb_ext_functions = {
        [0x0101] = "RESET SYSTEM",
        [0x0102] = "DIAGNOSTICS RESET",
        [0x0201] = "READ DATE AND TIME",
        [0x0202] = "READ DATE",
        [0x0203] = "READ TIME",
        [0x0281] = "WRITE DATE AND TIME",
        [0x0282] = "WRITE SYSTEM DATE",                                                                        # Source: https://www.emerson.com/documents/automation/bsap-communications-application-programmer-s-reference-en-132716.pdf Section 4.5
        [0x0283] = "WRITE SYSTEM TIME",                                                                        # Source: https://www.emerson.com/documents/automation/bsap-communications-application-programmer-s-reference-en-132716.pdf Section 4.6
        [0x0301] = "Audit Trail File - Read Request (MSD address, time)",                                      # Source: https://www.emerson.com/documents/automation/bsap-communications-application-programmer-s-reference-en-132716.pdf Section 8.1.1
        [0x0302] = "Audit Trail File - Read Request (Report Signal Name/Unit texts)",                          # Source: https://www.emerson.com/documents/automation/bsap-communications-application-programmer-s-reference-en-132716.pdf Section 8.1.2
        [0x0303] = "Audit Trail File - Read Request (Report in ASCII format)",                                 # Source: https://www.emerson.com/documents/automation/bsap-communications-application-programmer-s-reference-en-132716.pdf Section 8.1.3
        [0x0304] = "Audit Trail File - Read Request (MSD, Time, Seq#)",                                        # Source: https://www.emerson.com/documents/automation/bsap-communications-application-programmer-s-reference-en-132716.pdf Section 8.1.4
        [0x0305] = "Audit Trail File - Read Request (Name, Units, Seq#)",                                      # Source: https://www.emerson.com/documents/automation/bsap-communications-application-programmer-s-reference-en-132716.pdf Section 8.1.5
        [0x0306] = "Audit Trail File - Read Request (ASCII, Seq#)",                                            # Source: https://www.emerson.com/documents/automation/bsap-communications-application-programmer-s-reference-en-132716.pdf Section 8.1.6
        [0x0306] = "Audit Trail File - Read Request (ASCII, Seq#)",                                            # Source: https://www.emerson.com/documents/automation/bsap-communications-application-programmer-s-reference-en-132716.pdf Section 8.1.6
        [0x0307] = "Audit Trail File - Write Request (ASCII note)",                                            # Source: https://www.emerson.com/documents/automation/bsap-communications-application-programmer-s-reference-en-132716.pdf Section 8.1.7
        [0x0308] = "Audit Trail File - Set Pointer",                                                           # Source: https://www.emerson.com/documents/automation/bsap-communications-application-programmer-s-reference-en-132716.pdf Section 8.1.8
        [0x0309] = "Read Audit Logs – Initial Selective Request",                                              # Source: https://www.emerson.com/documents/automation/bsap-communications-application-programmer-s-reference-en-132716.pdf Section 8.1.9
        [0x030a] = "Read Audit Logs – Continuation Selective Request",                                         # Source: https://www.emerson.com/documents/automation/bsap-communications-application-programmer-s-reference-en-132716.pdf Section 8.1.10
        [0x030b] = "Collect Records from Audit Logs Starting From a Specified Point - Initial Request",        # Source: https://www.emerson.com/documents/automation/bsap-communications-application-programmer-s-reference-en-132716.pdf Section 8.1.11
        [0x030c] = "Collect Records from Audit Logs Starting From a Specified Point - Continuation Request",   # Source: https://www.emerson.com/documents/automation/bsap-communications-application-programmer-s-reference-en-132716.pdf Section 8.1.11
        [0x0400] = "CHANGE LOCAL NODE ADDR",
        [0x0501] = "Standard Security Code Validation (Simple Mode)",                                          # Source: https://www.emerson.com/documents/automation/bsap-communications-application-programmer-s-reference-en-132716.pdf Section 8.2.1
        [0x0502] = "Enhanced Security Code Validation (Secure Mode - GET KEY)",                                # Source: https://www.emerson.com/documents/automation/bsap-communications-application-programmer-s-reference-en-132716.pdf Section 8.2.2
        [0x0503] = "Enhanced Security Code Validation (Secure Mode - LOGIN REQUEST)",                          # Source: https://www.emerson.com/documents/automation/bsap-communications-application-programmer-s-reference-en-132716.pdf Section 8.2.3
        [0x0601] = "Define/Change the Expanded BSAP Group Number",                                             # Source: https://www.emerson.com/documents/automation/bsap-communications-application-programmer-s-reference-en-132716.pdf Section 8.3.1
        [0x0602] = "Undefine (Clear) the Expanded BSAP Group Number",                                          # Source: https://www.emerson.com/documents/automation/bsap-communications-application-programmer-s-reference-en-132716.pdf Section 8.3.2
        [0x0603] = "Read the Expanded BSAP Group Number",                                                      # Source: https://www.emerson.com/documents/automation/bsap-communications-application-programmer-s-reference-en-132716.pdf Section 8.3.3
        [0x0701] = "Read File Attribute Table",                                                                # Source: https://www.emerson.com/documents/automation/bsap-communications-application-programmer-s-reference-en-132716.pdf Section 8.4.1
        [0x0702] = "Read Record Format Definition",                                                            # Source: https://www.emerson.com/documents/automation/bsap-communications-application-programmer-s-reference-en-132716.pdf Section 8.4.2
        [0x0703] = "Read Record Format Definition By Name",                                                    # Source: https://www.emerson.com/documents/automation/bsap-communications-application-programmer-s-reference-en-132716.pdf Section 8.4.3
        [0x0704] = "Read File Pointers",                                                                       # Source: https://www.emerson.com/documents/automation/bsap-communications-application-programmer-s-reference-en-132716.pdf Section 8.4.4
        [0x0705] = "Read File Pointers By Name",                                                               # Source: https://www.emerson.com/documents/automation/bsap-communications-application-programmer-s-reference-en-132716.pdf Section 8.4.5
        [0x0706] = "Read Records By Start Date",                                                               # Source: https://www.emerson.com/documents/automation/bsap-communications-application-programmer-s-reference-en-132716.pdf Section 8.4.6
        [0x0707] = "Read Records By Sequence Number",                                                          # Source: https://www.emerson.com/documents/automation/bsap-communications-application-programmer-s-reference-en-132716.pdf Section 8.4.7
        [0x0708] = "Write File Definition",                                                                    # Source: https://www.emerson.com/documents/automation/bsap-communications-application-programmer-s-reference-en-132716.pdf Section 8.4.8
        [0x0800] = "Read Port Communication Statistics",                                                       # Source: https://www.emerson.com/documents/automation/bsap-communications-application-programmer-s-reference-en-132716.pdf Section 8.5.1
        [0x0801] = "Reset Port Communication Statistics",                                                      # Source: https://www.emerson.com/documents/automation/bsap-communications-application-programmer-s-reference-en-132716.pdf Section 8.5.2
        [0x0802] = "Read Buffer Usage",                                                                        # Source: https://www.emerson.com/documents/automation/bsap-communications-application-programmer-s-reference-en-132716.pdf Section 8.5.3
        [0x0803] = "Reset Buffer Usage Counts",                                                                # Source: https://www.emerson.com/documents/automation/bsap-communications-application-programmer-s-reference-en-132716.pdf Section 8.5.4
        [0x0804] = "Read Crash Blocks",                                                                        # Source: https://www.emerson.com/documents/automation/bsap-communications-application-programmer-s-reference-en-132716.pdf Section 8.5.5
        [0x0805] = "Reset Crash Blocks",                                                                       # Source: https://www.emerson.com/documents/automation/bsap-communications-application-programmer-s-reference-en-132716.pdf Section 8.5.6
        [0x0806] = "Read Port Summary",                                                                        # Source: https://www.emerson.com/documents/automation/bsap-communications-application-programmer-s-reference-en-132716.pdf Section 8.5.7
        [0x0808] = "Read Hardware Registers",                                                                  # Source: https://www.emerson.com/documents/automation/bsap-communications-application-programmer-s-reference-en-132716.pdf Section 8.5.13
        [0x0900] = "Read Array Elements By Column",                                                            # Source: https://www.emerson.com/documents/automation/bsap-communications-application-programmer-s-reference-en-132716.pdf Section 8.6.1
        [0x0901] = "Read Individual Array Elements",                                                           # Source: https://www.emerson.com/documents/automation/bsap-communications-application-programmer-s-reference-en-132716.pdf Section 8.6.2
        [0x0A00] = "Read Version, Features, PROM Link Date",                                                   # Source: https://www.emerson.com/documents/automation/bsap-communications-application-programmer-s-reference-en-132716.pdf Section 8.7.1
        [0x0A01] = "Read Custom PROM Information",                                                             # Source: https://www.emerson.com/documents/automation/bsap-communications-application-programmer-s-reference-en-132716.pdf Section 8.7.2
        [0x0A02] = "Read NRT Information",                                                                     # Source: https://www.emerson.com/documents/automation/bsap-communications-application-programmer-s-reference-en-132716.pdf Section 8.7.3
        [0x0A03] = "Read On Board Serial EEPROM Information",                                                  # Source: https://www.emerson.com/documents/automation/bsap-communications-application-programmer-s-reference-en-132716.pdf Section 8.7.4
        [0x0A04] = "Read RTU Hardware/Software Items",                                                         # Source: https://www.emerson.com/documents/automation/bsap-communications-application-programmer-s-reference-en-132716.pdf Section 8.7.5
        [0x0A04] = "Read RTU Hardware/Software Items",                                                         # Source: https://www.emerson.com/documents/automation/bsap-communications-application-programmer-s-reference-en-132716.pdf Section 8.7.5
        [0x1000] = "Read Global IP Statistics",                                                                # Source: https://www.emerson.com/documents/automation/bsap-communications-application-programmer-s-reference-en-132716.pdf Section 8.5.8    ## No Extended Request Sub-function Code specified on request packet but 0x0810 is specified as the xsfc value on returned packet
        [0x1100] = "Read Global ICMP Statistics",                                                              # Source: https://www.emerson.com/documents/automation/bsap-communications-application-programmer-s-reference-en-132716.pdf Section 8.5.9    ## No Extended Request Sub-function Code specified on request packet but 0x0811 is specified as the xsfc value on returned packet
        [0x1200] = "Read Global UDP Statistics",                                                               # Source: https://www.emerson.com/documents/automation/bsap-communications-application-programmer-s-reference-en-132716.pdf Section 8.5.10   ## No Extended Request Sub-function Code specified on request packet but 0x0812 is specified as the xsfc value on returned packet
        [0x1300] = "Read Global IBP Statistics",                                                               # Source: https://www.emerson.com/documents/automation/bsap-communications-application-programmer-s-reference-en-132716.pdf Section 8.5.11   ## No Extended Request Sub-function Code specified on request packet but 0x0810 (Same as "Read Global IP Statistics" above) is specified as the xsfc value on returned packet
        [0x1F00] = "Reset Global IP Statistics"                                                                # Source: https://www.emerson.com/documents/automation/bsap-communications-application-programmer-s-reference-en-132716.pdf Section 8.5.12   ## No Extended Request Sub-function Code specified on request packet but 0x081F is specified as the xsfc value on returned packet
    } &default = function(n: count): string {return fmt("Unknown RDB Func-0x%02x", n); };
}
