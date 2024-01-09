
\*
author: coldren
created: 20240107
modified: 20240107
As part of the 100 Days of YARA 2024 challenge, John Hammond shared the idea to have magic numbers in a single YARA file.
I thought it was brilliant.
I based the rule syntax on stvemillertime ct_headers file.
Gary Kessler provides a json file that I parsed to generate those rules.
Thanks to Gary Kessler: https://www.garykessler.net/library/file_sigs.html
Careful, some of those rules are not usable as is!
This is still a work in progress.
*\

rule sign_0 { strings: $hex = { 00 00 00 } condition: $hex } \\ High Efficiency Image Container (HEIC)_1: AVIF
rule sign_1 { strings: $hex = { 00 00 00 20 66 74 79 70 68 65 69 63 } condition: $hex } \\ High Efficiency Image Container (HEIC)_2: HEIC
rule sign_2 { strings: $hex = { 00 00 00 0C 6A 50 20 20 } condition: $hex } \\ JPEG2000 image files: JP2
rule sign_3 { strings: $hex = { 00 00 00 14 66 74 79 70 } condition: $hex } \\ 3GPP multimedia files: 3GP
rule sign_4 { strings: $hex = { 00 00 00 14 66 74 79 70 69 73 6F 6D } condition: $hex } \\ MPEG-4 v1: MP4
rule sign_5 { strings: $hex = { 00 00 00 14 66 74 79 70 } condition: $hex } \\ 3rd Generation Partnership Project 3GPP: 3GG,3GP,3G2
rule sign_6 { strings: $hex = { 00 00 00 00 14 00 00 00 } condition: $hex } \\ Windows Disk Image: TBI
rule sign_7 { strings: $hex = { 00 00 00 00 62 31 05 00 09 00 00 00 00 20 00 00 00 09 00 00 00 00 00 00 } condition: $hex } \\ Bitcoin Core wallet.dat file: DAT
rule sign_8 { strings: $hex = { 00 00 00 18 66 74 79 70 } condition: $hex } \\ MPEG-4 video_1: 3GP5,M4V,MP4
rule sign_9 { strings: $hex = { 00 00 00 1C 66 74 79 70 } condition: $hex } \\ MPEG-4 video_2: MP4
rule sign_10 { strings: $hex = { 00 00 00 20 66 74 79 70 } condition: $hex } \\ 3GPP2 multimedia files: 3GP
rule sign_11 { strings: $hex = { 00 00 00 20 66 74 79 70 4D 34 41 } condition: $hex } \\ Apple audio and video: M4A
rule sign_12 { strings: $hex = { 00 00 00 20 66 74 79 70 } condition: $hex } \\ 3rd Generation Partnership Project 3GPP2: 3GG,3GP,3G2
rule sign_13 { condition: uint32be(0) == 0x00000100 } \\ Windows icon|printer spool file: ICO,SPL
rule sign_14 { condition: uint32be(0) == 0x000001B3 } \\ MPEG video file: MPG
rule sign_15 { condition: uint32be(0) == 0x000001BA } \\ DVD video file: MPG,VOB
rule sign_16 { condition: uint32be(0) == 0x00000200 } \\ Windows cursor: CUR
rule sign_17 { strings: $hex = { 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 } condition: $hex } \\ Compucon-Singer embroidery design file: XXX
rule sign_18 { condition: uint32be(0) == 0x00000200 } \\ QuattroPro spreadsheet: WB2
rule sign_19 { condition: uint32be(0) == 0x000003F3 } \\ Amiga Hunk executable: (none)
rule sign_20 { condition: uint32be(0) == 0x0020AF30 } \\ Wii images container: TPL
rule sign_21 { strings: $hex = { 00 00 02 00 06 04 06 00 } condition: $hex } \\ Lotus 1-2-3 (v1): WK1
rule sign_22 { strings: $hex = { 00 00 1A 00 00 10 04 00 } condition: $hex } \\ Lotus 1-2-3 (v3): WK3
rule sign_23 { strings: $hex = { 00 00 1A 00 02 10 04 00 } condition: $hex } \\ Lotus 1-2-3 (v4-v5): WK4,WK5
rule sign_24 { strings: $hex = { 00 00 1A 00 05 10 04 } condition: $hex } \\ Lotus 1-2-3 (v9): 123
rule sign_25 { strings: $hex = { 00 00 49 49 58 50 52 } condition: $hex } \\ Quark Express (Intel): QXD
rule sign_26 { strings: $hex = { 00 00 4D 4D 58 50 52 } condition: $hex } \\ Quark Express (Motorola): QXD
rule sign_27 { strings: $hex = { 00 00 FF FF FF FF } condition: $hex } \\ Windows Help file_1: HLP
rule sign_28 { strings: $hex = { 00 01 00 00 00 } condition: $hex } \\ TrueType font file: TTF
rule sign_29 { strings: $hex = { 00 01 00 00 4D 53 49 53 41 4D 20 44 61 74 61 62 61 73 65 } condition: $hex } \\ Microsoft Money file: MNY
rule sign_30 { strings: $hex = { 00 01 00 00 53 74 61 6E 64 61 72 64 20 41 43 45 20 44 42 } condition: $hex } \\ Microsoft Access 2007: ACCDB
rule sign_31 { strings: $hex = { 00 01 00 00 53 74 61 6E 64 61 72 64 20 4A 65 74 20 44 42 } condition: $hex } \\ Microsoft Access: MDB
rule sign_32 { condition: uint32be(0) == 0x00014241 } \\ Palm Address Book Archive: ABA
rule sign_33 { condition: uint32be(0) == 0x00014244 } \\ Palm DateBook Archive: DBA
rule sign_34 { strings: $hex = { 00 06 15 61 00 00 00 02 00 00 04 D2 00 00 10 00 } condition: $hex } \\ Netscape Navigator (v4) database: DB
rule sign_35 { condition: uint32be(0) == 0x000DBBA0 } \\ Mbox table of contents file: (none)
rule sign_36 { condition: uint16be(0) == 0x0011 } \\ FLIC animation: FLI
rule sign_37 { strings: $hex = { 00 14 00 00 01 02 } condition: $hex } \\ BIOS details in RAM: (none)
rule sign_38 { strings: $hex = { 00 1E 84 90 00 00 00 00 } condition: $hex } \\ Netscape Communicator (v4) mail folder: SNM
rule sign_39 { strings: $hex = { 00 3B 05 00 01 00 00 00 } condition: $hex } \\ Paessler PRTG Monitoring System: DB
rule sign_40 { condition: uint32be(512) == 0x006E1EF0 } \\ PowerPoint presentation subheader_1: PPT
rule sign_41 { condition: uint32be(0) == 0x01000200 } \\ Webex Advanced Recording Format: ARF
rule sign_42 { condition: uint32be(0) == 0x01003930 } \\ Firebird and Interbase database files: FDB,GDB
rule sign_43 { strings: $hex = { 01 01 47 19 A4 00 00 00 00 00 00 00 } condition: $hex } \\ The Bat! Message Base Index: TBI
rule sign_44 { condition: uint32be(0) == 0x010F0000 } \\ SQL Data Base: MDF
rule sign_45 { condition: uint16be(0) == 0x0110 } \\ Novell LANalyzer capture file: TR1
rule sign_46 { strings: $hex = { 01 DA 01 01 00 03 } condition: $hex } \\ Silicon Graphics RGB Bitmap: RGB
rule sign_47 { strings: $hex = { 01 FF 02 04 03 02 } condition: $hex } \\ Micrografx vector graphic file: DRW
rule sign_48 { condition: uint32be(0) == 0x02647373 } \\ Digital Speech Standard file: DSS
rule sign_49 { condition: uint8(0) == 0x03 } \\ MapInfo Native Data Format: DAT
rule sign_50 { condition: uint8(0) == 0x03 } \\ dBASE III file: DB3
rule sign_51 { condition: uint32be(0) == 0x03000000 } \\ Quicken price history: QPH
rule sign_52 { condition: uint32be(0) == 0x03000000 } \\ Nokia PC Suite Content Copier file: NFC
rule sign_53 { strings: $hex = { 03 00 00 00 41 50 50 52 } condition: $hex } \\ Approach index file: ADX
rule sign_54 { condition: uint32be(0) == 0x03647373 } \\ Digital Speech Standard (v3): DSS
rule sign_55 { condition: uint8(0) == 0x04 } \\ dBASE IV file: DB4
rule sign_56 { condition: uint32be(0) == 0x04000000 } \\ INFO2 Windows recycle bin_1: (none)
rule sign_57 { condition: uint32be(0) == 0x05000000 } \\ INFO2 Windows recycle bin_2: (none)
rule sign_58 { strings: $hex = { 06 06 ED F5 D8 1D 46 E5 BD 31 EF E7 FE 74 B7 1D } condition: $hex } \\ Adobe InDesign: INDD
rule sign_59 { strings: $hex = { 06 0E 2B 34 02 05 01 01 0D 01 02 01 01 02 } condition: $hex } \\ Material Exchange Format: MXF
rule sign_60 { condition: uint8(0) == 0x07 } \\ Generic drawing programs: DRW
rule sign_61 { condition: uint32be(0) == 0x07534B46 } \\ SkinCrafter skin: SKF
rule sign_62 { strings: $hex = { 07 64 74 32 64 64 74 64 } condition: $hex } \\ DesignTools 2D Design file: DTD
rule sign_63 { condition: uint8(0) == 0x08 } \\ dBASE IV or dBFast configuration file: DB
rule sign_64 { strings: $hex = { 09 08 10 00 00 06 05 00 } condition: $hex } \\ Excel spreadsheet subheader_1: XLS
rule sign_65 { condition: uint32be(0) == 0x0A020101 } \\ ZSOFT Paintbrush file_1: PCX
rule sign_66 { condition: uint32be(0) == 0x0A030101 } \\ ZSOFT Paintbrush file_2: PCX
rule sign_67 { condition: uint32be(0) == 0x0A050101 } \\ ZSOFT Paintbrush file_3: PCX
rule sign_68 { strings: $hex = { 0A 16 6F 72 67 2E 62 69 74 63 6F 69 6E 2E 70 72 } condition: $hex } \\ MultiBit Bitcoin wallet file: WALLET
rule sign_69 { condition: uint16be(0) == 0x0CED } \\ Monochrome Picture TIFF bitmap: MP
rule sign_70 { condition: uint32be(0) == 0x0D444F43 } \\ DeskMate Document: DOC
rule sign_71 { strings: $hex = { 0E 4E 65 72 6F 49 53 4F } condition: $hex } \\ Nero CD compilation: NRI
rule sign_72 { condition: uint32be(0) == 0x0E574B53 } \\ DeskMate Worksheet: WKS
rule sign_73 { condition: uint32be(512) == 0x0F00E803 } \\ PowerPoint presentation subheader_2: PPT
rule sign_74 { strings: $hex = { 0F 53 49 42 45 4C 49 55 53 } condition: $hex } \\ Sibelius Music - Score: SIB
rule sign_75 { condition: uint32be(0) == 0x10000000 } \\ Easy CD Creator 5 Layout file: CL5
rule sign_76 { strings: $hex = { 11 00 00 00 53 43 43 41 } condition: $hex } \\ Windows prefetch file: PF
rule sign_77 { strings: $hex = { 1A 00 00 } condition: $hex } \\ Lotus Notes database template: NTF
rule sign_78 { strings: $hex = { 1A 00 00 04 00 00 } condition: $hex } \\ Lotus Notes database: NSF
rule sign_79 { condition: uint16be(0) == 0x1A02 } \\ LH archive (old vers.-type 1): ARC
rule sign_80 { condition: uint16be(0) == 0x1A03 } \\ LH archive (old vers.-type 2): ARC
rule sign_81 { condition: uint16be(0) == 0x1A04 } \\ LH archive (old vers.-type 3): ARC
rule sign_82 { condition: uint16be(0) == 0x1A08 } \\ LH archive (old vers.-type 4): ARC
rule sign_83 { condition: uint16be(0) == 0x1A09 } \\ LH archive (old vers.-type 5): ARC
rule sign_84 { condition: uint16be(0) == 0x1A0B } \\ Compressed archive file: PAK
rule sign_85 { condition: uint32be(0) == 0x1A350100 } \\ WinPharoah capture file: ETH
rule sign_86 { condition: uint32be(0) == 0x1A45DFA3 } \\ WebM video file: WEBM
rule sign_87 { condition: uint32be(0) == 0x1A45DFA3 } \\ Matroska stream file_1: MKV
rule sign_88 { strings: $hex = { 1A 45 DF A3 93 42 82 88 } condition: $hex } \\ Matroska stream file_2: MKV
rule sign_89 { strings: $hex = { 1A 52 54 53 20 43 4F 4D } condition: $hex } \\ Runtime Software disk image: DAT
rule sign_90 { condition: uint16be(0) == 0x1D7D } \\ WordStar Version 5.0-6.0 document: WS
rule sign_91 { strings: $hex = { 1F 8B 08 } condition: $hex } \\ GZIP archive file: GZ
rule sign_92 { strings: $hex = { 1F 8B 08 } condition: $hex } \\ VLC Player Skin file: VLT
rule sign_93 { condition: uint32be(0) == 0x1F8B0800 } \\ Synology router configuration backup file: DSS
rule sign_94 { strings: $hex = { 1F 9D 90 } condition: $hex } \\ Compressed tape archive_1: TAR.Z
rule sign_95 { condition: uint16be(0) == 0x1FA0 } \\ Compressed tape archive_2: TAR.Z
rule sign_96 { condition: uint8(0) == 0x21 } \\ MapInfo Sea Chart: BSB
rule sign_97 { strings: $hex = { 21 0D 0A 43 52 52 2F 54 68 69 73 20 65 6C 65 63 } condition: $hex } \\ NOAA Raster Navigation Chart (RNC) file: BSB
rule sign_98 { condition: uint16be(0) == 0x2112 } \\ AIN Compressed Archive: AIN
rule sign_99 { strings: $hex = { 21 3C 61 72 63 68 3E 0A } condition: $hex } \\ Unix archiver (ar)-MS Program Library Common Object File Format (COFF): LIB
rule sign_100 { condition: uint32be(0) == 0x2142444E } \\ Microsoft Outlook Exchange Offline Storage Folder: OST
rule sign_101 { condition: uint16be(0) == 0x2320 } \\ Cerius2 file: MSI
rule sign_102 { strings: $hex = { 23 20 44 69 73 6B 20 44 } condition: $hex } \\ VMware 4 Virtual Disk description: VMDK
rule sign_103 { strings: $hex = { 23 20 4D 69 63 72 6F 73 } condition: $hex } \\ MS Developer Studio project file: DSP
rule sign_104 { strings: $hex = { 23 20 54 68 69 73 20 69 73 20 61 6E 20 4B 65 79 } condition: $hex } \\ Google Earth Keyhole Placemark file: ETA
rule sign_105 { strings: $hex = { 23 21 41 4D 52 } condition: $hex } \\ Adaptive Multi-Rate ACELP Codec (GSM): AMR
rule sign_106 { strings: $hex = { 23 21 53 49 4C 4B 0A } condition: $hex } \\ Skype audio compression: SIL
rule sign_107 { strings: $hex = { 23 3F 52 41 44 49 41 4E } condition: $hex } \\ Radiance High Dynamic Range image file: HDR
rule sign_108 { condition: uint32be(0) == 0x23407E5E } \\ VBScript Encoded script: VBE
rule sign_109 { condition: uint32be(0) == 0x234E4246 } \\ NVIDIA Scene Graph binary file: NBF
rule sign_110 { strings: $hex = { 23 50 45 43 30 30 30 31 } condition: $hex } \\ Brother-Babylock-Bernina Home Embroidery: PEC
rule sign_111 { strings: $hex = { 23 50 45 53 30 } condition: $hex } \\ Brother-Babylock-Bernina Home Embroidery: PES
rule sign_112 { strings: $hex = { 24 46 4C 32 40 28 23 29 } condition: $hex } \\ SPSS Data file: SAV
rule sign_113 { strings: $hex = { 25 21 50 53 2D 41 64 6F } condition: $hex } \\ Encapsulated PostScript file: EPS
rule sign_114 { strings: $hex = { 25 21 50 53 2D 41 64 6F 62 65 2D } condition: $hex } \\ PostScript file: PS
rule sign_115 { condition: uint32be(0) == 0x25504446 } \\ PDF file: PDF,FDF
rule sign_116 { strings: $hex = { 25 62 69 74 6D 61 70 } condition: $hex } \\ Fuzzy bitmap (FBM) file: FBM
rule sign_117 { strings: $hex = { 28 54 68 69 73 20 66 69 } condition: $hex } \\ BinHex 4 Compressed Archive: HQX
rule sign_118 { strings: $hex = { 2A 2A 2A 20 20 49 6E 73 } condition: $hex } \\ Symantec Wise Installer log: LOG
rule sign_119 { strings: $hex = { 2D 6C 68 } condition: $hex } \\ Compressed archive: LHA,LZH
rule sign_120 { condition: uint32be(0) == 0x2E524543 } \\ RealPlayer video file (V11+): IVR
rule sign_121 { condition: uint32be(0) == 0x2E524D46 } \\ RealMedia streaming media: RM,RMVB
rule sign_122 { strings: $hex = { 2E 52 4D 46 00 00 00 12 } condition: $hex } \\ RealAudio file: RA
rule sign_123 { strings: $hex = { 2E 72 61 FD 00 } condition: $hex } \\ RealAudio streaming media: RA
rule sign_124 { condition: uint32be(0) == 0x2E736E64 } \\ NeXT-Sun Microsystems audio file: AU
rule sign_125 { strings: $hex = { 2F 2F 20 3C 21 2D 2D 20 3C 6D 64 62 3A 6D 6F 72 6B 3A 7A } condition: $hex } \\ Thunderbird-Mozilla Mail Summary File: MSF
rule sign_126 { condition: uint8(0) == 0x30 } \\ MS security catalog file: CAT
rule sign_127 { strings: $hex = { 30 00 00 00 4C 66 4C 65 } condition: $hex } \\ Windows Event Viewer file: EVT
rule sign_128 { strings: $hex = { 30 20 48 45 41 44 } condition: $hex } \\ GEnealogical Data COMmunication (GEDCOM) file: GED
rule sign_129 { strings: $hex = { 30 26 B2 75 8E 66 CF 11 } condition: $hex } \\ Windows Media Audio-Video File: ASF,WMA,WMV
rule sign_130 { strings: $hex = { 30 31 4F 52 44 4E 41 4E } condition: $hex } \\ National Transfer Format Map: NTF
rule sign_131 { strings: $hex = { 30 37 30 37 30 } condition: $hex } \\ cpio archive: (none)
rule sign_132 { condition: uint16be(0) == 0x31BE } \\ MS Write file_1: WRI
rule sign_133 { condition: uint16be(0) == 0x32BE } \\ MS Write file_2: WRI
rule sign_134 { strings: $hex = { 32 03 10 00 00 00 00 00 00 00 80 00 00 00 FF 00 } condition: $hex } \\ Pfaff Home Embroidery: PCS
rule sign_135 { condition: uint32be(0) == 0x34CDB2A1 } \\ Tcpdump capture file: (none)
rule sign_136 { strings: $hex = { 37 7A BC AF 27 1C } condition: $hex } \\ 7-Zip compressed file: 7Z
rule sign_137 { strings: $hex = { 37 E4 53 96 C9 DB D6 07 } condition: $hex } \\ zisofs compressed file: (none)
rule sign_138 { condition: uint32be(0) == 0x38425053 } \\ Photoshop image: PSD
rule sign_139 { strings: $hex = { 3A 56 45 52 53 49 4F 4E } condition: $hex } \\ Surfplan kite project file: SLE
rule sign_140 { condition: uint8(0) == 0x3C } \\ Advanced Stream Redirector: ASX
rule sign_141 { condition: uint8(0) == 0x3C } \\ BizTalk XML-Data Reduced Schema: XDR
rule sign_142 { strings: $hex = { 3C 21 64 6F 63 74 79 70 } condition: $hex } \\ AOL HTML mail: DCI
rule sign_143 { condition: uint16be(0) == 0x3C3F } \\ Windows Script Component: WSC
rule sign_144 { strings: $hex = { 3C 3F 78 6D 6C 20 76 65 72 73 69 6F 6E 3D } condition: $hex } \\ Windows Visual Stylesheet: MANIFEST
rule sign_145 { strings: $hex = { 3C 3F 78 6D 6C 20 76 65 72 73 69 6F 6E 3D 22 31 2E 30 22 3F 3E } condition: $hex } \\ User Interface Language: XML
rule sign_146 { strings: $hex = { 3C 3F 78 6D 6C 20 76 65 72 73 69 6F 6E 3D 22 31 2E 30 22 3F 3E 0D 0A 3C 4D 4D 43 5F 43 6F 6E 73 6F 6C 65 46 69 6C 65 20 43 6F 6E 73 6F 6C 65 56 65 72 73 69 6F 6E 3D 22 } condition: $hex } \\ MMC Snap-in Control file: MSC
rule sign_147 { strings: $hex = { 3C 43 54 72 61 6E 73 54 69 6D 65 6C 69 6E 65 3E } condition: $hex } \\ Picasa movie project file: MXF
rule sign_148 { strings: $hex = { 3C 43 73 6F 75 6E 64 53 79 6E 74 68 65 73 69 7A } condition: $hex } \\ Csound music: CSD
rule sign_149 { strings: $hex = { 3C 4B 65 79 68 6F 6C 65 3E } condition: $hex } \\ Google Earth Keyhole Overlay file: ETA
rule sign_150 { strings: $hex = { 3C 4D 61 6B 65 72 46 69 } condition: $hex } \\ Adobe FrameMaker: FM,MIF
rule sign_151 { strings: $hex = { 3C 67 70 78 20 76 65 72 73 69 6F 6E 3D 22 31 2E } condition: $hex } \\ GPS Exchange (v1.1): GPX
rule sign_152 { strings: $hex = { 3C 7E 36 3C 5C 25 5F 30 67 53 71 68 3B } condition: $hex } \\ BASE85 file: B85
rule sign_153 { strings: $hex = { 3E 00 03 00 FE FF 09 00 06 } condition: $hex } \\ Quatro Pro for Windows 7.0: WB3
rule sign_154 { condition: uint32be(0) == 0x3F5F0300 } \\ Windows Help file_2: GID,HLP
rule sign_155 { strings: $hex = { 40 40 40 20 00 00 40 40 40 40 } condition: $hex } \\ EndNote Library File: ENL
rule sign_156 { condition: uint32be(0) == 0x41426F78 } \\ Analog Box (ABox) circuit files: ABOX2
rule sign_157 { condition: uint32be(0) == 0x41433130 } \\ Generic AutoCAD drawing: DWG
rule sign_158 { strings: $hex = { 41 43 76 } condition: $hex } \\ Steganos virtual secure drive: SLE
rule sign_159 { condition: uint32be(0) == 0x41435344 } \\ AOL parameter-info files: (none)
rule sign_160 { condition: uint32be(0) == 0x414D594F } \\ Harvard Graphics symbol graphic: SYW
rule sign_161 { strings: $hex = { 41 4F 4C } condition: $hex } \\ AOL config files: ABI,ABY,BAG,IDX,IND,PFC
rule sign_162 { strings: $hex = { 41 4F 4C 20 46 65 65 64 } condition: $hex } \\ AOL and AIM buddy list: BAG
rule sign_163 { strings: $hex = { 41 4F 4C 44 42 } condition: $hex } \\ AOL address book: ABY
rule sign_164 { strings: $hex = { 41 4F 4C 44 42 } condition: $hex } \\ AOL user configuration: IDX
rule sign_165 { strings: $hex = { 41 4F 4C 49 44 58 } condition: $hex } \\ AOL client preferences-settings file: IND
rule sign_166 { strings: $hex = { 41 4F 4C 49 4E 44 45 58 } condition: $hex } \\ AOL address book index: ABI
rule sign_167 { strings: $hex = { 41 4F 4C 56 4D 31 30 30 } condition: $hex } \\ AOL personal file cabinet: ORG,PFC
rule sign_168 { strings: $hex = { 41 56 47 36 5F 49 6E 74 } condition: $hex } \\ AVG6 Integrity database: DAT
rule sign_169 { strings: $hex = { 41 56 49 20 4C 49 53 54 } condition: $hex } \\ RIFF Windows Audio: AVI
rule sign_170 { condition: uint32be(0) == 0x41724301 } \\ FreeArc compressed file: ARC
rule sign_171 { condition: uint32be(0) == 0x42414144 } \\ NTFS MFT (BAAD): (none)
rule sign_172 { condition: uint32be(0) == 0x42446963 } \\ Google Chrome dictionary file: BDIC
rule sign_173 { strings: $hex = { 42 45 47 49 4E 3A 56 43 } condition: $hex } \\ vCard: VCF
rule sign_174 { strings: $hex = { 42 4C 49 32 32 33 } condition: $hex } \\ Speedtouch router firmware: BIN,BLI,RBI
rule sign_175 { condition: uint16be(0) == 0x424D } \\ Bitmap image: BMP,DIB
rule sign_176 { strings: $hex = { 42 4F 4F 4B 4D 4F 42 49 } condition: $hex } \\ Palmpilot resource file: PRC
rule sign_177 { condition: uint32be(0) == 0x425047FB } \\ Better Portable Graphics: BPG
rule sign_178 { strings: $hex = { 42 5A 68 } condition: $hex } \\ bzip2 compressed archive: BZ2,TAR,BZ2,TBZ2,TB2
rule sign_179 { strings: $hex = { 42 5A 68 } condition: $hex } \\ Mac Disk image (BZ2 compressed): DMG
rule sign_180 { strings: $hex = { 42 65 67 69 6E 20 50 75 66 66 65 72 } condition: $hex } \\ Puffer ASCII encrypted archive: APUF
rule sign_181 { strings: $hex = { 42 6C 69 6E 6B } condition: $hex } \\ Blink compressed archive: BLI
rule sign_182 { strings: $hex = { 43 23 2B 44 A4 43 4D A5 } condition: $hex } \\ RagTime document: RTD
rule sign_183 { condition: uint32be(0(null)) == 0x43415420 } \\ EA Interchange Format File (IFF)_3: IFF
rule sign_184 { strings: $hex = { 43 42 46 49 4C 45 } condition: $hex } \\ WordPerfect dictionary: CBD
rule sign_185 { strings: $hex = { 43 44 30 30 31 } condition: $hex } \\ ISO-9660 CD Disc Image: ISO
rule sign_186 { strings: $hex = { 43 44 44 41 66 6D 74 20 } condition: $hex } \\ RIFF CD audio: CDA
rule sign_187 { condition: uint32be(0) == 0x4349534F } \\ Compressed ISO CD image: CSO
rule sign_188 { strings: $hex = { 43 4D 4D 4D 15 00 00 00 } condition: $hex } \\ Windows 7 thumbnail: DB
rule sign_189 { condition: uint32be(0) == 0x434D5831 } \\ Corel Binary metafile: CLB
rule sign_190 { condition: uint32be(0) == 0x434F4D2B } \\ COM+ Catalog: CLB
rule sign_191 { condition: uint32be(0) == 0x434F5744 } \\ VMware 3 Virtual Disk: VMDK
rule sign_192 { strings: $hex = { 43 50 54 37 46 49 4C 45 } condition: $hex } \\ Corel Photopaint file_1: CPT
rule sign_193 { strings: $hex = { 43 50 54 46 49 4C 45 } condition: $hex } \\ Corel Photopaint file_2: CPT
rule sign_194 { condition: uint32be(0) == 0x43524547 } \\ Win9x registry hive: DAT
rule sign_195 { strings: $hex = { 43 52 55 53 48 20 76 } condition: $hex } \\ Crush compressed archive: CRU
rule sign_196 { strings: $hex = { 43 57 53 } condition: $hex } \\ Shockwave Flash file: SWF
rule sign_197 { strings: $hex = { 43 61 6C 63 75 6C 75 78 20 49 6E 64 6F 6F 72 20 } condition: $hex } \\ Calculux Indoor lighting project file: CIN
rule sign_198 { strings: $hex = { 43 61 74 61 6C 6F 67 20 } condition: $hex } \\ WhereIsIt Catalog: CTF
rule sign_199 { strings: $hex = { 43 6C 69 65 6E 74 20 55 } condition: $hex } \\ IE History file: DAT
rule sign_200 { condition: uint32be(0) == 0x43723234 } \\ Google Chrome Extension: CRX
rule sign_201 { condition: uint32be(0) == 0x43724F44 } \\ Google Chromium patch update: CRX
rule sign_202 { strings: $hex = { 43 72 65 61 74 69 76 65 20 56 6F 69 63 65 20 46 } condition: $hex } \\ Creative Voice: VOC
rule sign_203 { strings: $hex = { 44 41 41 00 00 00 00 00 } condition: $hex } \\ PowerISO Direct-Access-Archive image: DAA
rule sign_204 { condition: uint32be(0) == 0x44415800 } \\ DAX Compressed CD image: DAX
rule sign_205 { condition: uint32be(0) == 0x44424648 } \\ Palm Zire photo database: DB
rule sign_206 { condition: uint32be(0) == 0x444D5321 } \\ Amiga DiskMasher compressed archive: DMS
rule sign_207 { strings: $hex = { 44 4F 53 } condition: $hex } \\ Amiga disk file: ADF
rule sign_208 { condition: uint32be(0) == 0x44535462 } \\ DST Compression: DST
rule sign_209 { strings: $hex = { 44 56 44 } condition: $hex } \\ DVR-Studio stream file: DVR
rule sign_210 { strings: $hex = { 44 56 44 } condition: $hex } \\ DVD info file: IFO
rule sign_211 { strings: $hex = { 45 4C 49 54 45 20 43 6F } condition: $hex } \\ Elite Plus Commander game file: CDR
rule sign_212 { strings: $hex = { 45 4E 54 52 59 56 43 44 } condition: $hex } \\ VideoVCD-VCDImager file: VCD
rule sign_213 { strings: $hex = { 45 52 02 00 00 } condition: $hex } \\ Apple ISO 9660-HFS hybrid CD image: ISO
rule sign_214 { strings: $hex = { 45 52 46 53 53 41 56 45 } condition: $hex } \\ EasyRecovery Saved State file: DAT
rule sign_215 { condition: uint32be(0) == 0x44534420 } \\ DSD Storage Facility audio file: DSF
rule sign_216 { condition: uint16be(0) == 0x4550 } \\ MS Document Imaging file: MDI
rule sign_217 { strings: $hex = { 45 56 46 09 0D 0A FF 00 } condition: $hex } \\ Expert Witness Compression Format: E01
rule sign_218 { strings: $hex = { 45 56 46 32 0D 0A 81 } condition: $hex } \\ EnCase Evidence File Format V2: Ex01
rule sign_219 { strings: $hex = { 45 6C 66 46 69 6C 65 00 } condition: $hex } \\ Windows Vista event log: EVTX
rule sign_220 { strings: $hex = { 45 86 00 00 06 00 } condition: $hex } \\ QuickBooks backup: QBB
rule sign_221 { strings: $hex = { 46 41 58 43 4F 56 45 52 } condition: $hex } \\ MS Fax Cover Sheet: CPE
rule sign_222 { strings: $hex = { 46 44 42 48 00 } condition: $hex } \\ Fiasco database definition file: FDB
rule sign_223 { condition: uint32be(0) == 0x46494C45 } \\ NTFS MFT (FILE): (none)
rule sign_224 { strings: $hex = { 46 4C 56 } condition: $hex } \\ Flash video file: FLV
rule sign_225 { condition: uint32be(0) == 0x464F524D } \\ IFF ANIM file: ANM
rule sign_226 { condition: uint32be(0) == 0x464F524D } \\ EA Interchange Format File (IFF)_1: IFF
rule sign_227 { strings: $hex = { 46 4F 52 4D 00 } condition: $hex } \\ Audio Interchange File: AIFF
rule sign_228 { strings: $hex = { 46 4F 52 4D 00 } condition: $hex } \\ DAKX Compressed Audio: DAX
rule sign_229 { strings: $hex = { 46 57 53 } condition: $hex } \\ Shockwave Flash player: SWF
rule sign_230 { condition: uint32be(0) == 0x46726F6D } \\ Generic e-mail_2: EML
rule sign_231 { condition: uint32be(0) == 0x47494638 } \\ GIF file: GIF
rule sign_232 { condition: uint32be(0) == 0x47504154 } \\ GIMP pattern file: PAT
rule sign_233 { condition: uint32be(0) == 0x47524942 } \\ General Regularly-distributed Information (GRIdded) Binary: GRB
rule sign_234 { strings: $hex = { 47 58 32 } condition: $hex } \\ Show Partner graphics file: GX2
rule sign_235 { strings: $hex = { 47 65 6E 65 74 65 63 20 4F 6D 6E 69 63 61 73 74 } condition: $hex } \\ Genetec video archive: G64
rule sign_236 { strings: $hex = { 48 44 52 2A 50 6F 77 65 72 42 75 69 6C 64 65 72 } condition: $hex } \\ SAP PowerBuilder integrated development environment file: PBD
rule sign_237 { strings: $hex = { 48 45 41 44 45 52 20 52 45 43 4F 52 44 2A 2A 2A } condition: $hex } \\ SAS Transport dataset: XPT
rule sign_238 { strings: $hex = { 48 48 47 42 31 } condition: $hex } \\ Harvard Graphics presentation file: SH3
rule sign_239 { strings: $hex = { 49 20 49 } condition: $hex } \\ TIFF file_1: TIF,TIFF
rule sign_240 { strings: $hex = { 49 44 33 } condition: $hex } \\ MP3 audio file: MP3
rule sign_241 { strings: $hex = { 49 44 33 03 00 00 00 } condition: $hex } \\ Sprint Music Store audio: KOZ
rule sign_242 { strings: $hex = { 49 49 1A 00 00 00 48 45 } condition: $hex } \\ Canon RAW file: CRW
rule sign_243 { condition: uint32be(0) == 0x49492A00 } \\ TIFF file_2: TIF,TIFF
rule sign_244 { strings: $hex = { 49 4D 4D 4D 15 00 00 00 } condition: $hex } \\ Windows 7 thumbnail_2: DB
rule sign_245 { condition: uint32be(0) == 0x49536328 } \\ Install Shield compressed file: CAB,HDR
rule sign_246 { strings: $hex = { 49 54 4F 4C 49 54 4C 53 } condition: $hex } \\ MS Reader eBook: LIT
rule sign_247 { condition: uint32be(0) == 0x49545346 } \\ MS Compiled HTML Help File: CHI,CHM
rule sign_248 { strings: $hex = { 49 6E 6E 6F 20 53 65 74 } condition: $hex } \\ Inno Setup Uninstall Log: DAT
rule sign_249 { strings: $hex = { 49 6E 74 65 72 40 63 74 69 76 65 20 50 61 67 65 } condition: $hex } \\ Inter@ctive Pager Backup (BlackBerry file: IPD
rule sign_250 { strings: $hex = { 4A 41 52 43 53 00 } condition: $hex } \\ JARCS compressed archive: JAR
rule sign_251 { condition: uint32be(0) == 0x4A47030E } \\ AOL ART file_1: JG
rule sign_252 { condition: uint32be(0) == 0x4A47040E } \\ AOL ART file_2: JG
rule sign_253 { strings: $hex = { 4B 44 4D } condition: $hex } \\ VMware 4 Virtual Disk: VMDK
rule sign_254 { strings: $hex = { 4B 47 42 5F 61 72 63 68 } condition: $hex } \\ KGB archive: KGB
rule sign_255 { condition: uint32be(0) == 0x4B490000 } \\ Win9x printer spool file: SHD
rule sign_256 { strings: $hex = { 4B 57 41 4A 88 F0 27 D1 } condition: $hex } \\ KWAJ (compressed) file: (none)
rule sign_257 { strings: $hex = { 4C 00 00 00 01 14 02 00 } condition: $hex } \\ Windows shortcut file: LNK
rule sign_258 { condition: uint16be(0) == 0x4C01 } \\ MS COFF relocatable object code: OBJ
rule sign_259 { strings: $hex = { 4C 41 3A } condition: $hex } \\ Tajima emboridery: DST
rule sign_260 { condition: uint32be(0) == 0x4C4E0200 } \\ Windows help file_3: GID,HLP
rule sign_261 { condition: uint32be(0) == 0x4C495354 } \\ EA Interchange Format File (IFF)_2: IFF
rule sign_262 { strings: $hex = { 4C 50 46 20 00 01 } condition: $hex } \\ DeluxePaint Animation: ANM
rule sign_263 { strings: $hex = { 4C 56 46 09 0D 0A FF 00 } condition: $hex } \\ Logical File Evidence Format: E01
rule sign_264 { strings: $hex = { 4D 2D 57 20 50 6F 63 6B } condition: $hex } \\ Merriam-Webster Pocket Dictionary: PDB
rule sign_265 { strings: $hex = { 4D 41 52 31 00 } condition: $hex } \\ Mozilla archive: MAR
rule sign_266 { condition: uint32be(0) == 0x4D415243 } \\ Microsoft-MSN MARC archive: MAR
rule sign_267 { strings: $hex = { 4D 41 54 4C 41 42 20 35 2E 30 20 4D 41 54 2D 66 69 6C 65 } condition: $hex } \\ MATLAB v5 workspace: MAT
rule sign_268 { strings: $hex = { 4D 41 72 30 00 } condition: $hex } \\ MAr compressed archive: MAR
rule sign_269 { strings: $hex = { 4D 43 57 20 54 65 63 68 6E 6F 67 6F 6C 69 65 73 } condition: $hex } \\ TargetExpress target file: MTE
rule sign_270 { strings: $hex = { 4D 44 4D 50 93 A7 } condition: $hex } \\ Windows dump file: DMP,HDMP
rule sign_271 { strings: $hex = { 4D 49 4C 45 53 } condition: $hex } \\ Milestones project management file: MLS
rule sign_272 { condition: uint32be(0) == 0x4D4C5357 } \\ Skype localization data file: MLS
rule sign_273 { condition: uint32be(0) == 0x4D4D002A } \\ TIFF file_3: TIF,TIFF
rule sign_274 { condition: uint32be(0) == 0x4D4D002B } \\ TIFF file_4: TIF,TIFF
rule sign_275 { strings: $hex = { 4D 4D 4D 44 00 00 } condition: $hex } \\ Yamaha Synthetic music Mobile Application Format: MMF
rule sign_276 { condition: uint32be(0) == 0x4D52564E } \\ VMware BIOS state file: NVRAM
rule sign_277 { condition: uint32be(0) == 0x4D534346 } \\ Microsoft cabinet file: CAB
rule sign_278 { condition: uint32be(0) == 0x4D534346 } \\ OneNote Package: ONEPKG
rule sign_279 { condition: uint32be(0) == 0x4D534346 } \\ Powerpoint Packaged Presentation: PPZ
rule sign_280 { condition: uint32be(0) == 0x4D534346 } \\ MS Access Snapshot Viewer file: SNP
rule sign_281 { strings: $hex = { 4D 53 46 54 02 00 01 00 } condition: $hex } \\ OLE-SPSS-Visual C++ library file: TLB
rule sign_282 { strings: $hex = { D 53 48 7C 5E 7E 5C 26 7C } condition: $hex } \\ Health Level-7 data (pipe delimited) file: HL7
rule sign_283 { strings: $hex = { 4D 53 57 49 4D } condition: $hex } \\ Microsoft Windows Imaging Format: WIM
rule sign_284 { strings: $hex = { 4D 53 5F 56 4F 49 43 45 } condition: $hex } \\ Sony Compressed Voice File: CDR,DVF,MSV
rule sign_285 { condition: uint32be(0) == 0x4D546864 } \\ MIDI sound file: MID,MIDI
rule sign_286 { condition: uint32be(0) == 0x4D546864 } \\ Yamaha Piano: PCS
rule sign_287 { condition: uint16be(0) == 0x4D56 } \\ CD Stomper Pro label file: DSN
rule sign_288 { strings: $hex = { 4D 56 32 31 34 } condition: $hex } \\ Milestones project management file_1: MLS
rule sign_289 { condition: uint32be(0) == 0x4D563243 } \\ Milestones project management file_2: MLS
rule sign_290 { condition: uint16be(0) == 0x4D5A } \\ Windows-DOS executable file: COM,DLL,DRV,EXE,PIF,QTS,QTX,SYS
rule sign_291 { condition: uint16be(0) == 0x4D5A } \\ MS audio compression manager driver: ACM
rule sign_292 { condition: uint16be(0) == 0x4D5A } \\ Library cache file: AX
rule sign_293 { condition: uint16be(0) == 0x4D5A } \\ Control panel application: CPL
rule sign_294 { condition: uint16be(0) == 0x4D5A } \\ Font file: FON
rule sign_295 { condition: uint16be(0) == 0x4D5A } \\ ActiveX-OLE Custom Control: OCX
rule sign_296 { condition: uint16be(0) == 0x4D5A } \\ OLE object library: OLB
rule sign_297 { condition: uint16be(0) == 0x4D5A } \\ Screen saver: SCR
rule sign_298 { condition: uint16be(0) == 0x4D5A } \\ VisualBASIC application: VBX
rule sign_299 { condition: uint16be(0) == 0x4D5A } \\ Windows virtual device drivers: VXD,386
rule sign_300 { strings: $hex = { 4D 5A 90 00 03 00 00 00 } condition: $hex } \\ Acrobat plug-in: API
rule sign_301 { strings: $hex = { 4D 5A 90 00 03 00 00 00 } condition: $hex } \\ DirectShow filter: AX
rule sign_302 { strings: $hex = { 4D 5A 90 00 03 00 00 00 } condition: $hex } \\ Audition graphic filter: FLT
rule sign_303 { strings: $hex = { 4D 5A 90 00 03 00 00 00 04 00 00 00 FF FF } condition: $hex } \\ ZoneAlam data file: ZAP
rule sign_304 { strings: $hex = { 4D 69 63 72 6F 73 6F 66 74 20 43 2F 43 2B 2B 20 } condition: $hex } \\ MS C++ debugging symbols file: PDB
rule sign_305 { strings: $hex = { 4D 69 63 72 6F 73 6F 66 74 20 56 69 73 75 61 6C } condition: $hex } \\ Visual Studio .NET file: SLN
rule sign_306 { strings: $hex = { 4D 69 63 72 6F 73 6F 66 74 20 57 69 6E 64 6F 77 73 20 4D 65 64 69 61 20 50 6C 61 79 65 72 20 2D 2D 20 } condition: $hex } \\ Windows Media Player playlist: WPL
rule sign_307 { strings: $hex = { 4D 73 52 63 66 } condition: $hex } \\ VMapSource GPS Waypoint Database: GDB
rule sign_308 { strings: $hex = { 4E 41 56 54 52 41 46 46 } condition: $hex } \\ TomTom traffic data: DAT
rule sign_309 { condition: uint32be(0) == 0x4E422A00 } \\ MS Windows journal: JNT,JTP
rule sign_310 { strings: $hex = { 4E 45 53 4D 1A 01 } condition: $hex } \\ NES Sound file: NSF
rule sign_311 { strings: $hex = { 4E 49 54 46 30 } condition: $hex } \\ National Imagery Transmission Format file: NTF
rule sign_312 { strings: $hex = { 4E 61 6D 65 3A 20 } condition: $hex } \\ Agent newsreader character map: COD
rule sign_313 { strings: $hex = { 4F 50 43 4C 44 41 54 } condition: $hex } \\ 1Password 4 Cloud Keychain: attachment
rule sign_314 { strings: $hex = { 4F 50 4C 44 61 74 61 62 } condition: $hex } \\ Psion Series 3 Database: DBF
rule sign_315 { strings: $hex = { 4F 54 54 4F 00 } condition: $hex } \\ OpenType font: OTF
rule sign_316 { strings: $hex = { 4F 67 67 53 00 02 00 00 } condition: $hex } \\ Ogg Vorbis Codec compressed file: OGA,OGG,OGV,OGX
rule sign_317 { condition: uint16be(0) == 0x4F7B } \\ Visio-DisplayWrite 4 text file: DW4
rule sign_318 { strings: $hex = { 50 00 00 00 20 00 00 00 } condition: $hex } \\ Quicken QuickFinder Information File: IDX
rule sign_319 { strings: $hex = { 50 35 0A } condition: $hex } \\ Portable Graymap Graphic: PGM
rule sign_320 { condition: uint32be(0) == 0x5041434B } \\ Quake archive file: PAK
rule sign_321 { strings: $hex = { 50 41 47 45 44 55 } condition: $hex } \\ Windows memory dump: DMP
rule sign_322 { strings: $hex = { 50 41 58 } condition: $hex } \\ PAX password protected bitmap: PAX
rule sign_323 { condition: uint32be(0) == 0x50455354 } \\ PestPatrol data-scan strings: DAT
rule sign_324 { strings: $hex = { 50 47 50 64 4D 41 49 4E } condition: $hex } \\ PGP disk image: PGD
rule sign_325 { strings: $hex = { 50 49 43 54 00 08 } condition: $hex } \\ ChromaGraph Graphics Card Bitmap: IMG
rule sign_326 { condition: uint32be(0) == 0x504B0304 } \\ PKZIP archive_1: ZIP
rule sign_327 { condition: uint32be(0) == 0x504B0304 } \\ Android package: APK
rule sign_328 { condition: uint32be(0) == 0x504B0304 } \\ MacOS X Dashboard Widget: ZIP
rule sign_329 { condition: uint32be(0) == 0x504B0304 } \\ MS Office Open XML Format Document: DOCX,PPTX,XLSX
rule sign_330 { condition: uint32be(0) == 0x504B0304 } \\ Java archive_1: JAR
rule sign_331 { condition: uint32be(0) == 0x504B0304 } \\ Google Earth session file: KMZ
rule sign_332 { condition: uint32be(0) == 0x504B0304 } \\ KWord document: KWD
rule sign_333 { condition: uint32be(0) == 0x504B0304 } \\ OpenDocument template: ODT,ODP,OTT
rule sign_334 { condition: uint32be(0) == 0x504B0304 } \\ Microsoft Open XML paper specification: OXPS
rule sign_335 { condition: uint32be(0) == 0x504B0304 } \\ OpenOffice documents: SXC,SXD,SXI,SXW
rule sign_336 { condition: uint32be(0) == 0x504B0304 } \\ StarOffice spreadsheet: SXC
rule sign_337 { condition: uint32be(0) == 0x504B0304 } \\ Windows Media compressed skin file: WMZ
rule sign_338 { condition: uint32be(0) == 0x504B0304 } \\ Mozilla Browser Archive: XPI
rule sign_339 { condition: uint32be(0) == 0x504B0304 } \\ XML paper specification file: XPS
rule sign_340 { condition: uint32be(0) == 0x504B0304 } \\ eXact Packager Models: XPT
rule sign_341 { strings: $hex = { 50 4B 03 04 0A 00 02 00 } condition: $hex } \\ Open Publication Structure eBook: EPUB
rule sign_342 { strings: $hex = { 50 4B 03 04 14 00 01 00 } condition: $hex } \\ ZLock Pro encrypted ZIP: ZIP
rule sign_343 { strings: $hex = { 50 4B 03 04 14 00 06 00 } condition: $hex } \\ MS Office 2007 documents: DOCX,PPTX,XLSX
rule sign_344 { strings: $hex = { 50 4B 03 04 14 00 08 00 } condition: $hex } \\ Java archive_2: JAR
rule sign_345 { condition: uint32be(0) == 0x504B0506 } \\ PKZIP archive_2: ZIP
rule sign_346 { condition: uint32be(0) == 0x504B0708 } \\ PKZIP archive_3: ZIP
rule sign_347 { strings: $hex = { 50 4B 4C 49 54 45 } condition: $hex } \\ PKLITE archive: ZIP
rule sign_348 { strings: $hex = { 50 4B 53 70 58 } condition: $hex } \\ PKSFX self-extracting archive: ZIP
rule sign_349 { condition: uint32be(0) == 0x504D4343 } \\ Windows Program Manager group file: GRP
rule sign_350 { strings: $hex = { 50 4E 43 49 55 4E 44 4F } condition: $hex } \\ Norton Disk Doctor undo file: DAT
rule sign_351 { strings: $hex = { 50 4D 4F 43 43 4D 4F 43 } condition: $hex } \\ Microsoft Windows User State Migration Tool: PMOCCMOC
rule sign_352 { condition: uint32be(0) == 0x50534612 } \\ Dreamcast Sound Format: DSF
rule sign_353 { condition: uint32be(0) == 0x50554658 } \\ Puffer encrypted archive: PUF
rule sign_354 { condition: uint32be(0) == 0x50615645 } \\ Parrot Video Encapsulation: (none)
rule sign_355 { condition: uint32be(92) == 0x51454C20 } \\ Quicken data: QEL
rule sign_356 { strings: $hex = { 51 46 49 } condition: $hex } \\ Qcow Disk Image: QEMU
rule sign_357 { strings: $hex = { 51 4C 43 4D 66 6D 74 20 } condition: $hex } \\ RIFF Qualcomm PureVoice: QCP
rule sign_358 { strings: $hex = { 51 57 20 56 65 72 2E 20 } condition: $hex } \\ Quicken data file: ABD,QSD
rule sign_359 { strings: $hex = { 52 00 6F 00 6F 00 74 00 20 00 45 00 6E 00 74 00 72 00 79 00 } condition: $hex } \\ Outlook-Exchange message subheader: MSG
rule sign_360 { strings: $hex = { 52 41 5A 41 54 44 42 31 } condition: $hex } \\ Shareaza (P2P) thumbnail: DAT
rule sign_361 { strings: $hex = { 52 44 58 32 0A } condition: $hex } \\ R saved work space: RDATA
rule sign_362 { strings: $hex = { 52 45 47 45 44 49 54 } condition: $hex } \\ WinNT Registry-Registry Undo files: REG,SUD
rule sign_363 { strings: $hex = { 52 45 56 4E 55 4D 3A 2C } condition: $hex } \\ Antenna data file: AD
rule sign_364 { condition: uint32be(0) == 0x52494646 } \\ Windows animated cursor: ANI
rule sign_365 { condition: uint32be(0) == 0x52494646 } \\ Corel Presentation Exchange metadata: CMX
rule sign_366 { condition: uint32be(0) == 0x52494646 } \\ CorelDraw document: CDR
rule sign_367 { condition: uint32be(0) == 0x52494646 } \\ Video CD MPEG movie: DAT
rule sign_368 { condition: uint32be(0) == 0x52494646 } \\ Micrografx Designer graphic: DS4
rule sign_369 { condition: uint32be(0) == 0x52494646 } \\ 4X Movie video: 4XM
rule sign_370 { condition: uint32be(0) == 0x52494646 } \\ Resource Interchange File Format: AVI,CDA,QCP,RMI,WAV,WEBP
rule sign_371 { strings: $hex = { 52 4D 49 44 64 61 74 61 } condition: $hex } \\ RIFF Windows MIDI: RMI
rule sign_372 { condition: uint32be(0) == 0x52545353 } \\ WinNT Netmon capture file: CAP
rule sign_373 { strings: $hex = { 52 61 72 21 1A 07 00 } condition: $hex } \\ WinRAR compressed archive: RAR
rule sign_374 { strings: $hex = { 52 65 74 75 72 6E 2D 50 } condition: $hex } \\ Generic e-mail_1: EML
rule sign_375 { condition: uint32be(4) == 0x53434341 } \\ Windows prefetch: PF
rule sign_376 { condition: uint32be(0) == 0x5343486C } \\ Underground Audio: AST
rule sign_377 { condition: uint32be(0) == 0x53434D49 } \\ Img Software Bitmap: IMG
rule sign_378 { condition: uint32be(0) == 0x53445058 } \\ SMPTE DPX (big endian): SDPX
rule sign_379 { condition: uint32be(0) == 0x53484F57 } \\ Harvard Graphics presentation: SHW
rule sign_380 { strings: $hex = { 53 49 45 54 52 4F 4E 49 } condition: $hex } \\ Sietronics CPI XRD document: CPI
rule sign_381 { strings: $hex = { 53 49 4D 50 4C 45 20 20 3D 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 54 } condition: $hex } \\ Flexible Image Transport System (FITS) file: FITS
rule sign_382 { strings: $hex = { 53 49 54 21 00 } condition: $hex } \\ StuffIt archive: SIT
rule sign_383 { strings: $hex = { 53 4D 41 52 54 44 52 57 } condition: $hex } \\ SmartDraw Drawing file: SDR
rule sign_384 { strings: $hex = { 53 50 46 49 00 } condition: $hex } \\ StorageCraft ShadownProtect backup file: SPF
rule sign_385 { condition: uint32be(0) == 0x53505642 } \\ MultiBit Bitcoin blockchain file: SPVB
rule sign_386 { strings: $hex = { 53 51 4C 69 74 65 20 66 6F 72 6D 61 74 20 33 00 } condition: $hex } \\ SQLite database file: DB
rule sign_387 { strings: $hex = { 53 51 4C 4F 43 4F 4E 56 } condition: $hex } \\ DB2 conversion file: CNV
rule sign_388 { strings: $hex = { 53 5A 20 88 F0 27 33 D1 } condition: $hex } \\ QBASIC SZDD file: (none)
rule sign_389 { strings: $hex = { 53 5A 44 44 88 F0 27 33 } condition: $hex } \\ SZDD file format: (none)
rule sign_390 { strings: $hex = { 53 74 75 66 66 49 74 20 } condition: $hex } \\ StuffIt compressed archive: SIT
rule sign_391 { strings: $hex = { 53 75 70 65 72 43 61 6C } condition: $hex } \\ SuperCalc worksheet: CAL
rule sign_392 { condition: uint32be(0) == 0x54485000 } \\ Wii-GameCube: THP
rule sign_393 { strings: $hex = { 54 68 69 73 20 69 73 20 } condition: $hex } \\ GNU Info Reader file: INFO
rule sign_394 { condition: uint32be(0) == 0x55434558 } \\ Unicode extensions: UCE
rule sign_395 { strings: $hex = { 55 46 41 C6 D2 C1 } condition: $hex } \\ UFA compressed archive: UFA
rule sign_396 { strings: $hex = { 55 46 4F 4F 72 62 69 74 } condition: $hex } \\ UFO Capture map file: DAT
rule sign_397 { strings: $hex = { 55 6E 46 69 6E 4D 46 } condition: $hex } \\ Measurement Data Format file: MF4
rule sign_398 { strings: $hex = { 56 43 50 43 48 30 } condition: $hex } \\ Visual C PreCompiled header: PCH
rule sign_399 { strings: $hex = { 56 45 52 53 49 4F 4E 20 } condition: $hex } \\ Visual Basic User-defined Control file: CTL
rule sign_400 { strings: $hex = { 56 65 72 73 69 6F 6E 20 } condition: $hex } \\ MapInfo Interchange Format file: MIF
rule sign_401 { strings: $hex = { 57 04 00 00 53 50 53 53 20 74 65 6D 70 6C 61 74 } condition: $hex } \\ SPSS template: SCT
rule sign_402 { strings: $hex = { 57 41 56 45 66 6D 74 20 } condition: $hex } \\ RIFF Windows Audio: WAV
rule sign_403 { condition: uint32be(8) == 0x57454250 } \\ RIFF WebP: WEBP
rule sign_404 { condition: uint32be(0) == 0x574D4D50 } \\ Walkman MP3 file: DAT
rule sign_405 { strings: $hex = { 57 53 32 30 30 30 } condition: $hex } \\ WordStar for Windows file: WS2
rule sign_406 { strings: $hex = { 57 69 6E 5A 69 70 } condition: $hex } \\ WinZip compressed archive: ZIP
rule sign_407 { strings: $hex = { 57 6F 72 64 50 72 6F } condition: $hex } \\ Lotus WordPro file: LWP
rule sign_408 { condition: uint16be(0) == 0x582D } \\ Exchange e-mail: EML
rule sign_409 { condition: uint32be(0) == 0x58435000 } \\ Packet sniffer files: CAP
rule sign_410 { strings: $hex = { 58 50 43 4F 4D 0A 54 79 } condition: $hex } \\ XPCOM libraries: XPT
rule sign_411 { condition: uint32be(0) == 0x58504453 } \\ SMPTE DPX file (little endian): DPX
rule sign_412 { condition: uint16be(0) == 0x5854 } \\ MS Publisher: BDR
rule sign_413 { condition: uint32be(0) == 0x5A4F4F20 } \\ ZOO compressed archive: ZOO
rule sign_414 { strings: $hex = { 5A 57 53 } condition: $hex } \\ Macromedia Shockwave Flash: SWF
rule sign_415 { strings: $hex = { 5B 47 65 6E 65 72 61 6C } condition: $hex } \\ MS Exchange configuration file: ECF
rule sign_416 { strings: $hex = { 5B 4D 53 56 43 } condition: $hex } \\ Visual C++ Workbench Info File: VCW
rule sign_417 { strings: $hex = { 5B 50 68 6F 6E 65 5D } condition: $hex } \\ Dial-up networking file: DUN
rule sign_418 { strings: $hex = { 5B 56 45 52 5D } condition: $hex } \\ Lotus AMI Pro document_1: SAM
rule sign_419 { strings: $hex = { 5B 56 4D 44 5D } condition: $hex } \\ VocalTec VoIP media file: VMD
rule sign_420 { strings: $hex = { 5B 57 69 6E 64 6F 77 73 } condition: $hex } \\ Microsoft Code Page Translation file: CPX
rule sign_421 { strings: $hex = { 5B 66 6C 74 73 69 6D 2E } condition: $hex } \\ Flight Simulator Aircraft Configuration: CFG
rule sign_422 { strings: $hex = { 5B 70 6C 61 79 6C 69 73 74 5D } condition: $hex } \\ WinAmp Playlist: PLS
rule sign_423 { strings: $hex = { 5B 76 65 72 5D } condition: $hex } \\ Lotus AMI Pro document_2: SAM
rule sign_424 { condition: uint32be(0) == 0x5DFCC800 } \\ Husqvarna Designer: HUS
rule sign_425 { condition: uint32be(0) == 0x5F27A889 } \\ Jar archive: JAR
rule sign_426 { strings: $hex = { 5F 43 41 53 45 5F } condition: $hex } \\ EnCase case file: CAS,CBK
rule sign_427 { condition: uint16be(0) == 0x60EA } \\ Compressed archive file: ARJ
rule sign_428 { strings: $hex = { 62 65 67 69 6E } condition: $hex } \\ UUencoded file: (none)
rule sign_429 { strings: $hex = { 62 65 67 69 6E 2D 62 61 73 65 36 34 } condition: $hex } \\ UUencoded BASE64 file: b64
rule sign_430 { strings: $hex = { 62 70 6C 69 73 74 } condition: $hex } \\ Binary property list (plist): (none)
rule sign_431 { condition: uint32be(0) == 0x63616666 } \\ Apple Core Audio File: CAF
rule sign_432 { strings: $hex = { 63 64 73 61 65 6E 63 72 } condition: $hex } \\ Macintosh encrypted Disk image (v1): DMG
rule sign_433 { strings: $hex = { 63 6F 6E 65 63 74 69 78 } condition: $hex } \\ Virtual PC HD image: VHD
rule sign_434 { strings: $hex = { 63 75 73 68 00 00 00 02 } condition: $hex } \\ Photoshop Custom Shape: CSH
rule sign_435 { condition: uint32be(0) == 0x64000000 } \\ Intel PROset-Wireless Profile: P10
rule sign_436 { strings: $hex = { 64 38 3A 61 6E 6E 6F 75 6E 63 65 } condition: $hex } \\ Torrent file: TORRENT
rule sign_437 { condition: uint32be(0) == 0x6465780A } \\ Dalvik (Android) executable file: dex
rule sign_438 { condition: uint32be(0) == 0x646E732E } \\ Audacity audio file: AU
rule sign_439 { strings: $hex = { 64 73 77 66 69 6C 65 } condition: $hex } \\ MS Visual Studio workspace file: DSW
rule sign_440 { strings: $hex = { 65 6E 63 72 63 64 73 61 } condition: $hex } \\ Macintosh encrypted Disk image (v2): DMG
rule sign_441 { condition: uint32be(0) == 0x66490000 } \\ WinNT printer spool file: SHD
rule sign_442 { strings: $hex = { 66 4C 61 43 00 00 00 22 } condition: $hex } \\ Free Lossless Audio Codec file: FLAC
rule sign_443 { strings: $hex = { 66 74 79 70 33 67 70 35 } condition: $hex } \\ MPEG-4 video file_1: MP4
rule sign_444 { strings: $hex = { 66 74 79 70 4D 34 41 20 } condition: $hex } \\ Apple Lossless Audio Codec file: M4A
rule sign_445 { strings: $hex = { 66 74 79 70 4D 34 56 20 } condition: $hex } \\ ISO Media-MPEG v4-iTunes AVC-LC: FLV,M4V
rule sign_446 { strings: $hex = { 66 74 79 70 4D 53 4E 56 } condition: $hex } \\ MPEG-4 video file_2: MP4
rule sign_447 { strings: $hex = { 66 74 79 70 69 73 6F 6D } condition: $hex } \\ ISO Base Media file (MPEG-4) v1: MP4
rule sign_448 { strings: $hex = { 66 74 79 70 6D 70 34 32 } condition: $hex } \\ MPEG-4 video-QuickTime file: M4V
rule sign_449 { strings: $hex = { 66 74 79 70 71 74 20 20 } condition: $hex } \\ QuickTime movie_7: MOV
rule sign_450 { condition: uint32be(0) == 0x67490000 } \\ Win2000-XP printer spool file: SHD
rule sign_451 { strings: $hex = { 67 69 6d 70 20 78 63 66 } condition: $hex } \\ GIMP file: XCF
rule sign_452 { condition: uint32be(0) == 0x68490000 } \\ Win Server 2003 printer spool file: SHD
rule sign_453 { condition: uint32be(0) == 0x69636E73 } \\ MacOS icon file: ICNS
rule sign_454 { condition: uint32be(0) == 0x6C33336C } \\ Skype user data file: DBB
rule sign_455 { condition: uint32be(4) == 0x6D6F6F76 } \\ QuickTime movie_1: MOV
rule sign_456 { condition: uint32be(4) == 0x66726565 } \\ QuickTime movie_2: MOV
rule sign_457 { condition: uint32be(4) == 0x6D646174 } \\ QuickTime movie_3: MOV
rule sign_458 { condition: uint32be(4) == 0x77696465 } \\ QuickTime movie_4: MOV
rule sign_459 { condition: uint32be(4) == 0x706E6F74 } \\ QuickTime movie_5: MOV
rule sign_460 { condition: uint32be(4) == 0x736B6970 } \\ QuickTime movie_6: MOV
rule sign_461 { strings: $hex = { 6D 73 46 69 6C 74 65 72 4C 69 73 74 } condition: $hex } \\ Internet Explorer v11 Tracking Protection List: TPL
rule sign_462 { strings: $hex = { 6D 75 6C 74 69 42 69 74 2E 69 6E 66 6F } condition: $hex } \\ MultiBit Bitcoin wallet information: INFO
rule sign_463 { condition: uint16be(0) == 0x6F3C } \\ SMS text (SIM): (none)
rule sign_464 { strings: $hex = { 6F 70 64 61 74 61 30 31 } condition: $hex } \\ 1Password 4 Cloud Keychain encrypted data: (none)
rule sign_465 { condition: uint32be(0) == 0x72656766 } \\ WinNT registry file: DAT
rule sign_466 { condition: uint32be(0) == 0x72696666 } \\ Sonic Foundry Acid Music File: AC
rule sign_467 { strings: $hex = { 72 74 73 70 3A 2F 2F } condition: $hex } \\ RealMedia metafile: RAM
rule sign_468 { condition: uint32be(0) == 0x736C6821 } \\ Allegro Generic Packfile (compressed): DAT
rule sign_469 { condition: uint32be(0) == 0x736C682E } \\ Allegro Generic Packfile (uncompressed): DAT
rule sign_470 { strings: $hex = { 73 6D 5F } condition: $hex } \\ PalmOS SuperMemo: PDB
rule sign_471 { strings: $hex = { 73 6F 6C 69 64 } condition: $hex } \\ STL (STereoLithography) file: STL
rule sign_472 { strings: $hex = { 73 72 63 64 6F 63 69 64 } condition: $hex } \\ CALS raster bitmap: CAL
rule sign_473 { condition: uint32be(0) == 0x737A657A } \\ PowerBASIC Debugger Symbols: PDB
rule sign_474 { strings: $hex = { 74 42 4D 50 4B 6E 57 72 } condition: $hex } \\ PathWay Map file: PRC
rule sign_475 { strings: $hex = { 74 72 75 65 00 } condition: $hex } \\ TrueType font: TTF
rule sign_476 { strings: $hex = { 75 73 74 61 72 } condition: $hex } \\ Tape Archive: TAR
rule sign_477 { condition: uint32be(0) == 0x762F3101 } \\ OpenEXR bitmap image: EXR
rule sign_478 { strings: $hex = { 76 32 30 30 33 2E 31 30 } condition: $hex } \\ Qimage filter: FLT
rule sign_479 { condition: uint32be(0) == 0x774F4632 } \\ Web Open Font Format 2: WOFF2
rule sign_480 { condition: uint32be(0) == 0x774F4646 } \\ Web Open Font Format: WOFF
rule sign_481 { strings: $hex = { 78 01 73 0D 62 62 60 } condition: $hex } \\ MacOS X image file: DMG
rule sign_482 { condition: uint32be(0) == 0x78617221 } \\ eXtensible ARchive file: XAR
rule sign_483 { condition: uint32be(0) == 0x7A626578 } \\ ZoomBrowser Image Index: INFO
rule sign_484 { strings: $hex = { 7B 0D 0A 6F 20 } condition: $hex } \\ Windows application log: LGC,LGD
rule sign_485 { strings: $hex = { 7B 22 75 72 6C 22 3A 20 22 68 74 74 70 73 3A 2F } condition: $hex } \\ Google Drive Drawing link: GDRAW
rule sign_486 { strings: $hex = { 7B 5C 70 77 69 } condition: $hex } \\ MS WinMobile personal note: PWI
rule sign_487 { strings: $hex = { 7B 5C 72 74 66 31 } condition: $hex } \\ Rich Text Format: RTF
rule sign_488 { strings: $hex = { 7C 4B C3 74 E1 C8 53 A4 79 B9 01 1D FC 4F DD 13 } condition: $hex } \\ Huskygram Poem or Singer embroidery: CSD
rule sign_489 { condition: uint32be(0) == 0x7E424B00 } \\ Corel Paint Shop Pro image: PSP
rule sign_490 { strings: $hex = { 7E 45 53 44 77 F6 85 3E BF 6A D2 11 45 61 73 79 20 53 74 72 65 65 74 20 44 72 61 77 } condition: $hex } \\ Easy Street Draw diagram file: ESD
rule sign_491 { strings: $hex = { 7E 74 2C 01 50 70 02 4D 52 } condition: $hex } \\ Digital Watchdog DW-TP-500G audio: IMG
rule sign_492 { condition: uint32be(0) == 0x7F454C46 } \\ ELF executable: (none)
rule sign_493 { condition: uint8(0) == 0x80 } \\ Relocatable object code: OBJ
rule sign_494 { strings: $hex = { 80 00 00 20 03 12 04 } condition: $hex } \\ Dreamcast audio: ADX
rule sign_495 { condition: uint32be(0) == 0x802A5FD7 } \\ Kodak Cineon image: CIN
rule sign_496 { strings: $hex = { 81 32 84 C1 85 05 D0 11 } condition: $hex } \\ Outlook Express address book (Win95): WAB
rule sign_497 { strings: $hex = { 81 CD AB } condition: $hex } \\ WordPerfect text: WPF
rule sign_498 { strings: $hex = { 89 50 4E 47 0D 0A 1A 0A } condition: $hex } \\ PNG image: PNG
rule sign_499 { strings: $hex = { 8A 01 09 00 00 00 E1 08 } condition: $hex } \\ MS Answer Wizard: AW
rule sign_500 { condition: uint32be(0) == 0x91334846 } \\ Hamarsoft compressed archive: HAP
rule sign_501 { condition: uint16be(0) == 0x9500 } \\ PGP secret keyring_1: SKR
rule sign_502 { condition: uint16be(0) == 0x9501 } \\ PGP secret keyring_2: SKR
rule sign_503 { strings: $hex = { 97 4A 42 32 0D 0A 1A 0A } condition: $hex } \\ JBOG2 image file: JB2
rule sign_504 { condition: uint8(0) == 0x99 } \\ GPG public keyring: GPG
rule sign_505 { condition: uint16be(0) == 0x9901 } \\ PGP public keyring: PKR
rule sign_506 { strings: $hex = { 9C CB CB 8D 13 75 D2 11 } condition: $hex } \\ Outlook address file: WAB
rule sign_507 { condition: uint32be(0) == 0xA1B2C3D4 } \\ tcpdump (libpcap) capture file: (none)
rule sign_508 { condition: uint32be(0) == 0xA1B2CD34 } \\ Extended tcpdump (libpcap) capture file: (none)
rule sign_509 { strings: $hex = { A9 0D 00 00 00 00 00 00 } condition: $hex } \\ Access Data FTK evidence: DAT
rule sign_510 { strings: $hex = { AB 4B 54 58 20 31 31 BB 0D 0A 1A 0A } condition: $hex } \\ Khronos texture file: KTX
rule sign_511 { strings: $hex = { AC 9E BD 8F 00 00 } condition: $hex } \\ Quicken data: QDF
rule sign_512 { condition: uint32be(512) == 0xA0461DF0 } \\ PowerPoint presentation subheader_3: PPT
rule sign_513 { condition: uint16be(0) == 0xACED } \\ Java serialization data: (none)
rule sign_514 { strings: $hex = { AC ED 00 05 73 72 00 12 } condition: $hex } \\ BGBlitz position database file: PDB
rule sign_515 { condition: uint32be(0) == 0xB04D4643 } \\ Win95 password file: PWL
rule sign_516 { condition: uint32be(0) == 0xB168DE3A } \\ PCX bitmap: DCX
rule sign_517 { condition: uint32be(0) == 0xB46E6844 } \\ Acronis True Image_1: TIB
rule sign_518 { strings: $hex = { B5 A2 B0 B3 B3 B0 A5 B5 } condition: $hex } \\ Windows calendar: CAL
rule sign_519 { condition: uint32be(0) == 0xB8C90C00 } \\ InstallShield Script: INS
rule sign_520 { strings: $hex = { BE 00 00 00 AB } condition: $hex } \\ MS Write file_3: WRI
rule sign_521 { strings: $hex = { BE BA FE CA 0F 50 61 6C 6D 53 47 20 44 61 74 61 } condition: $hex } \\ Palm Desktop DateBook: DAT
rule sign_522 { condition: uint32be(0) == 0xC3ABCDAB } \\ MS Agent Character file: ACS
rule sign_523 { condition: uint32be(0) == 0xC5D0D3C6 } \\ Adobe encapsulated PostScript: EPS
rule sign_524 { condition: uint32be(0) == 0xC8007900 } \\ Jeppesen FliteLog file: LBK
rule sign_525 { condition: uint32be(0) == 0xCAFEBABE } \\ Java bytecode: CLASS
rule sign_526 { strings: $hex = { CC 52 33 FC E9 2C 18 48 AF E3 36 30 1A 39 40 06 } condition: $hex } \\ Nokia phone backup file: NBU
rule sign_527 { strings: $hex = { CD 20 AA AA 02 00 00 00 } condition: $hex } \\ NAV quarantined virus file: (none)
rule sign_528 { strings: $hex = { CE 24 B9 A2 20 00 00 00 } condition: $hex } \\ Acronis True Image_2: TIB
rule sign_529 { condition: uint32be(0) == 0xCECECECE } \\ Java Cryptography Extension keystore: JCEKS
rule sign_530 { condition: uint32be(0) == 0xCEFAEDFE } \\ OS X ABI Mach-O binary (32-bit reverse): (none)
rule sign_531 { strings: $hex = { CF 11 E0 A1 B1 1A E1 00 } condition: $hex } \\ Perfect Office document: DOC
rule sign_532 { condition: uint32be(0) == 0xCFAD12FE } \\ Outlook Express e-mail folder: DBX
rule sign_533 { condition: uint32be(0) == 0xCFFAEDFE } \\ OS X ABI Mach-O binary (64-bit reverse): (none)
rule sign_534 { strings: $hex = { D0 CF 11 E0 A1 B1 1A E1 } condition: $hex } \\ Microsoft Office document: DOC,DOT,PPS,PPT,XLA,XLS,WIZ
rule sign_535 { strings: $hex = { D0 CF 11 E0 A1 B1 1A E1 } condition: $hex } \\ CaseWare Working Papers: AC_
rule sign_536 { strings: $hex = { D0 CF 11 E0 A1 B1 1A E1 } condition: $hex } \\ Access project file: ADP
rule sign_537 { strings: $hex = { D0 CF 11 E0 A1 B1 1A E1 } condition: $hex } \\ Lotus-IBM Approach 97 file: APR
rule sign_538 { strings: $hex = { D0 CF 11 E0 A1 B1 1A E1 } condition: $hex } \\ MSWorks database file: DB
rule sign_539 { strings: $hex = { D0 CF 11 E0 A1 B1 1A E1 } condition: $hex } \\ Microsoft Common Console Document: MSC
rule sign_540 { strings: $hex = { D0 CF 11 E0 A1 B1 1A E1 } condition: $hex } \\ Microsoft Installer package: MSI
rule sign_541 { strings: $hex = { D0 CF 11 E0 A1 B1 1A E1 } condition: $hex } \\ Microsoft Installer Patch: MSP
rule sign_542 { strings: $hex = { D0 CF 11 E0 A1 B1 1A E1 } condition: $hex } \\ Minitab data file: MTW
rule sign_543 { strings: $hex = { D0 CF 11 E0 A1 B1 1A E1 } condition: $hex } \\ ArcMap GIS project file: MXD
rule sign_544 { strings: $hex = { D0 CF 11 E0 A1 B1 1A E1 } condition: $hex } \\ Developer Studio File Options file: OPT
rule sign_545 { strings: $hex = { D0 CF 11 E0 A1 B1 1A E1 } condition: $hex } \\ MS Publisher file: PUB
rule sign_546 { strings: $hex = { D0 CF 11 E0 A1 B1 1A E1 } condition: $hex } \\ Revit Project file: RVT
rule sign_547 { strings: $hex = { D0 CF 11 E0 A1 B1 1A E1 } condition: $hex } \\ Visual Studio Solution User Options file: SOU
rule sign_548 { strings: $hex = { D0 CF 11 E0 A1 B1 1A E1 } condition: $hex } \\ SPSS output file: SPO
rule sign_549 { strings: $hex = { D0 CF 11 E0 A1 B1 1A E1 } condition: $hex } \\ Visio file: VSD
rule sign_550 { strings: $hex = { D0 CF 11 E0 A1 B1 1A E1 } condition: $hex } \\ MSWorks text document: WPS
rule sign_551 { condition: uint32be(0) == 0xD20A0000 } \\ WinPharoah filter file: FTR
rule sign_552 { condition: uint16be(0) == 0xD42A } \\ AOL history|typed URL files: ARL,AUT
rule sign_553 { condition: uint32be(0) == 0xD4C3B2A1 } \\ WinDump (winpcap) capture file: (none)
rule sign_554 { condition: uint32be(0) == 0xD7CDC69A } \\ Windows graphics metafile: WMF
rule sign_555 { condition: uint32be(0) == 0xDBA52D00 } \\ Word 2.0 file: DOC
rule sign_556 { condition: uint16be(0) == 0xDCDC } \\ Corel color palette: CPL
rule sign_557 { condition: uint16be(0) == 0xDCFE } \\ eFax file: EFX
rule sign_558 { strings: $hex = { E3 10 00 01 00 00 00 00 } condition: $hex } \\ Amiga icon: INFO
rule sign_559 { condition: uint32be(0) == 0xE3828596 } \\ Win98 password file: PWL
rule sign_560 { strings: $hex = { E4 52 5C 7B 8C D8 A7 4D } condition: $hex } \\ MS OneNote note: ONE
rule sign_561 { condition: uint8(0) == 0xE8 } \\ Windows executable file_1: COM,SYS
rule sign_562 { condition: uint8(0) == 0xE9 } \\ Windows executable file_2: COM,SYS
rule sign_563 { condition: uint8(0) == 0xEB } \\ Windows executable file_3: COM,SYS
rule sign_564 { condition: uint32be(0) == 0xEB3C902A } \\ GEM Raster file: IMG
rule sign_565 { strings: $hex = { EB 52 90 2D 46 56 45 2D } condition: $hex } \\ BitLocker boot sector (Vista): (none)
rule sign_566 { strings: $hex = { EB 58 90 2D 46 56 45 2D } condition: $hex } \\ BitLocker boot sector (Win7): (none)
rule sign_567 { condition: uint32be(512) == 0xECA5C100 } \\ Word document subheader: DOC
rule sign_568 { condition: uint32be(0) == 0xEDABEEDB } \\ RedHat Package Manager: RPM
rule sign_569 { strings: $hex = { EF BB BF } condition: $hex } \\ UTF-8 file: (none)
rule sign_570 { condition: uint32be(0) == 0xEFBBBF3C } \\ Windows Script Component (UTF-8)_1: WSF
rule sign_571 { strings: $hex = { EF BB BF 3C 3F } condition: $hex } \\ Windows Script Component (UTF-8)_2: WSC
rule sign_572 { strings: $hex = { EF BB BF 3C 3F 78 6D 6C 20 76 65 72 73 69 6F 6E } condition: $hex } \\ YouTube Timed Text (subtitle) file: YTT
rule sign_573 { strings: $hex = { F0 FF FF } condition: $hex } \\ FAT12 File Allocation Table: (none)
rule sign_574 { condition: uint32be(0) == 0xF8FFFFFF } \\ FAT16 File Allocation Table: (none)
rule sign_575 { strings: $hex = { F8 FF FF 0F FF FF FF 0F } condition: $hex } \\ FAT32 File Allocation Table_1: (none)
rule sign_576 { strings: $hex = { F8 FF FF 0F FF FF FF FF } condition: $hex } \\ FAT32 File Allocation Table_2: (none)
rule sign_577 { condition: uint32be(0) == 0xF9BEB4D9 } \\ Bitcoin-Qt blockchain block file: DAT
rule sign_578 { strings: $hex = { FD 37 7A 58 5A 00 } condition: $hex } \\ XZ archive: XZ
rule sign_579 { strings: $hex = { FD 37 7A 58 5A 00 } condition: $hex } \\ MS Publisher subheader: PUB
rule sign_580 { condition: uint32be(512) == 0xFDFFFFFF } \\ Thumbs.db subheader: DB
rule sign_581 { strings: $hex = { FD FF FF FF 02 } condition: $hex } \\ MS Publisher file subheader: PUB
rule sign_582 { strings: $hex = { FD FF FF FF 04 } condition: $hex } \\ Microsoft Outlook-Exchange Message: MSG
rule sign_583 { strings: $hex = { FD FF FF FF 04 } condition: $hex } \\ QuickBooks Portable Company File: QBM
rule sign_584 { strings: $hex = { FD FF FF FF 04 } condition: $hex } \\ Visual Studio Solution subheader: SUO
rule sign_585 { strings: $hex = { FD FF FF FF 0E 00 00 00 } condition: $hex } \\ PowerPoint presentation subheader_4: PPT
rule sign_586 { strings: $hex = { FD FF FF FF 10 } condition: $hex } \\ Excel spreadsheet subheader_2: XLS
rule sign_587 { strings: $hex = { FD FF FF FF 1C 00 00 00 } condition: $hex } \\ PowerPoint presentation subheader_5: PPT
rule sign_588 { strings: $hex = { FD FF FF FF 1F } condition: $hex } \\ Excel spreadsheet subheader_3: XLS
rule sign_589 { strings: $hex = { FD FF FF FF 20 } condition: $hex } \\ Developer Studio subheader: OPT
rule sign_590 { strings: $hex = { FD FF FF FF 22 } condition: $hex } \\ Excel spreadsheet subheader_4: XLS
rule sign_591 { strings: $hex = { FD FF FF FF 23 } condition: $hex } \\ Excel spreadsheet subheader_5: XLS
rule sign_592 { strings: $hex = { FD FF FF FF 28 } condition: $hex } \\ Excel spreadsheet subheader_6: XLS
rule sign_593 { strings: $hex = { FD FF FF FF 29 } condition: $hex } \\ Excel spreadsheet subheader_7: XLS
rule sign_594 { strings: $hex = { FD FF FF FF 43 00 00 00 } condition: $hex } \\ PowerPoint presentation subheader_6: PPT
rule sign_595 { condition: uint32be(0) == 0xFEEDFACE } \\ OS X ABI Mach-O binary (32-bit): (none)
rule sign_596 { condition: uint32be(0) == 0xFEEDFACF } \\ OS X ABI Mach-O binary (64-bit): (none)
rule sign_597 { condition: uint32be(0) == 0xFEEDFEED } \\ JavaKeyStore: (none)
rule sign_598 { condition: uint16be(0) == 0xFEEF } \\ Symantex Ghost image file: GHO,GHS
rule sign_599 { condition: uint16be(0) == 0xFEFF } \\ UTF-16-UCS-2 file: (none)
rule sign_600 { condition: uint8(0) == 0xFF } \\ Windows executable: SYS
rule sign_601 { strings: $hex = { FF 00 02 00 04 04 05 54 } condition: $hex } \\ Works for Windows spreadsheet: WKS
rule sign_602 { strings: $hex = { FF 0A 00 } condition: $hex } \\ QuickReport Report: QRP
rule sign_603 { strings: $hex = { FF 46 4F 4E 54 } condition: $hex } \\ Windows international code page: CPI
rule sign_604 { strings: $hex = { FF 4B 45 59 42 20 20 20 } condition: $hex } \\ Keyboard driver file: SYS
rule sign_605 { condition: uint32be(0) == 0xFF575043 } \\ WordPerfect text and graphics: WP,WPD,WPG,WPP,WP5,WP6
rule sign_606 { condition: uint16be(0) == 0xFFD8 } \\ Generic JPEG Image file: JPE,JPEG,JPG
rule sign_607 { strings: $hex = { FF D8 FF } condition: $hex } \\ JPEG-EXIF-SPIFF images: JFIF,JPE,JPEG,JPG
rule sign_608 { condition: uint16be(0) == 0xFFF1 } \\ MPEG-4 AAC audio: AAC
rule sign_609 { condition: uint16be(0) == 0xFFF9 } \\ MPEG-2 AAC audio: AAC
rule sign_610 { condition: uint16be(0) == 0xFFFE } \\ Windows Registry file: REG
rule sign_611 { condition: uint16be(0) == 0xFFFE } \\ UTF-32-UCS-2 file: (none)
rule sign_612 { condition: uint32be(0) == 0xFFFE0000 } \\ UTF-32-UCS-4 file: (none)
rule sign_613 { strings: $hex = { FF FE 23 00 6C 00 69 00 } condition: $hex } \\ MSinfo file: MOF
rule sign_614 { condition: uint32be(0) == 0xFFFFFFFF } \\ DOS system driver: SYS
