================================================================================
CTF PLATFORM & WORKBENCH - MASTER IMPLEMENTATION ROADMAP
================================================================================
Target Folder: C:\faiyaaz\projects\CTF
Backend (ctf-be):  Java 17 (LTS) + Spring Boot 3.3.x + MongoDB Atlas (Port 8080)
Frontend (ctf-fe): React 19 + Vite + Pure CSS Cyber Theme (Port 5173)

ROADMAP STATUS LEGEND:
[COMPLETED]   - Finished, tested, and pushed to GitHub
[CURRENT]     - Current step we are actively building
[UPCOMING]    - Next scheduled step in sequence

================================================================================
PHASE 1: SCAFFOLDING & FOUNDATION [COMPLETED]
================================================================================
[COMPLETED] Step 1.1: Clone and link GitHub repositories (ctf_fe & ctf_be)
[COMPLETED] Step 1.2: Initialize Java 17 + Spring Boot 3.3.x backend with Maven Wrapper (3.9.9)
[COMPLETED] Step 1.3: Initialize React 19 + Vite frontend with lucide-react & axios
[COMPLETED] Step 1.4: Create 1-click Windows dev launcher (run-dev.bat)
[COMPLETED] Step 1.5: Configure MongoDB Atlas connection with .env & gitignore protection

================================================================================
PHASE 2: BACKEND CORE ARCHITECTURE & DATABASE [COMPLETED]
================================================================================
[COMPLETED] Step 2.1: Implement MongoDB Models (User, Note, FlagCandidate, Challenge, Announcement)
[COMPLETED] Step 2.2: Implement Spring Data Repositories for all 5 models
[COMPLETED] Step 2.3: Implement Stateless JWT Authentication (JwtTokenProvider, JwtAuthFilter)
[COMPLETED] Step 2.4: Implement AuthController (/api/auth/register, /api/auth/login, /api/auth/me)
[COMPLETED] Step 2.5: Implement WorkspaceController (Persistent Notes & Cloud Flag Hunter APIs)
[COMPLETED] Step 2.6: Implement ChallengeController (Challenge board, hints & flag verify)

================================================================================
PHASE 3: FRONTEND FOUNDATION & DESIGN SYSTEM [COMPLETED]
================================================================================
[COMPLETED] Step 3.1: Cyber Design System & Tokens (src/styles/theme.css, auth.css, admin.css)
[COMPLETED] Step 3.2: Axios API Service Layer with JWT Bearer Interceptor (src/services/api.js)
[COMPLETED] Step 3.3: Global State Contexts (AuthContext.jsx & authService.js)
[COMPLETED] Step 3.4: Master App Layout (Navbar, Category Sidebar, Backend Live Indicator)
[COMPLETED] Step 3.5: Core UI Infrastructure (ToolWrapper, SendToMenu, CommandPalette, HexViewer)
================================================================================
PHASE 4: FRONTEND AUTH & PERSISTENT WORKSPACE PAGES [COMPLETED]
================================================================================
[COMPLETED] Step 4.1: LoginPage.jsx & RegisterPage.jsx (Operator authentication UI)
[COMPLETED] Step 4.2: NotesScratchpad.jsx (Cloud-persisted operator notes with auto-save)
[COMPLETED] Step 4.3: FlagHunter.jsx (Real-time regex flag scanner & MongoDB candidate pool)
[COMPLETED] Step 4.4: ChallengesPage.jsx (Live challenge board, solve counter & flag submission)

================================================================================
PHASE 5: MODULAR TOOL IMPLEMENTATION (64 TOOLS ACROSS 7 DOMAINS)
================================================================================
--- [5.1 Cryptography Suite (17 Tools)] ---
[COMPLETED] Step 5.1.1:  MultiDecoder.jsx (Base64, Hex, URL, Binary, ROT13, Atbash, Morse)
[COMPLETED] Step 5.1.2:  XorToolkit.jsx (Single-byte brute force & repeating key XOR)
[COMPLETED] Step 5.1.3:  HashUtils.jsx (MD5, SHA1/256/512, NTLM & type heuristic detector)
[COMPLETED] Step 5.1.4:  EncodingLab.jsx (Base32, Base58, Base64, Base85, Hex)
[COMPLETED] Step 5.1.5:  NumberConverter.jsx (Dec, Hex, Oct, Bin, ASCII, IEEE-754 float)
[COMPLETED] Step 5.1.6:  RsaHelper.jsx (Basic n, p, q, phi, d calculation)
[COMPLETED] Step 5.1.7:  AtbashCipher.jsx (Reversible alphabet substitution)
[COMPLETED] Step 5.1.8:  RailFenceCipher.jsx (Zig-zag transposition cipher)
[COMPLETED] Step 5.1.9:  BaconianCipher.jsx (5-bit binary alphabet cipher)
[COMPLETED] Step 5.1.10: BitwiseCalculator.jsx (Visual bitwise operator sandbox)
[COMPLETED] Step 5.1.11: RsaAttackLab.jsx + Backend Java Wiener/Fermat Engine
[COMPLETED] Step 5.1.12: VigenereSolver.jsx + Backend Java IoC Key Deduction
[COMPLETED] Step 5.1.13: PaddingOracleSim.jsx (PKCS#7 CBC decryption stepping simulator)
[COMPLETED] Step 5.1.14: SubstitutionSolver.jsx (Monoalphabetic solver with n-gram frequency)
[COMPLETED] Step 5.1.15: DiscreteLogSolver.jsx + Backend Java Baby-step Giant-step
[COMPLETED] Step 5.1.16: CribDragCracker.jsx (Interactive two-time pad crib dragging)
[CURRENT]   Step 5.1.17: RotShiftTable.jsx (Simultaneous 25-rotation Caesar table)

--- [5.2 Web Exploitation Suite (8 Tools)] ---
[UPCOMING]  Step 5.2.1: JwtAnalyzer.jsx (Token inspector, signature tamper & none-exploit)
[UPCOMING]  Step 5.2.2: PayloadGen.jsx (Curated dictionary across 13 web attack categories)
[UPCOMING]  Step 5.2.3: RequestAnalyzer.jsx + Backend Java HTTP Security Header Auditor
[UPCOMING]  Step 5.2.4: RegexTester.jsx (Interactive regex tester with CTF presets)
[UPCOMING]  Step 5.2.5: UrlParser.jsx (URL component decomposition)
[UPCOMING]  Step 5.2.6: UserAgentParser.jsx (Browser, OS, device fingerprint identifier)
[UPCOMING]  Step 5.2.7: HttpStatusCodes.jsx (RFC catalog with CTF security attack hints)
[UPCOMING]  Step 5.2.8: SstiSqliPlayground.jsx (Jinja2/Twig/SpEL RCE & SQLi filter bypass)

--- [5.3 Forensics & Steganography Suite (12 Tools)] ---
[UPCOMING]  Step 5.3.1:  FileAnalyzer.jsx (Magic byte identification & mime detection)
[UPCOMING]  Step 5.3.2:  StegAssistant.jsx (zsteg, steghide, binwalk command generator)
[UPCOMING]  Step 5.3.3:  LsbStegReader.jsx (HTML5 Canvas bitplane reader for LSBs)
[UPCOMING]  Step 5.3.4:  TimestampConverter.jsx (Epoch, Unix ms, Windows FILETIME, UUIDv1)
[UPCOMING]  Step 5.3.5:  ExifFieldReference.jsx (GPS, camera model, author metadata sheet)
[UPCOMING]  Step 5.3.6:  MimeTypeReference.jsx (Binary magic signatures dictionary)
[UPCOMING]  Step 5.3.7:  DefaultCredentials.jsx (Searchable router/server/CMS database)
[UPCOMING]  Step 5.3.8:  PcapParser.jsx + Backend Java PCAP Binary Stream Inspector
[UPCOMING]  Step 5.3.9:  MagicByteCarver.jsx + Backend Java Multipart File Carver
[UPCOMING]  Step 5.3.10: ZipCracker.jsx + Backend Java Multi-Threaded ZIP Password Cracker
[UPCOMING]  Step 5.3.11: PngChunkFixer.jsx + Backend Java IHDR CRC-32 Height Fixer
[UPCOMING]  Step 5.3.12: Base64MediaExtractor.jsx (Data-URI image, audio, SVG previewer)

--- [5.4 Network & OSINT Suite (5 Tools)] ---
[UPCOMING]  Step 5.4.1: NetworkCalc.jsx (IPv4/IPv6 CIDR subnet & wildcard calculator)
[UPCOMING]  Step 5.4.2: OsintWorkspace.jsx (Shodan, VirusTotal, Censys, Dork aggregator)
[UPCOMING]  Step 5.4.3: WordlistsReference.jsx (SecLists, RockYou download cheat sheets)
[UPCOMING]  Step 5.4.4: WhoisReference.jsx (Domain registrar & TLD field guide)
[UPCOMING]  Step 5.4.5: LiveWhoisDns.jsx + Backend Java TCP Port 43 Socket & Live DNS Resolver

--- [5.5 Reverse Engineering & Pwn Suite (13 Tools)] ---
[UPCOMING]  Step 5.5.1:  AsmReference.jsx (x86, x64, ARM opcode & register guide)
[UPCOMING]  Step 5.5.2:  RopReference.jsx (ROP gadgets, stack pivoting, ret2libc)
[UPCOMING]  Step 5.5.3:  FormatStringHelper.jsx (%x, %s, %n write offset generator)
[UPCOMING]  Step 5.5.4:  BinaryOverview.jsx (ELF, PE, Mach-O section structures)
[UPCOMING]  Step 5.5.5:  AsciiTable.jsx (0-255 ASCII character table)
[UPCOMING]  Step 5.5.6:  EndiannessConverter.jsx (Big/Little endian byte swapper)
[UPCOMING]  Step 5.5.7:  DataTypeSizes.jsx (C/C++ architectural types reference)
[UPCOMING]  Step 5.5.8:  CyclicPatternTool.jsx + Backend Java De Bruijn Sequence Generator
[UPCOMING]  Step 5.5.9:  ShellcodeReference.jsx (Curated Linux/Windows shellcodes)
[UPCOMING]  Step 5.5.10: PwnOffsetCalc.jsx (Stack alignment & frame pointer assistant)
[UPCOMING]  Step 5.5.11: EsolangInterpreter.jsx (Brainfuck visualizer with memory tape)
[UPCOMING]  Step 5.5.12: PwntoolsScriptGen.jsx (Boilerplate solve.py generator)
[UPCOMING]  Step 5.5.13: SyscallMatrix.jsx (Linux x86 & x64 syscall reference matrix)

--- [5.6 Reference & Search Suite (2 Tools)] ---
[UPCOMING]  Step 5.6.1: KaliCommands.jsx (Searchable 200+ commands in 10 categories)
[UPCOMING]  Step 5.6.2: GoogleDorkGen.jsx (1-click sensitive file search generator)

--- [5.7 Workspace & Productivity Suite (7 Tools)] ---
[UPCOMING]  Step 5.7.1: NotesScratchpad.jsx (Cloud notes with auto-save & tagging)
[UPCOMING]  Step 5.7.2: TextUtils.jsx (Deduplicator, sorter, word/char count, trimmer)
[UPCOMING]  Step 5.7.3: DiffChecker.jsx (Side-by-side text difference visualizer)
[UPCOMING]  Step 5.7.4: QrCodeReference.jsx (QR anatomy & error correction levels)
[UPCOMING]  Step 5.7.5: FlagHunter.jsx (Global regex candidate pool with cloud sync)
[UPCOMING]  Step 5.7.6: CommandPalette.jsx (Global Ctrl+K fuzzy launcher)
[UPCOMING]  Step 5.7.7: WriteUpGenerator.jsx (1-click markdown writeup compiler)

================================================================================
PHASE 6: FULL VERIFICATION & DEPLOYMENT PREPARATION
================================================================================
[UPCOMING]  Step 6.1: Full frontend production build verification (npm run build)
[UPCOMING]  Step 6.2: Full backend production build verification (mvnw clean package)
[UPCOMING]  Step 6.3: End-to-end integration test (UI -> Java -> MongoDB Atlas)
[UPCOMING]  Step 6.4: Multi-stage Dockerfile packaging for ctf-be (< 150MB Temurin JRE)
[UPCOMING]  Step 6.5: Final git sync and release documentation
================================================================================
