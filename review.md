# Code Review — osdp.py

## Summary

The analyser is functional and well-structured. Five issues are worth fixing: two are real bugs, two are quality/consistency problems introduced alongside the LED work, and one is a minor omission. Three pieces of dead code and one performance issue are also noted.

---

## Bugs

### 1. Duplicate opcode in `GetCmdReplyCode` — SCRYPT/CCRYPT and MFG/PIVDATAR never resolve correctly

**Lines 797 and 824; Lines 801 and 828**

Two opcodes are assigned to both a command and a reply:

| Opcode | Command (first match) | Reply (unreachable) |
|--------|-----------------------|---------------------|
| `0x76` | `SCRYPT`              | `CCRYPT`            |
| `0x80` | `MFG`                 | `PIVDATAR`          |

Because `GetCmdReplyCode` uses a chain of `if` statements, the first match always wins. The reply codes `CCRYPT` (0x76) and `PIVDATAR` (0x80) are therefore never returned.

**Fix:** Pass the direction flag into `GetCmdReplyCode` so it can branch on whether the byte is a command or a reply. The address byte (byte 1) already sets `is_reply`; store it as `self.pkt_is_reply` and use it in the lookup:

```python
def GetCmdReplyCode(self, cmd, is_reply):
    ...
    if cmd == 0x76:
        return 'CCRYPT' if is_reply else 'SCRYPT'
    if cmd == 0x80:
        return 'PIVDATAR' if is_reply else 'MFG'
    ...
```

Call site (line 530):
```python
self.pkt_cmd = self.GetCmdReplyCode(ch, self.pkt_is_reply)
```

---

### 2. `led_info` not cleared at the command byte — can bleed into the next LED packet on a truncated capture

**Line 529–536 vs line 697**

When the command byte (byte 5) is decoded, the code resets several summary fields:

```python
self.raw_decoded = ''
self.raw_data = None
self.kp_digits = ''
self.kp_digit_count = 0
self.buz_info = ''
```

`led_info` is absent from this list. It is only reset inside the `LED` data block at byte 6 (`self.led_info = ''`, line 697) and at end-of-packet (line 773). If a capture ends mid-LED packet (truncated), `led_info` will survive into the next session and appear on unrelated packets despite the end-of-packet reset never firing.

**Fix:** Add `self.led_info = ''` to the command-byte reset block at line 535:

```python
self.buz_info = ''
self.led_info = ''   # add this line
```

---

## Quality / Consistency Issues

### 3. Bare `except:` silently swallows all exceptions including `KeyboardInterrupt`

**Lines 470–474**

```python
try:
    ch = frame.data['data'][0]
except:
    # Not an ASCII character
    return
```

A bare `except:` catches `SystemExit`, `KeyboardInterrupt`, and every other exception. If the frame object has an unexpected structure the error is silently discarded, making debugging very difficult.

**Fix:**

```python
except (KeyError, IndexError, TypeError):
    return
```

---

### 4. LED lookup tables rebuilt on every byte

**Lines 692–695**

```python
elif self.pkt_cmd == 'LED':
    LED_CTRL_TEMP = {0: 'NOP', 1: 'Cancel', 2: 'Set timer'}
    LED_CTRL_PERM = {0: 'NOP', 1: 'Set'}
    LED_COLORS    = {0: 'None', 1: 'Red', ...}
```

These three dictionaries are created as local variables inside `decode()`, meaning they are constructed fresh on every call while a LED packet is being decoded (up to 14 times). The same issue exists for `tone_names` in the BUZ block (line 627).

**Fix:** Promote them to module-level constants (above the class definition):

```python
_LED_CTRL_TEMP = {0: 'NOP', 1: 'Cancel', 2: 'Set timer'}
_LED_CTRL_PERM = {0: 'NOP', 1: 'Set'}
_LED_COLORS    = {0: 'None', 1: 'Red', 2: 'Green', 3: 'Amber',
                  4: 'Blue', 5: 'Magenta', 6: 'Cyan', 7: 'White'}
_BUZ_TONE_NAMES = {0: 'No tone', 1: 'Off', 2: 'Default'}
```

---

### 5. Ambiguous `ON=` / `OFF=` field names in LED console summary

**Lines 754–758**

The permanent LED summary currently produces:

```
Perm=Set ON=100ms OFF=0ms ON=Green OFF=Green
```

`ON=` and `OFF=` appear twice — once for timing and once for colour. It is not obvious which is which.

**Fix:** Use distinct names to separate timing from colour:

```python
self.led_info += (f' Perm={self.led_perm_ctrl}'
                  f' ON={self.led_perm_on * 100}ms'
                  f' OFF={self.led_perm_off * 100}ms'
                  f' ON_col={self.led_perm_on_col}'
                  f' OFF_col={self.led_perm_off_col}')
```

Apply the same rename to the temporary struct summary at lines 730–734 (`T_col=` → `T_ON_col=`/`T_OFF_col=`).

---

## Dead Code

### 6. Unreachable `else` branch in PDCAP parser

**Lines 612–613**

```python
elif (self.byte_cnt % 3) == 2:
    msg = AnalyzerFrame(...)
else:
    msg = AnalyzerFrame('OSDP', ..., {'string': 'PDCAP parsing error'})
```

`n % 3` always yields 0, 1, or 2. The `else` branch is mathematically unreachable.

**Fix:** Remove the `else` block.

---

### 7. Redundant `raw_data is None` guard

**Lines 666–668**

```python
if self.raw_data is None:
    self.raw_data = []
self.raw_data.append(ch)
```

`self.raw_data` is unconditionally set to `[]` at line 661, five lines earlier. The guard can never be true when reached via normal control flow.

**Fix:** Remove the guard:

```python
self.raw_data.append(ch)
```

---

## Minor

### 8. `raw_decoded` not cleared at end-of-packet

**Line 771–775**

The end-of-packet handler now consistently clears `led_info`, `buz_info`, and `kp_digits`. `raw_decoded` is not cleared there — it relies solely on being reset at the command byte (line 531). While this works in practice (a new RAW packet will reset it), it is inconsistent with the pattern established for the other summary fields and could produce a stale value if `raw_decoded` were ever tested outside the command-byte path.

**Fix:** Add `self.raw_decoded = ''` to the end-of-packet reset block alongside the other fields.

---

## Issue Summary

| # | Severity | Location | Issue |
|---|----------|----------|-------|
| 1 | Bug | Lines 797, 824 | Duplicate opcodes 0x76 / 0x80 — reply codes never returned |
| 2 | Bug | Line 535 | `led_info` not reset at command byte |
| 3 | Quality | Lines 470–474 | Bare `except:` swallows all exceptions |
| 4 | Quality | Lines 627, 692–695 | Lookup dicts rebuilt on every decode call |
| 5 | Quality | Lines 754–758 | Ambiguous `ON=`/`OFF=` field names in LED summary |
| 6 | Dead code | Lines 612–613 | Unreachable `else` in PDCAP (`n % 3` is always 0–2) |
| 7 | Dead code | Lines 666–668 | `raw_data is None` guard is never true |
| 8 | Minor | Line 773 | `raw_decoded` not cleared at end-of-packet |
