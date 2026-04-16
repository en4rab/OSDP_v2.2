# High Level Analyzer
# For more information and documentation, please go to 
# https://support.saleae.com/extensions/high-level-analyzer-extensions

from saleae.analyzers import HighLevelAnalyzer, AnalyzerFrame, StringSetting, NumberSetting, ChoicesSetting

# Lookup tables used during decode — defined once at module level
_BUZ_TONE_NAMES = {0: 'No tone', 1: 'Off', 2: 'Default'}
_LED_CTRL_TEMP  = {0: 'NOP', 1: 'Cancel', 2: 'Set timer'}
_LED_CTRL_PERM  = {0: 'NOP', 1: 'Set'}
_LED_COLORS     = {0: 'None', 1: 'Red', 2: 'Green', 3: 'Amber',
                   4: 'Blue', 5: 'Magenta', 6: 'Cyan', 7: 'White'}


# High level analyzers must subclass the HighLevelAnalyzer class.
class OSDP_Analyzer(HighLevelAnalyzer):

    byte_cnt = 0            # byte counter for the current packet
    pkt_start_time = None   # packet start times for multibyte messages
    pkt_len = 0             # current packet length
    pkt_crc = None          # if current packet has crc (or checksum)
    pkt_scb = None          # if current packet has Security Control Block
    pkt_cmd = None          # current command
    pkt_is_reply = False    # True if packet is a PD->CP reply
    tmp = None              # temporary storage between decode() runnings

    # Console summary fields (assembled across bytes, printed at end of packet)
    pkt_addr_str = ''       # e.g. "CP->PD[0]"
    pkt_sqn = 0             # sequence number

    # RAW card data fields
    raw_format = None       # format byte (0=bit array, 1=wiegand)
    raw_bit_count = 0       # number of wiegand bits
    raw_data = None         # list of raw data bytes being collected
    raw_decoded = ''        # decoded card string (for console summary)

    # KEYPAD fields
    kp_digit_count = 0      # number of digits declared in the message
    kp_digits = ''          # digits collected so far

    # BUZ fields
    buz_info = ''           # assembled summary for console output

    # LED fields
    led_info = ''           # assembled summary for console output
    led_num = 0             # LED number
    led_temp_ctrl = ''      # temporary control code name
    led_temp_on = 0         # temporary on_count in units of 100 ms
    led_temp_off = 0        # temporary off_count in units of 100 ms
    led_temp_on_col = ''    # temporary on_color name
    led_temp_off_col = ''   # temporary off_color name
    led_perm_ctrl = ''      # permanent control code name
    led_perm_on = 0         # permanent on_count in units of 100 ms
    led_perm_off = 0        # permanent off_count in units of 100 ms
    led_perm_on_col = ''    # permanent on_color name
    led_perm_off_col = ''   # permanent off_color name

    # An optional list of types this analyzer produces, providing a way to 
    # customize the way frames are displayed in Logic 2.
    result_types = {
        'OSDP': {
            'format': '{{data.string}}'
        }
    }

    def __init__(self):
        print('[OSDP] Analyzer ready')

    # -------------------------------------------------------------------------
    # Wiegand / card data decoding
    # -------------------------------------------------------------------------

    def _bytes_to_bits(self, data_bytes, bit_count):
        """Convert byte array to MSB-first bit list of exactly bit_count bits."""
        bits = []
        for i in range(bit_count):
            byte_idx = i // 8
            bit_idx = 7 - (i % 8)
            if byte_idx < len(data_bytes):
                bits.append((data_bytes[byte_idx] >> bit_idx) & 1)
            else:
                bits.append(0)
        return bits

    def _extract(self, bits, start, end):
        """Extract bits[start..end] inclusive into an integer (MSB first)."""
        val = 0
        for i in range(start, min(end + 1, len(bits))):
            val = (val << 1) | bits[i]
        return val

    def _ep_ok(self, bits, parity_idx, data_start, data_end):
        """Even parity check: parity bit should make total 1-count even."""
        if parity_idx >= len(bits):
            return False
        count = sum(bits[data_start:data_end + 1])
        return bits[parity_idx] == (count % 2)

    def _op_ok(self, bits, parity_idx, data_start, data_end):
        """Odd parity check: parity bit should make total 1-count odd."""
        if parity_idx >= len(bits):
            return False
        count = sum(bits[data_start:data_end + 1])
        return bits[parity_idx] == (1 - count % 2)

    def decode_wiegand(self, data_bytes, bit_count):
        """
        Decode wiegand card data from raw OSDP bytes.
        Data bytes are packed MSB-first per OSDP spec.
        Returns a human-readable string with all candidate interpretations.
        """
        if bit_count == 0 or not data_bytes:
            return 'No card data'

        bits = self._bytes_to_bits(data_bytes, bit_count)
        results = []

        ex = self._extract  # shorthand

        if bit_count == 26:
            # H10301 (most common access control format)
            fc = ex(bits, 1, 8)
            cn = ex(bits, 9, 24)
            p = 'OK' if self._ep_ok(bits, 0, 1, 12) and self._op_ok(bits, 25, 13, 24) else 'Fail'
            results.append(f'H10301: FC={fc} CN={cn} P={p}')
            # Indala interpretation of same 26 bits
            fc_i = ex(bits, 1, 12)
            cn_i = ex(bits, 13, 24)
            results.append(f'Indala: FC={fc_i} CN={cn_i}')

        elif bit_count == 27:
            # Indala
            fc = ex(bits, 0, 12)
            cn = ex(bits, 13, 26)
            results.append(f'Indala(27b): FC={fc} CN={cn}')
            # Indala ASC — FC and CN assembled from non-sequential bit positions
            fc_asc_pattern = [9, 4, 6, 5, 0, 7, 19, 8, 10, 16, 24, 12, 22]
            cn_asc_pattern = [26, 1, 3, 15, 14, 17, 20, 13, 25, 2, 18, 21, 11, 23]
            fc_asc = 0
            for i in fc_asc_pattern:
                fc_asc = (fc_asc << 1) | (bits[i] if i < len(bits) else 0)
            cn_asc = 0
            for i in cn_asc_pattern:
                cn_asc = (cn_asc << 1) | (bits[i] if i < len(bits) else 0)
            results.append(f'Indala-ASC(27b): FC={fc_asc} CN={cn_asc}')
            # Tecom — FC and CN assembled from non-sequential bit positions
            fc_tecom_pattern = [15, 19, 24, 23, 22, 18, 6, 10, 14, 3, 2]
            cn_tecom_pattern = [0, 1, 13, 12, 9, 26, 20, 16, 17, 21, 25, 7, 8, 11, 4, 5]
            fc_tecom = 0
            for i in fc_tecom_pattern:
                fc_tecom = (fc_tecom << 1) | (bits[i] if i < len(bits) else 0)
            cn_tecom = 0
            for i in cn_tecom_pattern:
                cn_tecom = (cn_tecom << 1) | (bits[i] if i < len(bits) else 0)
            results.append(f'Tecom(27b): FC={fc_tecom} CN={cn_tecom}')

        elif bit_count == 28:
            fc = ex(bits, 4, 11)
            cn = ex(bits, 12, 26)
            p = 'OK' if self._ep_ok(bits, 0, 1, 13) and self._op_ok(bits, 27, 0, 26) else 'Fail'
            results.append(f'2804: FC={fc} CN={cn} P={p}')

        elif bit_count == 29:
            # Indala
            fc = ex(bits, 0, 12)
            cn = ex(bits, 13, 28)
            results.append(f'Indala(29b): FC={fc} CN={cn}')

        elif bit_count == 30:
            fc = ex(bits, 1, 12)
            cn = ex(bits, 13, 28)
            p = 'OK' if self._ep_ok(bits, 0, 1, 12) and self._op_ok(bits, 29, 13, 28) else 'Fail'
            results.append(f'ATS(30b): FC={fc} CN={cn} P={p}')

        elif bit_count == 31:
            fc = ex(bits, 1, 4)
            cn = ex(bits, 5, 27)
            results.append(f'HID-ADT(31b): FC={fc} CN={cn}')

        elif bit_count == 32:
            fc = ex(bits, 1, 13)
            cn = ex(bits, 14, 30)
            p = 'OK' if self._ep_ok(bits, 0, 1, 13) and self._op_ok(bits, 31, 14, 30) else 'Fail'
            results.append(f'ATS(32b): FC={fc} CN={cn} P={p}')
            fc2 = ex(bits, 1, 12)
            cn2 = ex(bits, 13, 30)
            results.append(f'HID(32b): FC={fc2} CN={cn2}')

        elif bit_count == 33:
            # Indala DSX and HID D10202 share the same FC/CN layout: FC bits 1-7, CN bits 8-31
            fc = ex(bits, 1, 7)
            cn = ex(bits, 8, 31)
            results.append(f'Indala-DSX(33b): FC={fc} CN={cn}')
            p = 'OK' if self._ep_ok(bits, 0, 1, 16) and self._op_ok(bits, 32, 16, 31) else 'Fail'
            results.append(f'HID-D10202(33b): FC={fc} CN={cn} P={p}')
            # RS2-HID R901592C — FC bits 2-3, CN bits 4-30
            # parity: bit 1 = even over bits 2-30, bit 31 = odd over bits 2-30
            fc2 = ex(bits, 2, 3)
            cn2 = ex(bits, 4, 30)
            ep2 = sum(bits[2:31])
            op2 = sum(bits[2:31])
            p2 = 'OK' if (bits[1] == ep2 % 2 and bits[31] == (1 - op2 % 2)) else 'Fail'
            results.append(f'RS2-HID-R901592C(33b): FC={fc2} CN={cn2} P={p2}')

        elif bit_count == 34:
            p = 'OK' if self._ep_ok(bits, 0, 1, 16) and self._op_ok(bits, 33, 17, 32) else 'Fail'
            # HID H10306
            fc = ex(bits, 1, 16)
            cn = ex(bits, 17, 32)
            results.append(f'H10306(34b): FC={fc} CN={cn} P={p}')
            # Indala Optus — FC and CN are swapped in bit position
            fc2 = ex(bits, 22, 32)
            cn2 = ex(bits, 1, 16)
            results.append(f'Indala-Optus(34b): FC={fc2} CN={cn2}')
            # Cardkey Smartpass
            fc3 = ex(bits, 1, 13)
            cn3 = ex(bits, 17, 32)
            il3 = ex(bits, 14, 16)
            results.append(f'Cardkey-Smartpass(34b): FC={fc3} CN={cn3} IL={il3}')
            # HID N1002
            fc4 = ex(bits, 9, 16)
            cn4 = ex(bits, 17, 32)
            results.append(f'HID-N1002(34b): FC={fc4} CN={cn4}')
            # BQT
            fc5 = ex(bits, 1, 8)
            cn5 = ex(bits, 9, 32)
            results.append(f'BQT(34b): FC={fc5} CN={cn5} P={p}')
            # Full Card Number
            csn34 = ex(bits, 1, 32)
            results.append(f'FullCSN(34b): {csn34}')

        elif bit_count == 35:
            # HID Corporate 1000
            cid = ex(bits, 2, 13)
            cn = ex(bits, 14, 33)
            results.append(f'Corp1000(35b): CID={cid} CN={cn}')

        elif bit_count == 36:
            # Chubb
            fc = ex(bits, 1, 14)
            cn = ex(bits, 19, 34)
            results.append(f'Chubb(36b): FC={fc} CN={cn}')
            # HID Inner Range
            fc2 = ex(bits, 21, 32)
            cn2 = ex(bits, 1, 16)
            results.append(f'HID-InnerRange(36b): FC={fc2} CN={cn2}')
            # HID Simplex
            fc3 = ex(bits, 1, 8)
            il3 = ex(bits, 9, 10)
            cn3 = ex(bits, 11, 34)
            op1 = sum(bits[1:18])
            op2 = sum(bits[17:35])
            p3 = 'OK' if (bits[0] == (1 - op1 % 2) and bits[35] == (1 - op2 % 2)) else 'Fail'
            results.append(f'HID-Simplex(36b): FC={fc3} CN={cn3} IL={il3} P={p3}')
            # HID Siemens
            fc4 = ex(bits, 1, 18)
            cn4 = ex(bits, 19, 34)
            results.append(f'HID-Siemens(36b): FC={fc4} CN={cn4}')

        elif bit_count == 37:
            p = 'OK' if self._ep_ok(bits, 0, 1, 18) and self._op_ok(bits, 36, 18, 35) else 'Fail'
            # H10302 - CSN only (no facility code)
            cn = ex(bits, 1, 35)
            results.append(f'H10302(37b): CN={cn} P={p}')
            # H10304 / Farpointe
            fc = ex(bits, 1, 16)
            cn2 = ex(bits, 17, 35)
            results.append(f'H10304(37b): FC={fc} CN={cn2} P={p}')
            # GuardPoint MDI
            fc3 = ex(bits, 3, 6)
            cn3 = ex(bits, 7, 35)
            results.append(f'GuardPoint-MDI(37b): FC={fc3} CN={cn3} P={p}')
            # AWID RS2 34 — own parity: bit 0 even over bits 1-16, bit 33 odd over bits 17-32
            fc4 = ex(bits, 1, 8)
            cn4 = ex(bits, 9, 32)
            p4 = 'OK' if self._ep_ok(bits, 0, 1, 16) and self._op_ok(bits, 33, 17, 32) else 'Fail'
            results.append(f'AWID-RS2-34(37b): FC={fc4} CN={cn4} P={p4}')
            # HID Generic — card number only, no parity
            cn5 = ex(bits, 4, 35)
            results.append(f'HID-Generic(37b): CN={cn5}')

        elif bit_count == 38:
            # ISCS
            fc = ex(bits, 5, 14)
            cn = ex(bits, 15, 36)
            p = 'OK' if self._ep_ok(bits, 0, 1, 18) and self._op_ok(bits, 37, 19, 36) else 'Fail'
            results.append(f'ISCS(38b): FC={fc} CN={cn} P={p}')
            # BQT
            fc2 = ex(bits, 24, 36)
            cn2 = ex(bits, 1, 19)
            results.append(f'BQT(38b): FC={fc2} AN={cn2}')

        elif bit_count == 39:
            fc = ex(bits, 1, 17)
            cn = ex(bits, 18, 37)
            p = 'OK' if self._ep_ok(bits, 0, 1, 18) and self._op_ok(bits, 38, 19, 37) else 'Fail'
            results.append(f'Pyramid(39b): FC={fc} CN={cn} P={p}')

        elif bit_count == 40:
            fc = ex(bits, 4, 15)
            cn = ex(bits, 16, 31)
            results.append(f'HID-Honeywell(40b): FC={fc} CN={cn}')
            fc2 = ex(bits, 1, 10)
            cn2 = ex(bits, 11, 38)
            p2 = 'OK' if self._ep_ok(bits, 0, 1, 19) and self._op_ok(bits, 39, 0, 38) else 'Fail'
            results.append(f'XceedID(40b): FC={fc2} CN={cn2} P={p2}')
            cn3 = ex(bits, 1, 38)
            results.append(f'Casi-Rusco(40b): CN={cn3}')

        elif bit_count == 42:
            # Lenel — FC bits 0-13, CN bits 14-25
            fc = ex(bits, 0, 13)
            cn = ex(bits, 14, 25)
            p = 'OK' if self._ep_ok(bits, 0, 1, 20) and self._op_ok(bits, 41, 21, 40) else 'Fail'
            results.append(f'Lenel(42b): FC={fc} CN={cn} P={p}')

        elif bit_count == 46:
            # DCAC — FC bits 7-20, CN bits 21-44
            fc = ex(bits, 7, 20)
            cn = ex(bits, 21, 44)
            results.append(f'DCAC(46b): FC={fc} CN={cn}')

        elif bit_count == 48:
            # HID H2004064 (Corporate 1000 48-bit)
            # Parity: bit 1 = even parity over pairs at every 3rd position; bit 0 = odd parity over bits 1-47
            cid = ex(bits, 2, 23)   # Company ID Code: bits 2-23 (22 bits)
            cn = ex(bits, 24, 46)  # Card Number: bits 24-46 (23 bits)
            ep1 = 0
            for i in range(3, 48):
                if i % 3 == 0:
                    if i < len(bits) and bits[i]:
                        ep1 += 1
                    if i + 1 < len(bits) and bits[i+1]:
                        ep1 += 1
            op1 = sum(bits[1:48])
            p1 = 'OK' if (bits[1] == ep1 % 2 and bits[0] == (1 - op1 % 2)) else 'Fail'
            results.append(f'H2004064-Corp1000(48b): CID={cid} CN={cn} P={p1}')

            # HID H10304 inner 37-bit (facility code + card number, offset inside the 48-bit frame)
            # Parity bit 11 = even over bits 12-29; parity bit 47 = odd over bits 29-46
            fc2 = ex(bits, 12, 27)  # Facility Code: bits 12-27 (16 bits)
            cn2 = ex(bits, 28, 46)  # Card Number:   bits 28-46 (19 bits)
            ep2 = sum(bits[12:30])
            op2 = sum(bits[29:47])
            p2 = 'OK' if (bits[11] == ep2 % 2 and bits[47] == (1 - op2 % 2)) else 'Fail'
            results.append(f'H10304(48b): FC={fc2} CN={cn2} P={p2}')

            # HUGHES ID H10302 (card number only, same parity positions as H10304)
            cn3 = ex(bits, 12, 46)  # Card Number: bits 12-46 (35 bits)
            results.append(f'HUGHES-H10302(48b): CN={cn3} P={p2}')
            # Full Card Number
            csn48 = ex(bits, 1, 46)
            results.append(f'FullCSN(48b): {csn48}')

        elif bit_count == 56:
            # Inner Range SIFER
            fc = ex(bits, 0, 23)
            cn = ex(bits, 24, 55)
            results.append(f'IR-SIFER(56b): FC={fc} CN={cn}')
            csn56 = ex(bits, 0, 55)
            results.append(f'FullCSN(56b): {csn56}')

        elif bit_count == 58:
            p = 'OK' if self._ep_ok(bits, 0, 1, 28) and self._op_ok(bits, 57, 29, 56) else 'Fail'
            agency  = ex(bits, 1, 14)
            system  = ex(bits, 15, 28)
            cred    = ex(bits, 29, 48)
            series  = ex(bits, 49, 52)
            issue   = ex(bits, 53, 56)
            results.append(f'TWIC/CAC-58(58b): Agency={agency} System={system} Cred={cred} Series={series} Issue={issue} P={p}')
            csn58 = ex(bits, 1, 56)
            results.append(f'FullCSN(58b): {csn58}')

        elif bit_count == 64:
            # TWIC/CAC 64 BCD
            agency  = ex(bits, 0, 15)
            system  = ex(bits, 16, 31)
            cred    = ex(bits, 32, 55)
            series  = ex(bits, 56, 59)
            issue   = ex(bits, 60, 63)
            results.append(f'TWIC/CAC-64-BCD(64b): Agency={agency} System={system} Cred={cred} Series={series} Issue={issue}')
            # TWIC/CAC 56 TSM
            agency2 = ex(bits, 0, 13)
            system2 = ex(bits, 14, 27)
            cred2   = ex(bits, 28, 47)
            series2 = ex(bits, 48, 51)
            issue2  = ex(bits, 52, 55)
            tsm     = ex(bits, 57, 63)
            results.append(f'TWIC/CAC-56-TSM(64b): Agency={agency2} System={system2} Cred={cred2} Series={series2} Issue={issue2} TSM={tsm}')
            csn64 = ex(bits, 0, 63)
            results.append(f'8byte-iCLASS-CSN(64b): {csn64}')

        elif bit_count == 75:
            p = 'OK' if self._ep_ok(bits, 0, 1, 37) and self._op_ok(bits, 74, 38, 73) else 'Fail'
            agency  = ex(bits, 1, 14)
            site    = ex(bits, 15, 28)
            cn      = ex(bits, 29, 48)
            expiry  = ex(bits, 49, 73)
            results.append(f'PIV(75b): Agency={agency} Site={site} CN={cn} Expiry={expiry} P={p}')
            cn_cls  = ex(bits, 1, 48)
            results.append(f'PIV-Class(75b): CN={cn_cls}')

        elif bit_count == 80:
            csn80 = ex(bits, 0, 79)
            results.append(f'10byte-CSN(80b): {csn80}')

        elif bit_count == 83:
            p = 'OK' if self._ep_ok(bits, 0, 1, 40) and self._op_ok(bits, 82, 41, 81) else 'Fail'
            agency  = ex(bits, 1, 14)
            system  = ex(bits, 15, 28)
            cred    = ex(bits, 29, 48)
            series  = ex(bits, 49, 52)
            issue   = ex(bits, 53, 56)
            expiry  = ex(bits, 57, 81)
            results.append(f'TWIC/CAC-83(83b): Agency={agency} System={system} Cred={cred} Series={series} Issue={issue} Expiry={expiry} P={p}')

        elif bit_count == 91:
            # TWIC/CAC 83 TSM — same fields as 83-bit plus TSM at bits 82-89, no parity
            agency  = ex(bits, 1, 14)
            system  = ex(bits, 15, 28)
            cred    = ex(bits, 29, 48)
            series  = ex(bits, 49, 52)
            issue   = ex(bits, 53, 56)
            expiry  = ex(bits, 57, 81)
            tsm     = ex(bits, 82, 89)
            results.append(f'TWIC/CAC-83-TSM(91b): Agency={agency} System={system} Cred={cred} Series={series} Issue={issue} Expiry={expiry} TSM={tsm}')

        elif bit_count == 107:
            # PIV 75 + HMAC 32 — same PIV fields in first 75 bits
            p = 'OK' if self._ep_ok(bits, 0, 1, 37) and self._op_ok(bits, 74, 38, 73) else 'Fail'
            agency  = ex(bits, 1, 14)
            site    = ex(bits, 15, 28)
            cn      = ex(bits, 29, 48)
            expiry  = ex(bits, 49, 73)
            results.append(f'PIV-75-HMAC-32(107b): Agency={agency} Site={site} CN={cn} Expiry={expiry} P={p}')

        elif bit_count == 128:
            csn128 = ex(bits, 0, 127)
            results.append(f'PIV-I(128b): CSN={csn128}')

        elif bit_count == 200:
            # PIV
            fc_piv  = ex(bits, 30, 49)
            cn_piv  = ex(bits, 55, 84)
            results.append(f'PIV(200b): FC={fc_piv} CN={cn_piv}')
            # FASC-N Embedded HMA/EXP — FC is bits 49 down to 30 (reversed)
            cn_fascn = ex(bits, 29, 48)
            fc_fascn = 0
            for i in range(49, 29, -1):
                fc_fascn = (fc_fascn << 1) | bits[i]
            results.append(f'FASC-N-Embedded-HMA/EXP(200b): FC={fc_fascn} CN={cn_fascn}')

        elif bit_count == 245:
            # FASC-N Appended EXP — FC is bits 49 down to 30 (reversed)
            cn_fascn = ex(bits, 29, 48)
            fc_fascn = 0
            for i in range(49, 29, -1):
                fc_fascn = (fc_fascn << 1) | bits[i]
            results.append(f'FASC-N-Appended-EXP(245b): FC={fc_fascn} CN={cn_fascn}')

        else:
            results.append(f'Unknown({bit_count}b)')

        # Always append raw hex CSN
        csn = 0
        for b in bits:
            csn = (csn << 1) | b
        hex_digits = (bit_count + 3) // 4
        results.append(f'Raw=0x{csn:0{hex_digits}X}')

        return ' | '.join(results)

    # -------------------------------------------------------------------------
    # Main decode entry point
    # -------------------------------------------------------------------------

    def decode(self, frame: AnalyzerFrame):
        try:
            ch = frame.data['data'][0]
        except (KeyError, IndexError, TypeError):
            return

        msg = AnalyzerFrame('OSDP', frame.start_time, frame.end_time, {})

        if self.byte_cnt == 0:
            if ch == 0x53:
                msg = AnalyzerFrame('OSDP', frame.start_time, frame.end_time, {'string': 'SOM'})
            else:
                return
        elif self.byte_cnt == 1:
            self.pkt_is_reply = bool(ch & 0x80)
            raw_addr = ch & 0x7F
            if raw_addr == 0x7F:
                addr_num = 'BC'
            else:
                addr_num = str(raw_addr)
            direction = 'PD->CP' if self.pkt_is_reply else 'CP->PD'
            self.pkt_addr_str = f'{direction}[{addr_num}]'
            addr = 'ADDR: '
            addr += 'BROADCAST' if raw_addr == 0x7F else str(raw_addr)
            if self.pkt_is_reply:
                addr += ' REPLY'
            msg = AnalyzerFrame('OSDP', frame.start_time, frame.end_time, {'string': addr})
        elif self.byte_cnt == 2:
            self.pkt_len = ch
            self.pkt_start_time = frame.start_time
            self.byte_cnt += 1
            return
        elif self.byte_cnt == 3:
            self.pkt_len = self.pkt_len + (ch << 8)
            if self.pkt_len > 1440:
                self.byte_cnt = 0
                return
            len_str = 'LEN: ' + str(self.pkt_len)
            msg = AnalyzerFrame('OSDP', self.pkt_start_time, frame.end_time, {'string': len_str})
        elif self.byte_cnt == 4:
            sqn = ch & 3
            self.pkt_sqn = sqn
            self.pkt_crc = bool(ch & 4)
            self.pkt_scb = bool(ch & 8)
            if self.pkt_crc:
                sum_str = 'CRC'
            else:
                sum_str = 'CHECKSUM'
            if self.pkt_scb:
                scb_str = 'SCB'
            else:
                scb_str = 'noSCB'
            ctrl = 'CTRL (' + 'SQN: ' + str(sqn) + ', ' + sum_str + ', ' + scb_str + ')'
            msg = AnalyzerFrame('OSDP', frame.start_time, frame.end_time, {'string': ctrl})
        else:
            # Header parsed
            if self.pkt_scb:
                msg = AnalyzerFrame('OSDP', frame.start_time, frame.end_time, {'string': str(self.byte_cnt + 1)})
            else:
                if self.byte_cnt == 5:  # cmd/reply byte
                    self.pkt_cmd = self.GetCmdReplyCode(ch, self.pkt_is_reply)
                    self.raw_decoded = ''
                    self.raw_data = None
                    self.kp_digits = ''
                    self.kp_digit_count = 0
                    self.buz_info = ''
                    self.led_info = ''
                    msg = AnalyzerFrame('OSDP', frame.start_time, frame.end_time, {'string': self.pkt_cmd})
                else:
                    if self.pkt_crc and self.byte_cnt == (self.pkt_len - 2):
                        self.pkt_start_time = frame.start_time
                        self.byte_cnt += 1
                        return
                    elif self.pkt_crc and self.byte_cnt == (self.pkt_len - 1):
                        msg = AnalyzerFrame('OSDP', self.pkt_start_time, frame.end_time, {'string': 'CRC'})
                    elif not self.pkt_crc and self.byte_cnt == (self.pkt_len - 1):
                        msg = AnalyzerFrame('OSDP', frame.start_time, frame.end_time, {'string': 'CHECKSUM'})
                    else:
                        # Command/Reply parsing
                        if self.pkt_cmd == 'ID':
                            if ch == 0x00:
                                msg = AnalyzerFrame('OSDP', frame.start_time, frame.end_time, {'string': 'Standard'})
                            else:
                                msg = AnalyzerFrame('OSDP', frame.start_time, frame.end_time, {'string': 'Unknown'})
                        elif self.pkt_cmd == 'CAP':
                            if ch == 0x00:
                                msg = AnalyzerFrame('OSDP', frame.start_time, frame.end_time, {'string': 'Standard'})
                            else:
                                msg = AnalyzerFrame('OSDP', frame.start_time, frame.end_time, {'string': 'Unknown'})
                        elif self.pkt_cmd == 'PDID':
                            if self.byte_cnt == 6:
                                self.pkt_start_time = frame.start_time
                                self.byte_cnt += 1
                                return
                            elif self.byte_cnt == 7:
                                self.byte_cnt += 1
                                return
                            elif self.byte_cnt == 8:
                                msg = AnalyzerFrame('OSDP', self.pkt_start_time, frame.end_time, {'string': 'Vendor Code'})
                            elif self.byte_cnt == 9:
                                msg = AnalyzerFrame('OSDP', frame.start_time, frame.end_time, {'string': 'Model'})
                            elif self.byte_cnt == 10:
                                msg = AnalyzerFrame('OSDP', frame.start_time, frame.end_time, {'string': 'Version'})
                            elif self.byte_cnt == 11:
                                self.tmp = ch
                                self.pkt_start_time = frame.start_time
                                self.byte_cnt += 1
                                return
                            elif self.byte_cnt == 12:
                                self.tmp += (ch << 8)
                                self.byte_cnt += 1
                                return
                            elif self.byte_cnt == 13:
                                self.tmp += (ch << 16)
                                self.byte_cnt += 1
                                return
                            elif self.byte_cnt == 14:
                                self.tmp += (ch << 24)
                                sn = 'SN: ' + str(self.tmp)
                                msg = AnalyzerFrame('OSDP', self.pkt_start_time, frame.end_time, {'string': sn})
                            elif self.byte_cnt == 15:
                                self.tmp = 'FW: v' + str(ch)
                                self.pkt_start_time = frame.start_time
                                self.byte_cnt += 1
                                return
                            elif self.byte_cnt == 16:
                                self.tmp += '.' + str(ch)
                                self.byte_cnt += 1
                                return
                            elif self.byte_cnt == 17:
                                self.tmp += '.' + str(ch)
                                msg = AnalyzerFrame('OSDP', self.pkt_start_time, frame.end_time, {'string': self.tmp})
                        elif self.pkt_cmd == 'PDCAP':
                            if (self.byte_cnt % 3) == 0:
                                self.tmp = self.PDCAPparse(ch)
                                self.pkt_start_time = frame.start_time
                                self.byte_cnt += 1
                                return
                            elif (self.byte_cnt % 3) == 1:
                                self.byte_cnt += 1
                                return
                            elif (self.byte_cnt % 3) == 2:
                                msg = AnalyzerFrame('OSDP', self.pkt_start_time, frame.end_time, {'string': self.tmp})
                        elif self.pkt_cmd == 'LSTATR':
                            if ch == 0x00:
                                msg = AnalyzerFrame('OSDP', frame.start_time, frame.end_time, {'string': 'Normal'})
                            elif ch == 0x01 and self.byte_cnt == 6:
                                msg = AnalyzerFrame('OSDP', frame.start_time, frame.end_time, {'string': 'tamper'})
                            elif ch == 0x01 and self.byte_cnt == 7:
                                msg = AnalyzerFrame('OSDP', frame.start_time, frame.end_time, {'string': 'power'})
                            else:
                                msg = AnalyzerFrame('OSDP', frame.start_time, frame.end_time, {'string': 'Unknown'})
                        elif self.pkt_cmd == 'BUZ':
                            if self.byte_cnt == 6:
                                msg = AnalyzerFrame('OSDP', frame.start_time, frame.end_time, {'string': f'Reader: {ch}'})
                            elif self.byte_cnt == 7:
                                tone_str = _BUZ_TONE_NAMES.get(ch, f'Custom({ch})')
                                msg = AnalyzerFrame('OSDP', frame.start_time, frame.end_time, {'string': f'Tone: {tone_str}'})
                                self.tmp = tone_str
                            elif self.byte_cnt == 8:
                                msg = AnalyzerFrame('OSDP', frame.start_time, frame.end_time, {'string': f'ON: {ch * 100}ms'})
                                self.buz_info = f'Tone={self.tmp} ON={ch * 100}ms'
                            elif self.byte_cnt == 9:
                                msg = AnalyzerFrame('OSDP', frame.start_time, frame.end_time, {'string': f'OFF: {ch * 100}ms'})
                                self.buz_info += f' OFF={ch * 100}ms'
                            elif self.byte_cnt == 10:
                                rep_str = 'forever' if ch == 0 else str(ch)
                                msg = AnalyzerFrame('OSDP', frame.start_time, frame.end_time, {'string': f'Rep: {rep_str}'})
                                self.buz_info += f' Rep={rep_str}'
                        elif self.pkt_cmd == 'RAW':
                            if self.byte_cnt == 6:
                                reader_str = 'Reader: ' + str(ch)
                                msg = AnalyzerFrame('OSDP', frame.start_time, frame.end_time, {'string': reader_str})
                            elif self.byte_cnt == 7:
                                self.raw_format = ch
                                if ch == 0x00:
                                    fmt_str = 'Format: Bit Array'
                                elif ch == 0x01:
                                    fmt_str = 'Format: Wiegand'
                                else:
                                    fmt_str = f'Format: Unknown(0x{ch:02X})'
                                msg = AnalyzerFrame('OSDP', frame.start_time, frame.end_time, {'string': fmt_str})
                            elif self.byte_cnt == 8:
                                self.tmp = ch
                                self.pkt_start_time = frame.start_time
                                self.byte_cnt += 1
                                return
                            elif self.byte_cnt == 9:
                                self.raw_bit_count = self.tmp + (ch << 8)
                                self.raw_data = []
                                bc_str = 'Bit Count: ' + str(self.raw_bit_count)
                                msg = AnalyzerFrame('OSDP', self.pkt_start_time, frame.end_time, {'string': bc_str})
                            else:
                                # Collect wiegand data bytes
                                if self.raw_data is None:
                                    self.raw_data = []
                                self.raw_data.append(ch)
                                expected_bytes = (self.raw_bit_count + 7) // 8
                                if len(self.raw_data) == expected_bytes:
                                    # All data collected - decode the card
                                    self.raw_decoded = self.decode_wiegand(self.raw_data, self.raw_bit_count)
                                    msg = AnalyzerFrame('OSDP', frame.start_time, frame.end_time, {'string': self.raw_decoded})
                                else:
                                    msg = AnalyzerFrame('OSDP', frame.start_time, frame.end_time, {'string': f'0x{ch:02X}'})
                        elif self.pkt_cmd == 'KEYPAD':
                            if self.byte_cnt == 6:
                                msg = AnalyzerFrame('OSDP', frame.start_time, frame.end_time, {'string': f'Reader: {ch}'})
                            elif self.byte_cnt == 7:
                                self.kp_digit_count = ch
                                self.kp_digits = ''
                                msg = AnalyzerFrame('OSDP', frame.start_time, frame.end_time, {'string': f'Digits: {ch}'})
                            else:
                                # Each subsequent byte is an ASCII digit character
                                if 0x20 <= ch <= 0x7E:
                                    key = chr(ch)
                                else:
                                    key = f'0x{ch:02X}'
                                self.kp_digits += key
                                msg = AnalyzerFrame('OSDP', frame.start_time, frame.end_time, {'string': f'Key: {key}'})
                        elif self.pkt_cmd == 'LED':
                            if self.byte_cnt == 6:
                                self.led_info = ''
                                msg = AnalyzerFrame('OSDP', frame.start_time, frame.end_time, {'string': f'Reader: {ch}'})
                            elif self.byte_cnt == 7:
                                self.led_num = ch
                                msg = AnalyzerFrame('OSDP', frame.start_time, frame.end_time, {'string': f'LED: {ch}'})
                            elif self.byte_cnt == 8:
                                self.led_temp_ctrl = _LED_CTRL_TEMP.get(ch, f'0x{ch:02X}')
                                msg = AnalyzerFrame('OSDP', frame.start_time, frame.end_time, {'string': f'Temp ctrl: {self.led_temp_ctrl}'})
                            elif self.byte_cnt == 9:
                                self.led_temp_on = ch
                                msg = AnalyzerFrame('OSDP', frame.start_time, frame.end_time, {'string': f'Temp ON: {ch * 100}ms'})
                            elif self.byte_cnt == 10:
                                self.led_temp_off = ch
                                msg = AnalyzerFrame('OSDP', frame.start_time, frame.end_time, {'string': f'Temp OFF: {ch * 100}ms'})
                            elif self.byte_cnt == 11:
                                self.led_temp_on_col = _LED_COLORS.get(ch, f'0x{ch:02X}')
                                msg = AnalyzerFrame('OSDP', frame.start_time, frame.end_time, {'string': f'Temp ON col: {self.led_temp_on_col}'})
                            elif self.byte_cnt == 12:
                                self.led_temp_off_col = _LED_COLORS.get(ch, f'0x{ch:02X}')
                                msg = AnalyzerFrame('OSDP', frame.start_time, frame.end_time, {'string': f'Temp OFF col: {self.led_temp_off_col}'})
                            elif self.byte_cnt == 13:
                                # Low byte of 16-bit timer_count; span annotation across both bytes
                                self.tmp = ch
                                self.pkt_start_time = frame.start_time
                                self.byte_cnt += 1
                                return
                            elif self.byte_cnt == 14:
                                timer_ms = (self.tmp + (ch << 8)) * 100
                                msg = AnalyzerFrame('OSDP', self.pkt_start_time, frame.end_time, {'string': f'Temp timer: {timer_ms}ms'})
                                # Build temporary summary (omit detail when NOP)
                                if self.led_temp_ctrl == 'NOP':
                                    self.led_info = f'LED{self.led_num} Temp=NOP'
                                else:
                                    self.led_info = (f'LED{self.led_num} Temp={self.led_temp_ctrl}'
                                                     f' T_ON={self.led_temp_on * 100}ms'
                                                     f' T_OFF={self.led_temp_off * 100}ms'
                                                     f' T_ON_col={self.led_temp_on_col}'
                                                     f' T_OFF_col={self.led_temp_off_col}'
                                                     f' T_timer={timer_ms}ms')
                            elif self.byte_cnt == 15:
                                perm_ctrl = _LED_CTRL_PERM.get(ch, f'0x{ch:02X}')
                                self.led_perm_ctrl = perm_ctrl
                                msg = AnalyzerFrame('OSDP', frame.start_time, frame.end_time, {'string': f'Perm ctrl: {perm_ctrl}'})
                            elif self.byte_cnt == 16:
                                self.led_perm_on = ch
                                msg = AnalyzerFrame('OSDP', frame.start_time, frame.end_time, {'string': f'Perm ON: {ch * 100}ms'})
                            elif self.byte_cnt == 17:
                                self.led_perm_off = ch
                                msg = AnalyzerFrame('OSDP', frame.start_time, frame.end_time, {'string': f'Perm OFF: {ch * 100}ms'})
                            elif self.byte_cnt == 18:
                                self.led_perm_on_col = _LED_COLORS.get(ch, f'0x{ch:02X}')
                                msg = AnalyzerFrame('OSDP', frame.start_time, frame.end_time, {'string': f'Perm ON col: {self.led_perm_on_col}'})
                            elif self.byte_cnt == 19:
                                self.led_perm_off_col = _LED_COLORS.get(ch, f'0x{ch:02X}')
                                # Append permanent summary (omit detail when NOP)
                                if self.led_perm_ctrl == 'NOP':
                                    self.led_info += ' Perm=NOP'
                                else:
                                    self.led_info += (f' Perm={self.led_perm_ctrl}'
                                                      f' ON={self.led_perm_on * 100}ms'
                                                      f' OFF={self.led_perm_off * 100}ms'
                                                      f' ON_col={self.led_perm_on_col}'
                                                      f' OFF_col={self.led_perm_off_col}')
                                msg = AnalyzerFrame('OSDP', frame.start_time, frame.end_time, {'string': f'Perm OFF col: {self.led_perm_off_col}'})

        self.byte_cnt += 1

        if self.pkt_len > 0:
            if self.pkt_len == self.byte_cnt:
                # End of packet - print one-line console summary
                card_info = f' | {self.raw_decoded}' if self.raw_decoded else ''
                kp_info   = f' | Keys({self.kp_digit_count}): "{self.kp_digits}"' if self.kp_digits else ''
                buz_info  = f' | {self.buz_info}' if self.buz_info else ''
                led_info  = f' | {self.led_info}'  if self.led_info  else ''
                print(f'[OSDP] {self.pkt_addr_str} {self.pkt_cmd} seq={self.pkt_sqn}{card_info}{kp_info}{buz_info}{led_info}')
                self.pkt_len = 0
                self.byte_cnt = 0
                self.raw_decoded = ''
                self.led_info = ''
                self.buz_info = ''
                self.kp_digits = ''

        return msg


    def GetCmdReplyCode(self, cmd, is_reply):
        # Commands                              # Meaning (Data)
        if cmd == 0x60:  return 'POLL'          # Poll (None)
        if cmd == 0x61:  return 'ID'            # ID Report Request (id type)
        if cmd == 0x62:  return 'CAP'           # PD Capabilities Request (Reply type)
        if cmd == 0x64:  return 'LSTAT'         # Local Status Report Request (None)
        if cmd == 0x65:  return 'ISTAT'         # Input Status Report Request (None)
        if cmd == 0x66:  return 'OSTAT'         # Output Status Report Request (None)
        if cmd == 0x67:  return 'RSTAT'         # Reader Status Report Request (None)
        if cmd == 0x68:  return 'OUT'           # Output Control Command (Output settings)
        if cmd == 0x69:  return 'LED'           # Reader Led Control Command (LED settings)
        if cmd == 0x6A:  return 'BUZ'           # Reader Buzzer Control Command (Buzzer settings)
        if cmd == 0x6B:  return 'TEXT'          # Text Output Command (Text settings)
        if cmd == 0x6E:  return 'COMSET'        # PD Communication Configuration Command (Com settings)
        if cmd == 0x73:  return 'BIOREAD'       # Scan and Send Biometric Data (Requested Return Format)
        if cmd == 0x74:  return 'BIOMATCH'      # Scan and Match Biometric Template (Biometric Template)
        if cmd == 0x75:  return 'KEYSET'        # Encryption Key Set Command (Encryption Key)
        if cmd == 0x76 and not is_reply:  return 'CHLNG'    # Challenge and Secure Session Initialization Rq. (Challenge Data)
        if cmd == 0x77:  return 'SCRYPT'        # Server Cryptogram (Encryption Data)
        if cmd == 0x7B:  return 'ACURXSIZE'     # Max ACU receive size (Buffer size)
        if cmd == 0x7C:  return 'FILETRANSFER'  # Send data file to PD (File contents)
        if cmd == 0x80 and not is_reply:  return 'MFG'      # Manufacturer Specific Command (Any)
        if cmd == 0xA1:  return 'XWR'           # Extended write data (APDU and details)
        if cmd == 0xA2:  return 'ABORT'         # Abort PD operation (None)
        if cmd == 0xA3:  return 'PIVDATA'       # Get PIV Data (Object details)
        if cmd == 0xA4:  return 'GENAUTH'       # Request Authenticate (Request details)
        if cmd == 0xA5:  return 'CRAUTH'        # Request Crypto Response (Challenge details)
        if cmd == 0xA7:  return 'KEEPACTIVE'    # PD read activation (Time duration)

        # Replies                               # Meaning (Data)
        if cmd == 0x40:  return 'ACK'           # Command accepted, nothing else to report (None)
        if cmd == 0x41:  return 'NAK'           # Command not processed (Reason for rejecting command)
        if cmd == 0x45:  return 'PDID'          # PD ID Report (Report data)
        if cmd == 0x46:  return 'PDCAP'         # PD Capabilities Report (Report data)
        if cmd == 0x48:  return 'LSTATR'        # Local Status Report (Report data)
        if cmd == 0x49:  return 'ISTATR'        # Input Status Report (Report data)
        if cmd == 0x4A:  return 'OSTATR'        # Output Status Report (Report data)
        if cmd == 0x4B:  return 'RSTATR'        # Reader Status Report (Report data)
        if cmd == 0x50:  return 'RAW'           # Reader Data - Raw bit image of card data (Card data)
        if cmd == 0x51:  return 'FMT'           # Reader Data - Formatted character stream (Card data)
        if cmd == 0x53:  return 'KEYPAD'        # Keypad Data (Keypad data)
        if cmd == 0x54:  return 'COM'           # PD Communications Configuration Report (Comm data)
        if cmd == 0x57:  return 'BIOREADR'      # Biometric Data (Biometric data)
        if cmd == 0x58:  return 'BIOMATCHR'     # Biometric Match Result (Result)
        if cmd == 0x76 and is_reply:  return 'CCRYPT'       # Client's ID, Random Number, and Cryptogram (Encryption Data)
        if cmd == 0x78:  return 'RMAC_I'        # Initial R-MAC (Encryption Data)
        if cmd == 0x79:  return 'BUSY'          # PD is Busy reply
        if cmd == 0x7A:  return 'FTSTAT'        # File transfer status (Status details)
        if cmd == 0x80 and is_reply:  return 'PIVDATAR'     # PIV Data Reply (credential data)
        if cmd == 0x81:  return 'GENAUTHR'      # Authentication response (response details)
        if cmd == 0x82:  return 'CRAUTHR'       # Response to challenge (response details)
        if cmd == 0x83:  return 'MFGSTATR'      # MFG specific status (status details)
        if cmd == 0x84:  return 'MFGERRR'       # MFG specific error (error details)
        if cmd == 0x90:  return 'MFGREP'        # Manufacturer Specific Reply (Any)
        if cmd == 0xB1:  return 'XRD'           # Extended Read Response (APDU and details)
        return 'Unknown'


    def PDCAPparse(self, fn_code):
        if fn_code == 1:  return 'Contact Status Monitoring'
        if fn_code == 2:  return 'Output Control'
        if fn_code == 3:  return 'Card Data Format'
        if fn_code == 4:  return 'Reader LED Control'
        if fn_code == 5:  return 'Reader Audible Output'
        if fn_code == 6:  return 'Reader Text Output'
        if fn_code == 7:  return 'Time Keeping'
        if fn_code == 8:  return 'Check Character Support'
        if fn_code == 9:  return 'Communication Security'
        if fn_code == 10: return 'Receive BufferSize'
        if fn_code == 11: return 'Largest Combined Message Size'
        if fn_code == 12: return 'Smart Card Support'
        if fn_code == 13: return 'Readers'
        if fn_code == 14: return 'Biometrics'
        if fn_code == 15: return 'Secure PIN Entry support'
        if fn_code == 16: return 'OSDP Version'
        return 'Unknown'
