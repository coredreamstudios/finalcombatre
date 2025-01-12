import struct
import sys
from pathlib import Path
from collections import Counter, defaultdict
import os

def read_lua_header(data):
    """Analyze Lua 5.1 bytecode header"""
    header = {
        'signature': data[0:4],
        'version': data[4],
        'format': data[5],
        'endianness': data[6],
        'int_size': data[7],
        'size_t': data[8],
        'instruction_size': data[9],
        'number_size': data[10],
        'integral_flag': data[11]
    }
    return header

def analyze_byte_relationships(data, block_size=4):
    """Analyze relationships between bytes within blocks"""
    relationships = defaultdict(Counter)
    
    # Skip header
    for i in range(12, len(data) - block_size, block_size):
        block = data[i:i+block_size]
        
        # Look for relationships between adjacent bytes
        for j in range(block_size-1):
            byte_pair = (block[j], block[j+1])
            relationships[j].update([byte_pair])
            
        # Look for relationships with position
        pos_in_file = i // block_size
        relationships['position'].update([(pos_in_file % 16, block[0])])
    
    return relationships

def find_substitution_patterns(data, block_size=4):
    """Look for potential substitution patterns in the data"""
    substitutions = defaultdict(Counter)
    
    # Skip header
    for i in range(12, len(data) - block_size, block_size):
        block = data[i:i+block_size]
        next_block = data[i+block_size:i+block_size*2] if i+block_size < len(data) else None
        
        if next_block and len(next_block) == block_size:
            # Look for byte substitution patterns
            for j in range(block_size):
                if block[j] == next_block[j]:
                    continue
                substitutions[j].update([(block[j], next_block[j])])
    
    return substitutions

def analyze_instruction_patterns(data, block_size=4):
    """Analyze patterns that might represent Lua instructions"""
    instructions = defaultdict(Counter)
    valid_opcodes = {
        0x00: "MOVE",
        0x01: "LOADK",
        0x02: "LOADBOOL",
        0x03: "LOADNIL",
        0x04: "GETUPVAL",
        0x05: "GETGLOBAL",
        0x06: "GETTABLE",
        0x07: "SETGLOBAL",
        0x08: "SETUPVAL",
        0x09: "SETTABLE",
        0x0A: "NEWTABLE",
        0x0B: "SELF",
        0x0C: "ADD",
        0x0D: "SUB",
        0x0E: "MUL",
        0x0F: "DIV",
        0x10: "MOD",
        0x11: "POW",
        0x12: "UNM",
        0x13: "NOT",
        0x14: "LEN",
        0x15: "CONCAT",
        0x16: "JMP",
        0x17: "EQ",
        0x18: "LT",
        0x19: "LE",
        0x1A: "TEST",
        0x1B: "TESTSET",
        0x1C: "CALL",
        0x1D: "TAILCALL",
        0x1E: "RETURN",
        0x1F: "FORLOOP",
        0x20: "FORPREP",
        0x21: "TFORLOOP",
        0x22: "SETLIST",
        0x23: "CLOSE",
        0x24: "CLOSURE",
        0x25: "VARARG"
    }
    
    # Skip header
    for i in range(12, len(data) - block_size, block_size):
        block = data[i:i+block_size]
        
        # Extract instruction fields
        opcode = block[0] & 0x3F  # 6 bits
        a = (block[0] >> 6) | ((block[1] & 0x1) << 2)  # 8 bits
        b = block[2]  # 9 bits
        c = block[3]  # 9 bits
        
        # Track valid vs invalid opcodes
        if opcode in valid_opcodes:
            instructions['valid_opcodes'].update([opcode])
            instructions[f'fields_{opcode}'].update([(a, b, c)])
        else:
            instructions['invalid_opcodes'].update([opcode])
        
        # Look for instruction sequences
        if i > 12:
            prev_block = data[i-block_size:i]
            prev_op = prev_block[0] & 0x3F
            if prev_op in valid_opcodes and opcode in valid_opcodes:
                instructions['valid_sequences'].update([(prev_op, opcode)])
    
    return instructions, valid_opcodes

def try_fix_invalid_opcode(block, opcode, instructions):
    """Try to fix invalid opcodes based on context"""
    # Common transformations observed in the packer
    opcode_map = {
        0x34: 0x24,  # Likely CLOSURE
        0x2e: 0x1e,  # Likely RETURN
        0x29: 0x09,  # Likely SETTABLE
        0x2c: 0x1c,  # Likely CALL
        0x2f: 0x0f   # Likely DIV
    }
    
    if opcode in opcode_map:
        fixed_opcode = opcode_map[opcode]
        # Check if this would create a valid sequence
        prev_op = block[0] & 0x3F
        if prev_op in instructions[1] and fixed_opcode in instructions[1]:  
            return fixed_opcode
    
    return opcode

def try_transform_block(block, pos, relationships, substitutions, instructions):
    """Apply discovered transformations to a block"""
    result = bytearray(block)
    
    # Extract potential instruction fields
    opcode = result[0] & 0x3F
    a = (result[0] >> 6) | ((result[1] & 0x1) << 2)
    b = result[2]
    c = result[3]
    
    # Try to fix invalid opcodes
    if opcode not in instructions[1]:  # valid_opcodes
        fixed_opcode = try_fix_invalid_opcode(block, opcode, instructions)
        if fixed_opcode != opcode:
            result[0] = (result[0] & 0xC0) | fixed_opcode
    
    # Check if this looks like a valid instruction
    if opcode in instructions[1]:  # valid_opcodes
        # Look for common field patterns for this opcode
        common_fields = instructions[0][f'fields_{opcode}'].most_common(1)
        if common_fields:
            common_a, common_b, common_c = common_fields[0][0]
            # If fields are similar but not identical, adjust them
            if abs(a - common_a) <= 2:
                new_a = common_a
                result[0] = (result[0] & 0x3F) | ((new_a & 0x3) << 6)
                result[1] = (result[1] & 0xFE) | ((new_a >> 2) & 0x1)
    
    # Apply position-based transformation
    pos_patterns = relationships['position']
    block_pos = pos % 16
    if block_pos in dict(pos_patterns.most_common(1)):
        expected_byte = dict(pos_patterns.most_common(1))[block_pos]
        if result[0] != expected_byte:
            # Only adjust if it wouldn't break a valid instruction
            if (result[0] & 0x3F) not in instructions[1]:
                diff = (expected_byte - result[0]) & 0xFF
                for i in range(len(result)):
                    result[i] = (result[i] + diff) & 0xFF
    
    return bytes(result)

def analyze_instruction_fields(data, block_size=4):
    """Analyze patterns in Lua instruction fields"""
    field_patterns = defaultdict(lambda: defaultdict(Counter))
    sequence_patterns = defaultdict(Counter)
    
    # Skip header
    for i in range(12, len(data) - block_size, block_size):
        block = data[i:i+block_size]
        
        # Extract instruction fields
        opcode = block[0] & 0x3F  # 6 bits
        a = (block[0] >> 6) | ((block[1] & 0x1) << 2)  # 8 bits
        b = block[2]  # 9 bits
        c = block[3]  # 9 bits
        
        # Track field patterns for each opcode
        field_patterns[opcode]['a'].update([a])
        field_patterns[opcode]['b'].update([b])
        field_patterns[opcode]['c'].update([c])
        
        # Look for field relationships
        if i > 12:
            prev_block = data[i-block_size:i]
            prev_opcode = prev_block[0] & 0x3F
            prev_a = (prev_block[0] >> 6) | ((prev_block[1] & 0x1) << 2)
            prev_b = prev_block[2]
            prev_c = prev_block[3]
            
            # Track field transitions
            sequence_patterns['a'].update([(prev_a, a)])
            sequence_patterns['b'].update([(prev_b, b)])
            sequence_patterns['c'].update([(prev_c, c)])
    
    return field_patterns, sequence_patterns

def analyze_field_transformations(field_patterns, sequence_patterns):
    """Analyze potential transformations applied to instruction fields"""
    transformations = {}
    
    # Analyze A field patterns (register allocation)
    a_patterns = defaultdict(list)
    for opcode, fields in field_patterns.items():
        a_values = fields['a'].most_common()
        if len(a_values) > 1:
            # Look for register allocation patterns
            diffs = [a_values[i][0] - a_values[i-1][0] for i in range(1, len(a_values))]
            if diffs and all(d == diffs[0] for d in diffs):
                a_patterns[diffs[0]].append(opcode)
    
    # Analyze B and C field patterns (constant pool indices)
    b_patterns = defaultdict(Counter)
    c_patterns = defaultdict(Counter)
    for opcode, fields in field_patterns.items():
        for b_val, _ in fields['b'].most_common():
            if b_val > 0:
                b_patterns[opcode].update([b_val & 0xFF])
        for c_val, _ in fields['c'].most_common():
            if c_val > 0:
                c_patterns[opcode].update([c_val & 0xFF])
    
    # Look for field transitions that might indicate encryption
    field_transitions = {
        'a': analyze_field_transitions(sequence_patterns['a']),
        'b': analyze_field_transitions(sequence_patterns['b']),
        'c': analyze_field_transitions(sequence_patterns['c'])
    }
    
    return {
        'a_patterns': dict(a_patterns),
        'b_patterns': dict(b_patterns),
        'c_patterns': dict(c_patterns),
        'transitions': field_transitions
    }

def analyze_field_transitions(transitions):
    """Analyze patterns in field value transitions"""
    patterns = []
    
    # Look for common differences
    diffs = Counter()
    for (prev, curr), count in transitions.most_common():
        if count > 5:  # Only consider frequent transitions
            diff = (curr - prev) & 0xFF
            diffs.update([diff])
    
    # Look for XOR patterns
    xor_patterns = Counter()
    for (prev, curr), count in transitions.most_common():
        if count > 5:
            xor = prev ^ curr
            xor_patterns.update([xor])
    
    return {
        'common_diffs': dict(diffs.most_common(5)),
        'xor_patterns': dict(xor_patterns.most_common(5))
    }

def try_fix_instruction_fields(block, opcode, field_analysis):
    """Try to fix instruction fields based on analysis"""
    result = bytearray(block)
    
    # Extract fields
    a = (result[0] >> 6) | ((result[1] & 0x1) << 2)
    b = result[2]
    c = result[3]
    
    # Fix B field for known patterns
    if opcode in field_analysis['b_patterns']:
        common_b = field_analysis['b_patterns'][opcode].most_common(1)
        if common_b:
            expected_b = common_b[0][0]
            # Check if current B field needs fixing
            if b != expected_b:
                # Try common transformations
                if b ^ 0x65 == expected_b:  # XOR with 0x65
                    result[2] = expected_b
                elif (b + 0x20) & 0xFF == expected_b:  # +0x20 transformation
                    result[2] = expected_b
    
    # Fix A field based on register patterns
    if a > 250:  # Invalid register number
        for diff, opcodes in field_analysis['a_patterns'].items():
            if opcode in opcodes:
                # Try to fix based on common register increment
                new_a = (a + diff) & 0xFF
                if new_a < 250:
                    result[0] = (result[0] & 0x3F) | ((new_a & 0x3) << 6)
                    result[1] = (result[1] & 0xFE) | ((new_a >> 2) & 0x1)
                break
    
    # Fix C field based on transitions
    transitions = field_analysis['transitions']['c']
    if transitions['xor_patterns']:
        most_common_xor = max(transitions['xor_patterns'].items(), key=lambda x: x[1])[0]
        # Try XOR pattern if it would produce a valid value
        new_c = c ^ most_common_xor
        if 0 <= new_c <= 255:
            result[3] = new_c
    
    return bytes(result)

def find_string_patterns(data):
    """Find potential string patterns in the data"""
    print("\nSearching for string patterns...")
    
    # Common string patterns in Lua code
    common_strings = {
        b'nil': 'nil value',
        b'true': 'boolean true',
        b'false': 'boolean false',
        b'local': 'local keyword',
        b'function': 'function keyword',
        b'end': 'end keyword',
        b'return': 'return keyword',
        b'if': 'if keyword',
        b'then': 'then keyword',
        b'else': 'else keyword',
        b'for': 'for keyword',
        b'do': 'do keyword',
        b'while': 'while keyword',
        b'break': 'break keyword',
        b'table': 'table namespace',
        b'string': 'string namespace',
        b'math': 'math namespace',
        b'io': 'io namespace',
        b'os': 'os namespace',
        b'require': 'require function',
        b'module': 'module function',
        b'setmetatable': 'setmetatable function',
        b'getmetatable': 'getmetatable function',
        b'pairs': 'pairs function',
        b'ipairs': 'ipairs function',
        b'next': 'next function',
        b'type': 'type function',
        b'error': 'error function',
        b'assert': 'assert function',
        b'print': 'print function',
        b'tostring': 'tostring function',
        b'tonumber': 'tonumber function',
    }
    
    # Track found patterns
    found = []
    
    # Look for common strings with different XOR keys
    for pattern, desc in common_strings.items():
        # Try different XOR keys
        for key in [0x20, 0x45, 0x65]:
            xored = bytes(b ^ key for b in pattern)
            
            # Search for XORed pattern
            pos = 0
            while True:
                pos = data.find(xored, pos)
                if pos == -1:
                    break
                    
                found.append((pos, key, pattern.decode('ascii'), desc))
                pos += 1
    
    # Sort by position
    found.sort()
    
    # Print results
    if found:
        print("\nFound string patterns:")
        for pos, key, text, desc in found:
            print(f"  {pos:04x}: XOR 0x{key:02x} = '{text}' ({desc})")
    
    return found

def analyze_file_chunks(data, chunk_size=16):
    """Analyze file in chunks to identify patterns"""
    print("\nAnalyzing file in chunks:")
    
    # Track chunk patterns
    patterns = []
    
    # Common patterns to look for
    common_patterns = {
        b'\x1b\x4c\x75\x61': 'Lua signature',
        b'\x00\x00\x00\x00': 'Zero padding',
        b'\xff\xff\xff\xff': 'All ones',
        b'\x45\x45\x45\x45': 'XOR key 0x45',
        b'\x65\x65\x65\x65': 'XOR key 0x65',
        b'\x20\x20\x20\x20': 'XOR key 0x20',
    }
    
    # Process file in chunks
    for i in range(0, len(data), chunk_size):
        chunk = data[i:i+chunk_size]
        
        # Skip if chunk is all zeros
        if all(b == 0 for b in chunk):
            continue
        
        # Look for common patterns
        for pattern, desc in common_patterns.items():
            if pattern in chunk:
                patterns.append((i, desc))
        
        # Check for repeating bytes
        if len(chunk) >= 4:
            for j in range(len(chunk)-3):
                if chunk[j] == chunk[j+1] == chunk[j+2] == chunk[j+3]:
                    patterns.append((i+j, f"Repeating byte 0x{chunk[j]:02x}"))
        
        # Check for printable ASCII sequences
        ascii_seq = []
        for j, b in enumerate(chunk):
            if 32 <= b <= 126:
                ascii_seq.append(b)
            elif ascii_seq:
                if len(ascii_seq) >= 4:
                    text = bytes(ascii_seq).decode('ascii')
                    patterns.append((i+j-len(ascii_seq), f"ASCII text: {text}"))
                ascii_seq = []
    
    # Print patterns
    if patterns:
        print("\nFound patterns:")
        for offset, desc in sorted(patterns):
            print(f"  {offset:04x}: {desc}")
    
    return patterns

def find_xor_key(data):
    """Find potential XOR key by looking at ASCII text"""
    print("\nSearching for XOR key...")
    
    # Common Lua keywords that might appear in the file
    keywords = [
        b'local', b'function', b'end', b'return',
        b'if', b'then', b'else', b'for', b'do',
        b'while', b'break', b'true', b'false', b'nil',
    ]
    
    # Track key frequencies
    key_counts = {}
    
    # Try each byte position
    for i in range(len(data)-8):
        # Get 8 bytes
        chunk = data[i:i+8]
        
        # Try each possible key
        for key in range(256):
            # XOR chunk with key
            decoded = bytes(b ^ key for b in chunk)
            
            # Check if result looks like ASCII text
            if all(32 <= b <= 126 for b in decoded):
                # Check if any keywords match when XORed with this key
                for keyword in keywords:
                    for j in range(len(data)-len(keyword)):
                        test = bytes(b ^ key for b in data[j:j+len(keyword)])
                        if test == keyword:
                            key_counts[key] = key_counts.get(key, 0) + 1
    
    # Sort keys by frequency
    if key_counts:
        print("\nPotential XOR keys:")
        for key, count in sorted(key_counts.items(), key=lambda x: x[1], reverse=True)[:5]:
            print(f"  0x{key:02x}: {count} matches")
            
            # Try decoding some text with this key
            print("  Sample decoded text:")
            for i in range(0, min(len(data), 1000), 100):
                decoded = bytes(b ^ key for b in data[i:i+100])
                text = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in decoded)
                print(f"    {i:04x}: {text}")
        
        # Return most frequent key
        return max(key_counts.items(), key=lambda x: x[1])[0]
    
    return None

def analyze_chunk_structure(data):
    """Analyze the structure of a Lua chunk"""
    print("\nDetailed chunk analysis:")
    
    # Header
    print("\nHeader:")
    print(f"  Signature: {data[0:4].hex()}")
    print(f"  Version: {chr(data[4])}")
    print(f"  Format: {data[5]}")
    print(f"  Endianness: {data[6]}")
    print(f"  Int size: {data[7]}")
    print(f"  Size_t: {data[8]}")
    print(f"  Instruction size: {data[9]}")
    print(f"  Number size: {data[10]}")
    print(f"  Integral flag: {data[11]}")
    
    # Size field
    size = int.from_bytes(data[12:16], 'little')
    print(f"\nSize field: {size} bytes")
    
    # Source path
    path_start = 16
    path_end = data.find(b'\x00\x00\x00\x00\x00\x00', path_start)
    if path_end == -1:
        path_end = path_start + 64
    path_bytes = data[path_start:path_end]
    print(f"\nSource path ({len(path_bytes)} bytes):")
    print(f"  Raw: {path_bytes.hex()}")
    
    # Find XOR key
    xor_key = find_xor_key(data)
    
    if xor_key is not None:
        print(f"\nFound XOR key: 0x{xor_key:02x}")
        
        # Try to decode path with key
        try:
            decoded = bytes(b ^ xor_key for b in path_bytes)
            if all(32 <= b <= 126 or b == 0 for b in decoded):
                print(f"  Decoded path: {decoded.decode('ascii', errors='ignore')}")
        except:
            pass
        
        return path_end, xor_key
    
    return path_end, None

def decrypt_with_xor(data, key):
    """Decrypt data using XOR key"""
    return bytes(b ^ key for b in data)

def rebuild_lua_chunk(data):
    """Rebuild Lua chunk preserving original structure"""
    # Analyze the chunk first
    path_end, xor_key = analyze_chunk_structure(data)
    
    if not xor_key:
        print("No valid XOR key found")
        return None
        
    print(f"\nDecrypting with XOR key 0x{xor_key:02x}...")
    
    # Keep original header
    chunk = bytearray(data[:13])
    
    # Decrypt rest of file
    decrypted = decrypt_with_xor(data[13:], xor_key)
    chunk.extend(decrypted)
    
    return bytes(chunk)

def decrypt_with_transformations(data, block_size=4):
    """Decrypt data using discovered transformations"""
    print("Building Lua chunk preserving original structure...")
    decrypted = rebuild_lua_chunk(data)
    
    if decrypted:
        # Write decrypted data
        output_path = os.path.join(os.path.dirname(input_file), "onload.decrypted.lua")
        with open(output_path, "wb") as f:
            f.write(decrypted)
        print(f"\nSaved decrypted version to: {os.path.relpath(output_path)}")
        
        # Write transformed version
        transformed_path = os.path.join(os.path.dirname(input_file), "onload.transformed.lua") 
        with open(transformed_path, "wb") as f:
            f.write(decrypted)
        print(f"\nSaved transformed version to: {os.path.relpath(transformed_path)}")
        
        # Print first 32 bytes after header
        print("\nFirst 32 bytes after header:")
        print(' '.join(f"{b:02x}" for b in decrypted[13:45]))
    
    return decrypted

def fix_lua_header(header):
    """Fix Lua header if needed"""
    # Lua 5.1 header: 1b4c7561 51000104 04040800
    fixed = bytearray([
        0x1b, 0x4c, 0x75, 0x61,  # \x1bLua
        0x51,                     # Version 5.1
        0x00,                     # Format version (official)
        0x01,                     # Little endian
        0x04,                     # int size
        0x04,                     # size_t
        0x04,                     # instruction size
        0x08,                     # lua_Number size
        0x00                      # Integral flag
    ])
    
    return bytes(fixed)

def print_field_analysis(field_analysis):
    """Print field analysis in a more organized way"""
    print("\nRegister allocation patterns:")
    for diff, opcodes in field_analysis['a_patterns'].items():
        print(f"  Register increment {diff}: {len(opcodes)} opcodes")
    
    print("\nConstant pool patterns:")
    total_constants = sum(len(patterns) for patterns in field_analysis['b_patterns'].values())
    print(f"  Total unique constants: {total_constants}")
    print("  Common constant values:", end=" ")
    all_values = []
    for patterns in field_analysis['b_patterns'].values():
        all_values.extend(patterns.elements())
    value_counts = Counter(all_values)
    print(", ".join(f"0x{val:02x}({count})" for val, count in value_counts.most_common(5)))
    
    print("\nField transitions:")
    for field, trans in field_analysis['transitions'].items():
        print(f"\n  {field.upper()}-field patterns:")
        print("    Common differences:", 
              ", ".join(f"0x{k:02x}({v})" for k,v in trans['common_diffs'].items()))
        print("    XOR patterns:", 
              ", ".join(f"0x{k:02x}({v})" for k,v in trans['xor_patterns'].items()))

def analyze_and_decrypt(filepath):
    global input_file
    input_file = filepath
    with open(filepath, 'rb') as f:
        data = f.read()
    
    print(f"File size: {len(data)} bytes")
    
    if data[0:4] != b'\x1bLua':
        print("Not a valid Lua bytecode file!")
        return
    
    header = read_lua_header(data)
    print("\nOriginal Header Analysis:")
    print(f"Signature: {header['signature'].hex()}")
    print(f"Version: {chr(header['version'])}")
    print(f"Format: {header['format']}")
    print(f"Endianness: {header['endianness']}")
    print(f"Int size: {header['int_size']}")
    print(f"Size_t: {header['size_t']}")
    print(f"Instruction size: {header['instruction_size']}")
    print(f"Number size: {header['number_size']}")
    print(f"Integral flag: {header['integral_flag']}")
    
    # Analyze and apply transformations
    decrypted = decrypt_with_transformations(data)
    
    # Save result
    output_path = filepath.parent / (filepath.stem + ".transformed.lua")
    with open(output_path, 'wb') as f:
        f.write(decrypted)
    print(f"\nSaved transformed version to: {output_path}")
    print("\nFirst 32 bytes after header:")
    print(' '.join(f'{b:02x}' for b in decrypted[12:44]))
    
    return decrypted

if __name__ == "__main__":
    lua_file = Path("Client/MainResDCF/onload.lua")
    if not lua_file.exists():
        print(f"File not found: {lua_file}")
        sys.exit(1)
    
    print(f"Analyzing transformations in {lua_file}...")
    decrypted = analyze_and_decrypt(lua_file)
