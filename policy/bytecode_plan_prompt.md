# FTFuzz Bytecode Plan — LLM Prompt (Format-Agnostic)**CRITICAL:** You MUST output `"schema_version": "ftfuzz.bytecode_plan.v1"`. This is the PREFERRED format. Only use `ftfuzz.relation_plan.v1` as a last resort for complex cross-region constraints.---You are a fuzzing mutation engineer. Your task is to produce a sequence of **format-agnostic byte-level operations** that transform an input seed to cross a program barrier.## Core PrincipleYou operate on a **raw byte buffer**. You do NOT think in terms of "declarations", "attributes", "elements", or "schema". You think in terms of: **"what bytes at what offset need to change?"**.Your training data contains knowledge of file formats (ELF, SQL, XML, JSON, PNG, JPEG, etc.). Use that knowledge to identify which byte offsets and patterns control the barrier condition.## Available Operations (8 opcodes)### FIND — Locate a byte pattern
```
{"op": "FIND", "params": {"pattern": "hex_bytes", "output": "ref_name", "start": "offset_or_ref", "occurrence": 1}}
```
- Searches the buffer for the exact hex byte sequence
- `output`: a name for the matched offset, referenced later as `{ref_name}`
- `start`: (optional) where to begin searching — absolute offset, `{ref}`, or `{ref}+N`
- `occurrence`: (optional) which match to use, default 1 (first)
- **If not found: the step and all steps referencing this output are silently skipped.**### WRITE — Overwrite bytes at offset
```
{"op": "WRITE", "params": {"offset": "offset_or_ref", "data": "hex_bytes"}}
```
- Overwrites bytes without changing buffer size or shifting anything### INSERT — Insert bytes, shifting everything right
```
{"op": "INSERT", "params": {"offset": "offset_or_ref", "data": "hex_bytes"}}
```
- Inserts bytes at offset, moves everything to the right### DELETE — Remove a byte range
```
{"op": "DELETE", "params": {"offset": "offset_or_ref", "length": N}}
```
- Deletes N bytes starting at offset, shifts everything left### SET_INT — Write integer at offset
```
{"op": "SET_INT", "params": {"offset": "offset_or_ref", "width": W, "endian": "le_or_be", "value": V}}
```
- Writes an integer of width bytes (1/2/4/8) in little-endian or big-endian
- Example: write 2-byte LE value 64 at offset 16 → `{"op": "SET_INT", "params": {"offset": 16, "width": 2, "endian": "le", "value": 64}}`### INC_INT — Arithmetic on integer at offset
```
{"op": "INC_INT", "params": {"offset": "offset_or_ref", "width": W, "endian": "le_or_be", "delta": D}}
```
- Reads integer, adds delta (can be negative), writes back
- Use for adjusting counter fields or section counts after insert/delete### SIZE_TO — Set integer to byte-length of a range
```
{"op": "SIZE_TO", "params": {"field_offset": "offset_or_ref", "width": W, "endian": "le_or_be", "range_start": "{ref}", "range_end": "END_or_ref"}}
```
- Computes the byte distance between two named offsets and writes it as an integer
- `range_end` can be `"END"` (end of buffer) or a `{ref}`
- **This is the most important primitive for binary formats.** Use it to fix length/size/chunk-size fields after insertions or deletions.### PRESERVE — Protect range from havoc mutation
```
{"op": "PRESERVE", "params": {"offset": "offset_or_ref", "length": N}}
```
- Marks a range as protected from random havoc during AFL++ mutation## Offset Reference Syntax| Syntax | Meaning |
|--------|---------|
| `0`, `4`, `64` | Absolute byte offset from buffer start |
| `{elf_hdr}` | Offset where FIND with output="elf_hdr" matched |
| `{elf_hdr}+16` | 16 bytes after the FIND match |
| `{elf_hdr}-4` | 4 bytes before the FIND match |
| `END` | End of buffer (only valid for SIZE_TO range_end) |## Format Reference — Common Patterns### ELF executables
- Magic: 7f454c46 at offset 0
- EI_CLASS (32/64): offset 4 (1=32bit, 2=64bit)
- EI_DATA (endian): offset 5 (1=LE, 2=BE)
- e_type: offset 16 LE uint16 (1=reloc, 2=exec, 3=shared)
- e_machine: offset 18 LE uint16
- e_shoff (section header offset): offset 40 LE uint64 (64-bit) or offset 32 LE uint32 (32-bit)
- e_shnum (section count): offset 60 LE uint16 (64-bit) or offset 48 LE uint16 (32-bit)### SQLite
- Header magic: 53514c69746520666f726d6174203300 ("SQLite format 3\0")
- Keywords as ASCII hex: 435245415445205441424c45 = "CREATE TABLE", 494e53455254 = "INSERT"
- SQL text is ASCII — search for SQL keywords as hex### XML
- Tags as ASCII hex: 3c = "<", 3e = ">", 2f = "/"
- <root = 3c726f6f74, </root> = 3c2f726f6f743e
- Attributes: 20786d6c3a69643d22 = ' xml:id="'### PNG
- Magic: 89504e470d0a1a0a
- IHDR chunk: 49484452
- Chunk length: 4-byte BE uint32 before each chunk type
- CRC: 4-byte BE uint32 after each chunk data### JPEG
- SOI marker: ffd8
- APP0/JFIF: ffe0
- DQT: ffdb, SOF0: ffc0, SOS: ffda, EOI: ffd9
- Segment length: 2-byte BE uint16 after marker## Critical Rules1. **Use hex bytes, NOT ASCII text** — `"data": "4946204e4f5420455849535453"` not `"IF NOT EXISTS"`
2. **Use hex bytes, NOT placeholder descriptions** — `"data": "02"` not `"data": "64-bit value"`
3. **DO NOT invent format-specific opcodes** — only the 8 above
4. **Always include PRESERVE for critical headers** — protect magic bytes, format markers
5. **Use SIZE_TO after INSERT/DELETE** — if you change payload size, update the corresponding length field
6. **If you cannot identify specific byte offsets, uscaffold_template/scaffold_script as fallback**
7. **DO NOT output `ensure_declaration_side`, `insert_matching_instance_field`, or any XML-semantic effects** — those are the OLD format## Output Format```json
{
  "schema_version": "ftfuzz.bytecode_plan.v1",
  "transition_id": "{transition_id}",
  "desired_outcome": true,
  "mechanism": {
    "summary": "Brief description of what byte-level changes achieve the state_goal"
  },
  "steps": [
    {"op": "FIND",    "params": {"pattern": "hex", "output": "ref1"}},
    {"op": "WRITE",   "params": {"offset": "{ref1}+4", "data": "hex"}},
    {"op": "SET_INT", "params": {"offset": 16, "width": 2, "endian": "le", "value": 3}},
    {"op": "SIZE_TO", "params": {"field_offset": "{hdr}+4", "width": 4, "endian": "le", "range_start": "{payload_start}", "range_end": "END"}},
    {"op": "PRESERVE", "params": {"offset": 0, "length": 64}}
  ],
  "scaffold_template": "hex_bytes — complete valid input for scaffold fallback (optional)",
  "scaffold_script": "Python3 script to generate scaffold bytes (optional, use for complex formats)",
  "focus_ranges": [
    {"start": N, "end": M, "role": "description", "confidence": 0.X}
  ],
  "preserve_ranges": [
    {"start": N, "end": M, "role": "description", "confidence": 0.X}
  ],
  "target_alignment": {
    "target_function": "string",
    "overrepair_risks": ["risks where mutations bypass the target"],
    "avoid_actions": ["mutation patterns to avoid"]
  }
}
```## Global Target Context{target_context}## Transition Data```
Active Transition: {transition_id}
Desired Outcome: {desired_outcome}
Function: {active_function}:{active_source}
Barrier Condition: {barrier_condition}
PreState Summary: {pre_state_summary}
PostState Summary: {post_state_summary}
State Goal Hint: {state_goal_hint}Upstream PostState Context (k={upstream_hops}):
{upstream_context}Prior Failed Actions:
{failed_actions}
```## Barrier Source CodeThe code below shows the actual barrier condition and surrounding context. Read it carefully to understand what comparison is being made and what input bytes affect it.{barrier_summary}## Seed Data (Example Inputs){seed_data}Produce the bytecode plan JSON.

{input_format_guidance}
