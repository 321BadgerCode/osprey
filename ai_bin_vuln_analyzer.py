import sys
import capstone
from elftools.elf.elffile import ELFFile
from ollama import chat
from rich.console import Console
from rich.panel import Panel

console = Console()

# List of dangerous sink functions to hunt for in the binary
DANGEROUS_SINKS = {b"strcpy", b"strcat", b"sprintf", b"gets", b"scanf", b"system"}

def extract_target_functions(binary_path: str) -> str:
	console.print(
		f"[bold cyan][*] Scanning symbol tables for high-risk sinks in:"
		f" {binary_path}[/bold cyan]"
	)

	try:
		with open(binary_path, "rb") as f:
			elffile = ELFFile(f)

			text_section = elffile.get_section_by_name(".text")
			if not text_section:
				console.print("[red][!] Error: No .text section found in ELF file.[/red]")
				sys.exit(1)

			code_bytes = text_section.data()
			load_addr = text_section["sh_addr"]

			# Look through symbol tables if available to find function bounds
			target_code = []
			md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)

			# Check symbol tables for function definitions
			symtab = elffile.get_section_by_name(".symtab")
			if symtab:
				for symbol in symtab.iter_symbols():
					if symbol["st_info"]["type"] == "STT_FUNC" and symbol["st_size"] > 0:
						func_name = symbol.name
						func_start = symbol["st_value"]
						func_size = symbol["st_size"]

						# If the function name looks custom or interesting, grab its bytes
						if func_name not in ["_start", "deregister_tm_clones", "register_tm_clones", "__do_global_dtors_aux", "frame_dummy", "__libc_csu_init", "__libc_csu_fini", "_init", "_fini"]:
							offset = func_start - load_addr
							if 0 <= offset < len(code_bytes):
								func_bytes = code_bytes[offset : offset + func_size]
								target_code.append(f"; --- Function: {func_name} ---")
								for i in md.disasm(func_bytes, func_start):
									target_code.append(f"0x{i.address:x}:\t{i.mnemonic}\t{i.op_str}")

			# Fallback: If no symbol table (stripped binary), disassemble a chunk of the .text section containing strings/calls
			if not target_code:
				console.print("[yellow][!] Binary is stripped. Extracting raw instruction stream...[/yellow]")
				for i in md.disasm(code_bytes[:2000], load_addr):
					target_code.append(f"0x{i.address:x}:\t{i.mnemonic}\t{i.op_str}")

			return "\n".join(target_code[:300]) # Cap to keep model focused

	except Exception as e:
		console.print(f"[red][!] Failed to parse binary: {e}[/red]")
		sys.exit(1)

def analyze_assembly(assembly_code: str):
	system_prompt = (
		"You are a strict binary vulnerability research assistant. You are given assembly code "
		"extracted from a compiled binary. Your ONLY task is to identify security vulnerabilities "
		"(such as buffer overflows, stack corruption, or unsafe string operations). "
		"Do NOT describe what the program does overall. Focus strictly on flaws.\n\n"
		"You MUST use this exact formatting template for your response:\n\n"
		"### Vulnerability Title: [Name the specific bug]\n"
		"### CWE ID: [e.g., CWE-120]\n"
		"### CVSS v3.1 Vector: [e.g., CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H]\n"
		"### Technical Description: [Explain the vulnerable instruction sequence, register setup, and sink]\n"
		"### Remediation Guidance: [Provide mitigation or code fix]"
	)

	user_content = (
		"Analyze the following extracted binary functions for vulnerabilities:\n\n"
		f"{assembly_code}"
	)

	console.print(
		"[bold yellow][*] Querying local abliterated model "
		"(huihui_ai/qwen2.5-coder-abliterate:7b)...[/bold yellow]\n"
	)

	stream = chat(
		model="huihui_ai/qwen2.5-coder-abliterate:7b",
		messages=[
			{"role": "system", "content": system_prompt},
			{"role": "user", "content": user_content},
		],
		stream=True,
		options={"temperature": 0.0, "num_predict": 700},
	)

	for chunk in stream:
		sys.stdout.write(chunk["message"]["content"])
		sys.stdout.flush()
	print()

if __name__ == "__main__":
	if len(sys.argv) < 2:
		console.print(
			"[red]Usage: python binary_auditor.py <path_to_executable>[/red]"
		)
		sys.exit(1)

	binary_path = sys.argv[1]
	disassembly = extract_target_functions(binary_path)

	console.print(
		Panel.fit(
			disassembly[:800] + "\n...",
			title="Extracted Function Assembly Preview",
			border_style="magenta",
		)
	)

	analyze_assembly(disassembly)
