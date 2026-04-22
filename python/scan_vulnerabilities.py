#!/usr/bin/env python3
"""
Vulnerability Scanner using Ollama LLM
This script scans Python source files and sends them to a local Ollama instance
for security vulnerability analysis.
"""

import os
import sys
import requests
from datetime import datetime

# ============================================================================
# CONFIGURATION
# ============================================================================
OLLAMA_URL = "http://192.168.1.99:11434/api/generate"
MODEL = "qwen3.5:4b"
SOURCE_DIR = "."
OUTPUT_FILE = "vulnerabilities.txt"
EXTENSIONS = [".py"]
MAX_CHARS_PER_CHUNK = 3000
EXCLUDE_FILES = [
    "scan_vulnerabilities.py",
    "test_code.py",
    OUTPUT_FILE
]

# ============================================================================
# PROMPT TEMPLATE
# ============================================================================
PROMPT_TEMPLATE = """You are a senior security engineer performing a code review. 
Analyze the following Python code for potential security vulnerabilities.

Focus specifically on:
1. SQL Injection (concatenated queries, lack of parameterization)
2. Hardcoded credentials (passwords, API keys, connection strings)
3. Insecure cryptography (weak algorithms, hardcoded salts)
4. Path traversal vulnerabilities (file operations with user input)
5. Insecure deserialization
6. Missing input validation
7. Cross-site scripting (XSS) in web contexts
8. Improper exception handling that leaks sensitive information

For each vulnerability found, respond with:
- **Vulnerability Type:** [e.g., SQL Injection]
- **Severity:** [Critical/High/Medium/Low]
- **Explanation:** [Brief description of the issue and why it's dangerous]

If NO vulnerabilities are found, respond with exactly: "No vulnerabilities detected."

Be concise but thorough. Only report genuine security concerns.

Code to analyze:
---
{code}
---"""

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def find_files(directory, extensions):
    """Recursively find all files with given extensions."""
    found = []
    for root, dirs, files in os.walk(directory):
        # Skip common non-code directories
        dirs[:] = [d for d in dirs if d not in ('.git', '__pycache__', 'env', 'venv', 'bin', 'obj')]
        for file in files:
            if any(file.endswith(ext) for ext in extensions):
                found.append(os.path.join(root, file))
    return found


def chunk_code(content, max_chars=MAX_CHARS_PER_CHUNK):
    """Split large code into chunks that fit the LLM's context window."""
    if len(content) <= max_chars:
        return [content]
    
    lines = content.split('\n')
    chunks = []
    current_chunk = ""
    
    for line in lines:
        if len(current_chunk) + len(line) + 1 <= max_chars:
            current_chunk += line + '\n'
        else:
            if current_chunk:
                chunks.append(current_chunk)
            current_chunk = line + '\n'
    
    if current_chunk:
        chunks.append(current_chunk)
    
    return chunks


def query_ollama(prompt):
    """Send prompt to Ollama and return the response."""
    payload = {
        "model": MODEL,
        "prompt": prompt,
        "stream": False,
        "options": {
            "temperature": 0.1,
            "num_predict": 500
        }
    }
    
    try:
        response = requests.post(OLLAMA_URL, json=payload, timeout=1000)
        response.raise_for_status()
        result = response.json()
        return result.get("response", "ERROR: No response field in JSON")
    except requests.exceptions.ConnectionError:
        return "ERROR: Could not connect to Ollama. Is it running?"
    except requests.exceptions.Timeout:
        return "ERROR: Ollama request timed out."
    except Exception as e:
        return f"ERROR: {str(e)}"


def test_ollama_connection():
    """Verify Ollama is reachable and model exists."""
    try:
        base_url = OLLAMA_URL.rsplit('/', 1)[0]
        response = requests.get(f"{base_url}/api/tags", timeout=5)
        response.raise_for_status()
        models = response.json().get("models", [])
        model_names = [m.get("name", "") for m in models]
        
        if MODEL not in model_names and not any(m.startswith(MODEL) for m in model_names):
            print(f"WARNING: Model '{MODEL}' not found. Available: {model_names}")
            return False
        return True
    except Exception as e:
        print(f"ERROR: Could not connect to Ollama: {e}")
        return False


# ============================================================================
# MAIN
# ============================================================================

def main():
    print("=" * 60)
    print("VULNERABILITY SCANNER USING OLLAMA LLM")
    print("=" * 60)
    print(f"Model: {MODEL}")
    print(f"Ollama URL: {OLLAMA_URL}")
    print(f"Scanning directory: {os.path.abspath(SOURCE_DIR)}")
    print()
    
    # Test Ollama connection
    print("Testing connection to Ollama...")
    if not test_ollama_connection():
        print("WARNING: Ollama connection issues detected. Scan may fail.")
    print()
    
    # Find all Python files
    print("Searching for Python files...")
    all_files = find_files(SOURCE_DIR, EXTENSIONS)
    print(f"Found {len(all_files)} total Python file(s).")
    
    # Apply exclusions (case‑insensitive)
    exclude_lower = [ef.lower() for ef in EXCLUDE_FILES]
    py_files = []
    for f in all_files:
        if os.path.basename(f).lower() in exclude_lower:
            print(f"  Excluded: {f}")
        else:
            py_files.append(f)
    
    print(f"\nTotal files to scan: {len(py_files)}")
    for f in py_files:
        print(f"  - {f}")
    print()
    
    # Write report
    with open(OUTPUT_FILE, "w", encoding="utf-8") as out:
        out.write("=" * 80 + "\n")
        out.write("VULNERABILITY SCAN REPORT\n")
        out.write("=" * 80 + "\n")
        out.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        out.write(f"Model: {MODEL}\n")
        out.write(f"Files Scanned: {len(py_files)}\n")
        out.write("=" * 80 + "\n\n")
        
        for idx, file_path in enumerate(py_files, 1):
            print(f"[{idx}/{len(py_files)}] Scanning: {file_path}")
            
            out.write(f"FILE: {file_path}\n")
            out.write("-" * 80 + "\n")
            
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    code_content = f.read()
            except Exception as e:
                out.write(f"ERROR reading file: {str(e)}\n\n")
                print(f"  ERROR: Could not read file - {e}")
                continue
            
            if not code_content.strip():
                out.write("File is empty or contains only whitespace.\n\n")
                print(f"  SKIPPED: File is empty")
                continue
            
            chunks = chunk_code(code_content)
            if len(chunks) > 1:
                out.write(f"(File split into {len(chunks)} chunks due to size)\n\n")
                print(f"  File split into {len(chunks)} chunks")
            
            for chunk_idx, chunk in enumerate(chunks, 1):
                if len(chunks) > 1:
                    out.write(f"--- CHUNK {chunk_idx}/{len(chunks)} ---\n")
                
                prompt = PROMPT_TEMPLATE.format(code=chunk)
                print(f"  Querying Ollama...")
                
                result = query_ollama(prompt)
                out.write(result + "\n\n")
                
                if result.startswith("ERROR:"):
                    print(f"  ERROR: {result}")
                else:
                    preview = result[:100].replace('\n', ' ')
                    print(f"  Response: {preview}...")
            
            out.write("\n" + "=" * 80 + "\n\n")
            print(f"  Completed: {file_path}\n")
        
        out.write("\n" + "=" * 80 + "\n")
        out.write("END OF REPORT\n")
        out.write("=" * 80 + "\n")
    
    print("=" * 60)
    print(f"SCAN COMPLETE. Report saved to: {os.path.abspath(OUTPUT_FILE)}")
    print("=" * 60)
    
    return True


if __name__ == "__main__":
    try:
        main()
        sys.exit(0)
    except Exception as e:
        print(f"\nFATAL ERROR: {str(e)}")
        import traceback
        traceback.print_exc()
        sys.exit(0)