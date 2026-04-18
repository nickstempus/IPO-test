#!/usr/bin/env python3
"""
Vulnerability Scanner using Ollama LLM
This script scans C# source files and sends them to a local Ollama instance
for security vulnerability analysis.
"""

import os
import sys
import glob
import json
import requests
from datetime import datetime

# ============================================================================
# CONFIGURATION - MODIFY THESE AS NEEDED
# ============================================================================
OLLAMA_URL = "http://localhost:11434/api/generate"
MODEL = "qwen2.5-coder:1.5b"           
SOURCE_DIR = "."             
OUTPUT_FILE = "vulnerabilities.txt"
EXTENSIONS = ["*.cs"]        
MAX_CHARS_PER_CHUNK = 3000

# ============================================================================
# PROMPT TEMPLATE FOR THE LLM
# ============================================================================
PROMPT_TEMPLATE = """You are a senior security engineer performing a code review. 
Analyze the following C# code for potential security vulnerabilities.

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
    """
    Recursively find all files with specified extensions in the directory.
    """
    files = []
    for ext in extensions:
        pattern = os.path.join(directory, "**", ext)
        files.extend(glob.glob(pattern, recursive=True))
    return files


def chunk_code(content, max_chars=MAX_CHARS_PER_CHUNK):
    """
    Split large files into chunks that fit within the LLM's context window.
    Tries to split at line boundaries when possible.
    """
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
    """
    Send a prompt to the local Ollama instance and return the response.
    """
    payload = {
        "model": MODEL,
        "prompt": prompt,
        "stream": False,
        "options": {
            "temperature": 0.1,    # Low temperature for more consistent/analytical responses
            "num_predict": 500     # Limit response length
        }
    }
    
    try:
        response = requests.post(OLLAMA_URL, json=payload, timeout=120)
        response.raise_for_status()
        result = response.json()
        return result.get("response", "ERROR: No response field in JSON")
    except requests.exceptions.ConnectionError:
        return "ERROR: Could not connect to Ollama. Is it running on localhost:11434?"
    except requests.exceptions.Timeout:
        return "ERROR: Ollama request timed out."
    except Exception as e:
        return f"ERROR: {str(e)}"


def test_ollama_connection():
    """
    Verify that Ollama is running and the specified model is available.
    """
    try:
        response = requests.get("http://localhost:11434/api/tags", timeout=5)
        response.raise_for_status()
        models = response.json().get("models", [])
        model_names = [m.get("name", "") for m in models]
        
        if MODEL not in model_names and not any(m.startswith(MODEL) for m in model_names):
            print(f"WARNING: Model '{MODEL}' not found in Ollama. Available: {model_names}")
            print(f"You may need to run: ollama pull {MODEL}")
            return False
        return True
    except Exception as e:
        print(f"ERROR: Could not connect to Ollama: {e}")
        print("Ensure Ollama is running with: ollama serve")
        return False


# ============================================================================
# MAIN SCAN FUNCTION
# ============================================================================

def main():
    """
    Main execution function.
    """
    print("=" * 60)
    print("VULNERABILITY SCANNER USING OLLAMA LLM")
    print("=" * 60)
    print(f"Model: {MODEL}")
    print(f"Ollama URL: {OLLAMA_URL}")
    print(f"Scanning directory: {os.path.abspath(SOURCE_DIR)}")
    print()
    
    # Test Ollama connection before proceeding
    print("Testing connection to Ollama...")
    if not test_ollama_connection():
        print("WARNING: Ollama connection issues detected. Scan may fail.")
    print()
    
    # Find all C# files
    print("Searching for C# files...")
    cs_files = find_files(SOURCE_DIR, EXTENSIONS)
    
    # Filter out obj and bin directories (build artifacts)
    cs_files = [f for f in cs_files if '\\obj\\' not in f and '\\bin\\' not in f]
    
    print(f"Found {len(cs_files)} C# file(s) to scan:")
    for f in cs_files:
        print(f"  - {f}")
    print()
    
    # Open output file for writing
    with open(OUTPUT_FILE, "w", encoding="utf-8") as out:
        # Write report header
        out.write("=" * 80 + "\n")
        out.write("VULNERABILITY SCAN REPORT\n")
        out.write("=" * 80 + "\n")
        out.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        out.write(f"Model: {MODEL}\n")
        out.write(f"Files Scanned: {len(cs_files)}\n")
        out.write("=" * 80 + "\n\n")
        
        # Scan each file
        for idx, file_path in enumerate(cs_files, 1):
            print(f"[{idx}/{len(cs_files)}] Scanning: {file_path}")
            
            out.write(f"FILE: {file_path}\n")
            out.write("-" * 80 + "\n")
            
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    code_content = f.read()
            except Exception as e:
                out.write(f"ERROR reading file: {str(e)}\n\n")
                print(f"  ERROR: Could not read file - {e}")
                continue
            
            # Skip empty files
            if not code_content.strip():
                out.write("File is empty or contains only whitespace.\n\n")
                print(f"  SKIPPED: File is empty")
                continue
            
            # Chunk if necessary (for large files)
            chunks = chunk_code(code_content)
            if len(chunks) > 1:
                out.write(f"(File split into {len(chunks)} chunks due to size)\n\n")
                print(f"  File split into {len(chunks)} chunks")
            
            # Query Ollama for each chunk
            for chunk_idx, chunk in enumerate(chunks, 1):
                if len(chunks) > 1:
                    out.write(f"--- CHUNK {chunk_idx}/{len(chunks)} ---\n")
                
                prompt = PROMPT_TEMPLATE.format(code=chunk)
                
                print(f"  Querying Ollama for analysis" + 
                      (f" (chunk {chunk_idx}/{len(chunks)})..." if len(chunks) > 1 else "..."))
                
                result = query_ollama(prompt)
                out.write(result + "\n\n")
                
                if result.startswith("ERROR:"):
                    print(f"  ERROR: {result}")
                else:
                    # Print a preview of the response
                    preview = result[:100].replace('\n', ' ') + "..."
                    print(f"  Response: {preview}")
            
            out.write("\n" + "=" * 80 + "\n\n")
            print(f"  Completed: {file_path}")
            print()
        
        # Write report footer
        out.write("\n" + "=" * 80 + "\n")
        out.write("END OF REPORT\n")
        out.write("=" * 80 + "\n")
    
    print("=" * 60)
    print(f"SCAN COMPLETE")
    print(f"Report saved to: {os.path.abspath(OUTPUT_FILE)}")
    print("=" * 60)
    
    return True


# ============================================================================
# ENTRY POINT
# ============================================================================

if __name__ == "__main__":
    try:
        success = main()
        if success:
            print("\nVulnerability scan completed successfully.")
            sys.exit(0)
        else:
            print("\nVulnerability scan completed with warnings.")
            sys.exit(0)  # Exit with 0 so pipeline continues
    except Exception as e:
        print(f"\nFATAL ERROR: {str(e)}")
        import traceback
        traceback.print_exc()
        sys.exit(0)  # Exit with 0 so pipeline continues (don't block build)
