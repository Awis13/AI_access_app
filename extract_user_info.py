#!/usr/bin/env python3
"""
Extract user information from text using an AI LLM SDK with structured-like responses
Extracts: login (surname without diacritics in lowercase), full name, and email
"""

import json
import sys
import unicodedata
import re
import logging
from typing import Dict, Optional
from config import LLM_MODEL_NAME, OLLAMA_BASE_URL
try:
    import ollama
    from pydantic import BaseModel
except ImportError:
    print("Error: Please install required packages:", file=sys.stderr)
    print("  pip install ollama pydantic", file=sys.stderr)
    sys.exit(1)

logger = logging.getLogger(__name__)
if logger.level == logging.NOTSET:
    logger.setLevel(logging.DEBUG)

def remove_diacritics(text: str) -> str:
    """Remove diacritics from text."""
    nfd_form = unicodedata.normalize('NFD', text)
    return ''.join(char for char in nfd_form if unicodedata.category(char) != 'Mn')

def create_login_from_surname(surname: str) -> str:
    """Create login from surname: remove diacritics and convert to lowercase."""
    clean_surname = remove_diacritics(surname)
    return clean_surname.lower()

# Define the schema for structured response using Pydantic
class UserInfo(BaseModel):
    """Schema for user information extraction"""
    full_name: str
    surname: str
    email: str

def extract_with_ollama(text: str, model_name: str = None) -> Dict:
    """
    Extract user information using Ollama with structured outputs.
    
    Args:
        text: The input text to parse
        model_name: The name of the model to use (optional)
    
    Returns:
        Dictionary with extracted user information
    """
    
    try:
        # Use the specified model or default from config
        model_to_use = model_name if model_name else LLM_MODEL_NAME
        logger.debug(
            "extract_with_ollama start | host=%s model=%s text_preview=%s",
            OLLAMA_BASE_URL,
            model_to_use,
            text[:120].replace("\n", " "),
        )
        
        # Prepare the prompt
        prompt = f"""Extract a person's full name, surname, and email address from the text below.

Guidelines:
- Return the name in its base (nominative) form when possible.
- Preserve diacritics (ě, š, č, ř, ž, etc.) if they appear in the source.
- Assume surname is the final word of the full name.

Examples:
- "Please onboard Ondřeje Nováka (ondrej.novak@example.com)." →
    full_name: "Ondřej Novák", surname: "Novák"
- "Access needed for Jana Novotná - jana.novotna@example.com" →
    full_name: "Jana Novotná", surname: "Novotná"
- "Create an account for Pavel Svoboda (psvoboda@example.com)" →
    full_name: "Pavel Svoboda", surname: "Svoboda"

Text: {text}"""
        
        # Configure Ollama client
        client = ollama.Client(host=OLLAMA_BASE_URL)
        logger.debug("Ollama client initialised, sending chat request")
        
        # Use Ollama with structured outputs
        response = client.chat(
            model=model_to_use,
            messages=[
                {
                    'role': 'user',
                    'content': prompt,
                }
            ],
            format=UserInfo.model_json_schema(),
            options={
                'temperature': 0.3,
                'top_p': 0.9,
            }
        )
        
        logger.debug("Raw Ollama response: %s", repr(response['message']['content']))
        
        # Parse the structured JSON response
        user_info = UserInfo.model_validate_json(response['message']['content'])
        
        # Convert to dictionary and add login field
        extracted = {
            "full_name": user_info.full_name,
            "surname": user_info.surname,
            "email": user_info.email
        }
        
        # Add the login field based on surname
        if extracted.get("surname"):
            extracted["login"] = create_login_from_surname(extracted["surname"])
        else:
            extracted["login"] = None
            
        logger.debug("Structured extraction result: %s", extracted)
        return extracted
        
    except ConnectionError as e:
        logger.error("Cannot connect to Ollama at %s: %s", OLLAMA_BASE_URL, e)
        print(f"Error: Cannot connect to Ollama: {e}", file=sys.stderr)
        print(f"Make sure Ollama is running at {OLLAMA_BASE_URL}", file=sys.stderr)
        return None
    except Exception as e:
        logger.exception("Error using Ollama backend")
        print(f"Error using Ollama: {e}", file=sys.stderr)
        print(f"Exception type: {type(e)}", file=sys.stderr)
        return None

def extract_with_regex(text: str) -> Dict:
    """
    Fallback method: Extract user information using regex patterns.
    
    Args:
        text: The input text to parse
    
    Returns:
        Dictionary with extracted user information
    """
    
    result = {
        "full_name": None,
        "surname": None,
        "email": None,
        "login": None
    }
    
    # Extract email (allow unicode letters in local-part and domain labels)
    email_pattern = r"\b[\w.!#$%&'*+/=?^`{|}~-]+@[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+\b"
    email_match = re.search(email_pattern, text)
    if email_match:
        result["email"] = email_match.group()
    
    # Try to extract name (this is basic and might need adjustment based on your text format)
    # Look for patterns like "Name: John Doe" or "Full Name: John Doe"
    name_patterns = [
        r'(?:Full )?Name:\s*([^\n,]+)',
        r'(?:Jméno|Meno|Prímeno):\s*([^\n,]+)',  # Czech/Slovak variants
        r'Jmeno:\s*([^\n,]+)',  # without diacritics
        r'(?:(?:user|uživatel|zaměstnanec)\s*:?\s*)([A-ZÁČĎÉĚÍŇÓŘŠŤÚŮÝŽ][a-záčďéěíňóřšťúůýž]+\s+[A-ZÁČĎÉĚÍŇÓŘŠŤÚŮÝŽ][a-záčďéěíňóřšťúůýž]+)',
        r'^([A-ZÁČĎÉĚÍŇÓŘŠŤÚŮÝŽ][a-záčďéěíňóřšťúůýž]+\s+[A-ZÁČĎÉĚÍŇÓŘŠŤÚŮÝŽ][a-záčďéěíňóřšťúůýž]+)',  # Name at start
    ]
    
    for pattern in name_patterns:
        name_match = re.search(pattern, text, re.MULTILINE | re.IGNORECASE)
        if name_match:
            result["full_name"] = name_match.group(1).strip()
            # Extract surname (last word of full name)
            name_parts = result["full_name"].split()
            if len(name_parts) > 0:
                result["surname"] = name_parts[-1]
                result["login"] = create_login_from_surname(result["surname"])
            break
    # If we have email but no name, try deriving login from email local-part
    if result["email"] and not result["login"]:
        local_part = result["email"].split('@', 1)[0]
        # If local part looks like name.surname or name_surname, take last token as surname
        tokens = re.split(r'[._-]+', local_part)
        if tokens:
            derived_surname = tokens[-1]
            result["surname"] = result["surname"] or derived_surname
            result["login"] = create_login_from_surname(derived_surname)
    
    return result

def main():
    """Main function to run the extraction."""
    
    # Check command line arguments
    if len(sys.argv) < 2:
        print("Usage: python extract_user_info.py <text_file> [--method ollama|regex] [--model <model_name>]")
        print("\nExample:")
        print('  python extract_user_info.py input.txt')
        print('  python extract_user_info.py input.txt --method ollama --model llama3.1')
        print('  echo "Jan Novák, email: jan.novak@example.com" | python extract_user_info.py -')
        sys.exit(1)
    
    # Read input text
    if sys.argv[1] == '-':
        # Read from stdin
        text = sys.stdin.read()
    else:
        # Read from file
        try:
            with open(sys.argv[1], 'r', encoding='utf-8') as f:
                text = f.read()
        except FileNotFoundError:
            print(f"Error: File '{sys.argv[1]}' not found", file=sys.stderr)
            sys.exit(1)
    
    # Parse optional arguments
    method = "ollama"  # Default to Ollama backend
    model_name = None  # Will use environment variable or default
    
    for i in range(2, len(sys.argv)):
        if sys.argv[i] == "--method" and i + 1 < len(sys.argv):
            method = sys.argv[i + 1]
        elif sys.argv[i] == "--model" and i + 1 < len(sys.argv):
            model_name = sys.argv[i + 1]
    
    # Extract information
    if method == "ollama":
        result = extract_with_ollama(text, model_name)
        if result is None:
            print("Falling back to regex method...", file=sys.stderr)
            result = extract_with_regex(text)
    else:
        result = extract_with_regex(text)
    
    # Output as JSON
    print(json.dumps(result, ensure_ascii=False, indent=2))

if __name__ == "__main__":
    main()
