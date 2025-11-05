#!/usr/bin/env python3
"""
Access Query Generator
Generates SQL queries for user creation and verification.
"""

try:
    import bcrypt
    BCRYPT_AVAILABLE = True
except ImportError:
    BCRYPT_AVAILABLE = False

def generate_password_hash(password):
    """Generate bcrypt hash for password"""
    if BCRYPT_AVAILABLE:
        try:
            salt = bcrypt.gensalt(rounds=12, prefix=b'2a')
            return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')
        except Exception as e:
            print(f"ERROR: bcrypt failed: {e}")
            return f"$2a$12$PLACEHOLDER_HASH_FOR_{password[:8]}_REPLACE_WITH_REAL_HASH"
    else:
        print("WARNING: bcrypt not available, using placeholder hash")
        return f"$2a$12$PLACEHOLDER_HASH_FOR_{password[:8]}_REPLACE_WITH_REAL_HASH"

def get_user_input():
    """Collect user information from input"""
    print("=== Access Query Generator ===")
    print()
    
    login = input("Enter login: ").strip()
    name = input("Enter full name: ").strip()
    email = input("Enter email: ").strip()
    password = input("Enter password (will be hashed): ").strip()
    
    # Set defaults without prompting
    enabled = "true"
    language = "CS"
    role_id = "1"
    
    return {
        'login': login,
        'name': name,
        'email': email,
        'password': password,
        'enabled': enabled.lower() == 'true',
        'language': language.upper(),
        'role_id': role_id
    }

def generate_queries(user_data):
    """Generate the SQL queries"""
    password_hash = generate_password_hash(user_data['password'])
    
    # Check if user exists query
    check_query = f"SELECT * FROM public.\"user\" WHERE login='{user_data['login']}';"
    
    # Insert user query
    insert_user_query = f"""INSERT INTO "public"."user" 
    ("id", "version", "login", "name", "password", "enabled", "account_expired", "account_locked", "password_expired", "email", "password_renew_hash", "preferred_language") 
VALUES 
    (nextval('hibernate_sequence'), 0, '{user_data['login']}', '{user_data['name']}', '{password_hash}', {str(user_data['enabled']).lower()}, false, false, false, '{user_data['email']}', null, '{user_data['language']}');"""
    
    # Insert user role query
    insert_role_query = f"""INSERT INTO "public"."user_role" 
    ("user_id", "role_id") 
VALUES 
    (lastval(), {user_data['role_id']});"""
    
    # Final verification query
    verify_query = f"SELECT * FROM public.\"user\" WHERE login='{user_data['login']}';"
    
    return check_query, insert_user_query, insert_role_query, verify_query

def main():
    try:
        user_data = get_user_input()
        print("\n" + "="*50)
        print("GENERATED SQL QUERIES")
        print("="*50)
        
        check_query, insert_user_query, insert_role_query, verify_query = generate_queries(user_data)
        
        print("\n-- Check if user exists:")
        print(check_query)
        
        print("\n-- Insert user:")
        print(insert_user_query)
        
        print("\n-- Insert user role:")
        print(insert_role_query)
        
        print("\n-- Verify user creation:")
        print(verify_query)
        
        print("\n" + "="*50)
        print("Copy the queries above and execute them in your database.")
        
    except KeyboardInterrupt:
        print("\n\nOperation cancelled.")
    except Exception as e:
        print(f"\nError: {e}")

if __name__ == "__main__":
    main()