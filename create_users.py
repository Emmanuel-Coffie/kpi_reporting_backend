import os
import django
import pandas as pd
from django.core.exceptions import MultipleObjectsReturned

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'kpi_system.settings')
django.setup()

from django.contrib.auth.models import User
from kpis.models import Directorate

def clean_string(value):
    """Clean and standardize string values"""
    if pd.isna(value):
        return ''
    return str(value).strip()

def create_users_from_excel(file_path):
    try:
        # Read the Directorates sheet
        df = pd.read_excel(file_path, sheet_name='Directorates', header=1)  # Skip first row
        
        # Print available columns for debugging
        print("\nAvailable columns in Excel file:")
        print(df.columns.tolist())
        print("\nFirst 5 rows of data:")
        print(df.head().to_string())
        
        # Define expected columns with case-insensitive matching
        expected_columns = {
            'full_name': ['FULL NAME', 'FULLNAME', 'NAME'],
            'email': ['OUTLOOK EMAIL ACCOUNT', 'EMAIL', 'EMAIL ACCOUNT'],
            'directorate': ['DIRECTORATE', 'DIRECTORATE '],
            'staff_number': ['STAFF NUMBER', 'STAFF NO', 'STAFF_ID'],
            'phone': ['PHONE NUMBER', 'PHONE', 'MOBILE']
        }
        
        # Find matching columns (case-insensitive)
        col_map = {}
        for field, possible_names in expected_columns.items():
            for col in df.columns:
                if col.upper() in [name.upper() for name in possible_names]:
                    col_map[field] = col
                    break
            else:
                print(f"Warning: No column found for {field} (tried: {', '.join(possible_names)})")
        
        # Verify we have required columns
        if 'full_name' not in col_map or 'email' not in col_map:
            raise ValueError("Missing required columns (full name and email)")
        
        # Filter out rows without full name or email
        df = df[df[col_map['full_name']].notna() & df[col_map['email']].notna()]
        
        created_users = 0
        skipped_users = 0
        directorate_errors = 0
        
        for index, row in df.iterrows():
            try:
                full_name = clean_string(row[col_map['full_name']])
                email = clean_string(row[col_map['email']]).lower()
                
                # Skip if email is not valid
                if '@' not in email:
                    print(f"Row {index+2}: Invalid email '{email}' for {full_name}. Skipping...")
                    skipped_users += 1
                    continue
                    
                # Split full name into first and last name
                name_parts = full_name.split()
                first_name = name_parts[0] if name_parts else ''
                last_name = ' '.join(name_parts[1:]) if len(name_parts) > 1 else ''
                
                # Get username from email (part before @)
                username = email.split('@')[0]
                
                # Default password
                password = '00000000'
                
                # Check if user already exists
                if User.objects.filter(username=username).exists():
                    print(f"Row {index+2}: User {username} already exists. Skipping...")
                    skipped_users += 1
                    continue
                    
                # Create user
                user = User.objects.create_user(
                    username=username,
                    email=email,
                    password=password,
                    first_name=first_name,
                    last_name=last_name
                )
                
                # Try to add user to directorate if directorate exists in mapping
                if 'directorate' in col_map and pd.notna(row[col_map['directorate']]):
                    directorate_name = clean_string(row[col_map['directorate']])
                    if directorate_name:  # Only proceed if directorate name is not empty
                        try:
                            # Handle case where directorate name might have extra spaces or different casing
                            directorate = Directorate.objects.filter(name__iexact=directorate_name).first()
                            if directorate:
                                directorate.users.add(user)
                                print(f"Row {index+2}: Created user {username} and added to {directorate_name}")
                            else:
                                print(f"Row {index+2}: Created user {username} (directorate '{directorate_name}' not found)")
                                directorate_errors += 1
                        except MultipleObjectsReturned:
                            print(f"Row {index+2}: Multiple directorates found with name '{directorate_name}'. User not added to any.")
                            directorate_errors += 1
                else:
                    print(f"Row {index+2}: Created user {username} (no directorate specified)")
                
                created_users += 1
                    
            except Exception as e:
                print(f"Row {index+2}: Error processing user - {str(e)}")
                skipped_users += 1
                continue
        
        print(f"\nSummary:")
        print(f"Successfully created {created_users} new users.")
        print(f"Skipped {skipped_users} users (duplicates, invalid data, or errors)")
        if directorate_errors > 0:
            print(f"Note: {directorate_errors} users had directorate assignment issues")
    
    except Exception as e:
        print(f"\nFatal error processing Excel file: {str(e)}")

if __name__ == "__main__":
    excel_file = "Users.xlsx"  # Path to your Excel file
    print(f"Starting user import from {excel_file}...")
    create_users_from_excel(excel_file)
    print("Import process completed.")