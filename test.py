from gorilla_api import *
import os
import pickle
from googleapiclient.discovery import build
from googleapiclient.http import MediaFileUpload
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

def create_service():
    """Create and authenticate Google Drive service."""
    creds = None
    if os.path.exists('token.pickle'):
        with open('token.pickle', 'rb') as token:
            creds = pickle.load(token)
    
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(
                os.environ['GOOGLE_CLIENT_SECRETS'], scopes=['https://www.googleapis.com/auth/drive.file'])
            creds = flow.run_local_server(port=0)
        with open('token.pickle', 'wb') as token:
            pickle.dump(creds, token)
    
    service = build('drive', 'v3', credentials=creds)
    return service

def upload_file(filename, filepath, mimetype):
    """Upload file to Google Drive."""
    try:
        service = create_service()
        file_metadata = {'name': filename}
        media = MediaFileUpload(filepath, mimetype=mimetype)
        file = service.files().create(body=file_metadata, media_body=media, fields='id').execute()
        print('File ID: %s' % file.get('id'))
    except Exception as e:
        print(f"An error occurred: {e}")

def read_file_binary(file_path):
    """Read binary file."""
    with open(file_path, 'rb') as file:
        return file.read()
    
def write_file_binary(file_path, data):
    """Write binary data to file."""
    with open(file_path, 'wb') as file:
        file.write(data)
"""
def encrypt_file_binary(input_path, key_name, output_name):
    #Encrypt binary file.
    try:
        plaintext = read_file_binary(input_path)
        encrypted_data = encrypt(plaintext.decode("utf-8"), key_name)  # Assume encrypt handles bytes
        if isinstance(encrypted_data, str):
            encrypted_data = encrypted_data.encode('utf-8')
        write_file_binary(output_name, encrypted_data)
        print(f"Encryption successful, file written to {output_name}")
    except Exception as e:
        print(f"Error during encryption: {e}")
"""
def encrypt_file_binary(input_path, key_name, output_name):
    try:
        # Read the binary file directly
        plaintext = read_file_binary(input_path)
        # Encrypt directly without decoding
        encrypted_data = encrypt(plaintext, key_name)
        # Write encrypted data as binary
        write_file_binary(output_name, encrypted_data)
        print(f"Encryption successful, file written to {output_name}")
    except Exception as e:
        print(f"Error during encryption: {e}")

def decrypt_file_binary(input_path, key_name, output_name):
    """Decrypt binary file."""
    try:
        ciphertext = read_file_binary(input_path)
        decrypted_data = decrypt(ciphertext, key_name)  # Assume decrypt handles bytes
        write_file_binary(output_name, decrypted_data)
        print(f"Decryption successful, file written to {output_name}")
    except Exception as e:
        print(f"Error during decryption: {e}")


# Usage
eccKeyName = "ecc-key"
createEccKey(eccKeyName)

rsaKeyName = "rsa-key"
createRsaKey(rsaKeyName)

message = "This is an Encryption Test! Hello World!"

  # Assumes createRsaKey is part of gorilla_api

#encrypt_file_binary('example.txt', eccKeyName, "encrypted.txt")
#decrypt_file_binary('encrypted.txt', eccKeyName, "decrypted.txt")
enc = encrypt(message, rsaKeyName)
print(enc)

dec = decrypt(enc, rsaKeyName)
print(dec)

sign = sign(message,eccKeyName)
print(sign)

deleteKey(eccKeyName)  # Assumes deleteKey is part of gorilla_api
deleteKey(rsaKeyName)
