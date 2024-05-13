import paramiko
import base64
from creds import *

def run_ssh_command(ip: str, username: str, passwd: str, command: str) -> str:
    # Create a new SSH client
    client = paramiko.SSHClient()
    # Automatically add untrusted hosts (make sure okay for security policy)
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        client.connect(ip, username=username, password=passwd)
        # Execute the SSH command
        stdin, stdout, stderr = client.exec_command(command)
        # Read the output from stdout and stderr streams
        output = stdout.read()
        return output.decode('utf-8')

    finally:
        # Close the connection
        client.close()

def ping():
    ssh_command = f'parsec-tool ping'
    return run_ssh_command(ip_address, user, passwd, ssh_command)

def listKeys():
    ssh_command = f'parsec-tool list-keys'
    return run_ssh_command(ip_address, user, passwd, ssh_command)

def createCsr(keyName):
    ssh_command = f'parsec-tool create-csr --key-name {keyName}'
    return run_ssh_command(ip_address, user, passwd, ssh_command)

def createEccKey(keyName):
    ssh_command = f'parsec-tool create-ecc-key --key-name {keyName}'
    return run_ssh_command(ip_address, user, passwd, ssh_command)

def createRsaKey(keyName):
    ssh_command = f'parsec-tool create-rsa-key --key-name {keyName}'
    return run_ssh_command(ip_address, user, passwd, ssh_command)

def deleteKey(keyName):
    ssh_command = f'parsec-tool delete-key --key-name {keyName}'
    return run_ssh_command(ip_address, user, passwd, ssh_command).strip()

def encrypt(inputData, keyName):
    ssh_command = f"parsec-tool encrypt '{inputData}' --key-name {keyName}"
    print(ssh_command)
    encrypted_data = run_ssh_command(ip_address, user, passwd, ssh_command)
    # Encode the binary data to base64 to ensure safe string handling
    return encrypted_data.strip()

def decrypt(inputData: str, keyName:str):
    ssh_command = f"parsec-tool decrypt '{inputData}' --key-name {keyName}"
    return run_ssh_command(ip_address, user, passwd, ssh_command)


'''
def encrypt(input_data, key_name):
    # Convert binary data to a base64-encoded string
    encoded_data = base64.b64encode(input_data).decode('utf-8')
    ssh_command = f"echo {encoded_data} | base64 --decode | parsec-tool encrypt --key-name {key_name} | base64"
    print(ssh_command)
    encrypted_data = run_ssh_command(ip_address, user, passwd, ssh_command)
    print(encrypted_data)
    return base64.b64decode(encrypted_data.strip())

def encrypt(input_data, key_name):
    """ Encrypt data using parsec-tool via SSH. """
    try:
        # Correctly encode the binary data to base64
        encoded_data = base64.b64encode(input_data).decode('utf-8')
        # Correct command using encoded data
        ssh_command = f"echo {encoded_data} | base64 --decode | parsec-tool encrypt --key-name {key_name} | base64"
        encrypted_data = run_ssh_command(ip_address, user, passwd, ssh_command)
        # Check and decode the base64 encrypted data
        if not encrypted_data.strip():
            raise ValueError("No data returned from encryption command.")
        return base64.b64decode(encrypted_data.strip())
    except Exception as e:
        print(f"An error occurred during encryption: {e}")
        return None

def decrypt(input_data, key_name):
    encoded_data = base64.b64encode(input_data).decode('utf-8')
    ssh_command = f"echo {encoded_data} | base64 --decode | parsec-tool decrypt --key-name {key_name} | base64"
    decrypted_data = run_ssh_command(ip_address, user, passwd, ssh_command)
    return base64.b64decode(decrypted_data.strip())
'''

def sign(inputData, keyName):
    ssh_command = f"parsec-tool sign '{inputData}' --key-name {keyName}"
    print(ssh_command)
    return run_ssh_command(ip_address, user, passwd, ssh_command)

def generateRandom(nBytes):
    ssh_command = f'parsec-tool --generate-random {nBytes}'
    return run_ssh_command(ip_address, user, passwd, ssh_command)

