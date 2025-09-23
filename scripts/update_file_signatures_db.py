import json
import argparse
import os
import subprocess

SEPERATOR = ':'
NAME_INDEX = 0
SIGNATURE_INDEX = 3
DATABASE_FILE_URL = "https://database.clamav.net/main.cvd"
DATABASE_FILE_NAME = "../data/main.cvd"
EXTRACT_DATABASE_FILE_TO = "../data/file_signatures"
SIGTOOL_PATH = "%USERPROFILE%\\Downloads\\clamav-1.4.3.win.x64\\clamav-1.4.3.win.x64\\sigtool.exe"
DATABASE_FILE = "main.ndb"
OUTPUT_FILE = "../data/file_signatures.json"

def main():
    parser = argparse.ArgumentParser(description='Update signatures database (signatures)')
    parser.add_argument('-d', '--download', action='store_true', help='Download new database from URL')
    parser.add_argument('-e', '--extract', action='store_true', help='Extract the database file')
    parser.add_argument('-p', '--parse', action='store_true', help='Parse CSV to SQLite database')
    parser.add_argument('-r', '--remove_files', action='store_true', help='Remove the leftover files (if exists) (zip, csv)')
    args = parser.parse_args()

    if args.download:
        print("\n\n=======================================")
        print("CAN NO LONGER DOWNLOAD THE DATABASE!")
        print("CalmAV has blocked the option to download")
        print("the database using a script. Please download")
        print("the database manually from the following URL:")
        print(DATABASE_FILE_URL)
        print("=======================================\n\n")


    if args.extract:
        try:
            extract_database(os.path.abspath(DATABASE_FILE_NAME), os.path.abspath(EXTRACT_DATABASE_FILE_TO))
        except Exception as e:
            print(f"Error extracting database: {e}")
            return

    if args.parse:
        try:
            parse_database(os.path.join(EXTRACT_DATABASE_FILE_TO, DATABASE_FILE), OUTPUT_FILE)
        except Exception as e:
            print(f"Error parsing database: {e}")
            return


def extract_database(database_file, output_path):
    """Extract the database file using sigtool"""
    
    print(f"Extracting database from {database_file} to {output_path}...")
    
    if not os.path.exists(output_path):
        os.makedirs(output_path)

    curr_dir = os.getcwd()
    os.chdir(output_path)
    subprocess.run([SIGTOOL_PATH, "--unpack", database_file])
    os.chdir(curr_dir)

    print(f"Database extracted successfully to {output_path}")

def parse_database(database_file, output_file_path):
    """Parse the database file and extract the signatures"""
    
    print(f"Parsing database from {database_file}...")
    
    signature_name_map = {}
    
    with open(database_file, 'r') as f:
        lines = f.readlines()

        for line in lines:
            name, signature = parse_line(line)

            signature_name_map[signature] = name

    with open(output_file_path, 'w') as f:
        json.dump(signature_name_map, f)

    print(f"Database parsed successfully to {output_file_path}")

def parse_line(line):
    parts = line.split(SEPERATOR)

    name = parts[NAME_INDEX]
    signature = parts[SIGNATURE_INDEX]

    return name, signature

if __name__ == '__main__':
  main()