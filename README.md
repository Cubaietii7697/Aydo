# Aydo

The best anti virus, ever!!

## VMRunner

VMRunner is a simple tool that allows you to run a virtual machine in a sandbox environment.

### Note about the VMRunner

Remember to change the following constants in the VMRunner.cpp file:

- VM_RUN_PATH
- ANALYSIS_VM_PATH
- SANDBOXES_DIRECTORY_PATH

To your own constants!

## Data

The data folder contains the file hashes database and the signatures database. It is not included with the repository, because the database is updated daily and is huge.

To update the database, run the following commands:

```bash
python scripts/update_file_hashes_db.py -d -e -p
python scripts/update_file_signatures_db.py -d -e -p
```

### Script Arguments

| Script | Argument | Short | Long | Description |
|--------|----------|-------|------|-------------|
| Both | Download | `-d` | `--download` | Download new database from URL |
| Both | Extract | `-e` | `--extract` | Extract the database file |
| Both | Parse | `-p` | `--parse` | Parse CSV to SQLite database |
| Both | Remove files | `-r` | `--remove_files` | Remove the leftover files (if exists) (zip, csv) |
| update_file_hashes_db.py | Custom CSV | | `--csv` | Custom CSV file name (default: file_hashes.csv) |
| update_file_hashes_db.py | Custom ZIP | | `--zip` | Custom ZIP file name (default: file_hashes.zip) |
| update_file_hashes_db.py | Custom DB | | `--db` | Custom SQLite database file name (default: file_hashes.db) |

### Data formats

#### File hashes

The database is organized in a table named "file_hashes" with the following columns:

| sha256 | name |
|--------|------|
| 0e306925a2ce33cb034c072708b5c39e0e306925a2ce33cb034c072708b5c39e | RansomwareExample |

#### In-file signatures

The in-file signatures are formatted this way (in a JSON file):

```json
{
    "AABB??BB": "RansomwareExample" // Meaning, AABB??BB is the signature, and RansomwareExample is the name
}
```

### Note about the database

Because CalmAV has blocked the option to download the database using a script (they added a captcha), you will need to download the database manually from the following URL:

<https://database.clamav.net/main.cvd>

Also, you have to download [clamav](https://github.com/Cisco-Talos/clamav) to extract the database file using their sigtool.exe (**just download the _zip_ file, and extract it to a folder, and then paste the sigtool.exe path into the script.**)

## License

MIT
