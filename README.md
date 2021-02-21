# cve_manager
A python script that:

  a) parses NIST NVD CVEs, 
  b) prcoesses and exports them to CSV files, 
  c) creates a postgres database and imports all the data in it, and
  d) provides (basic) query capabilities for this CVEs database.

It requires Python 3 ("psycopg2" and "requests" python libraries)

Usage examples: 

- Download, parse and save in CSV files all CVEs from NIST NVD:
  ./cve_manager.py -d -p -csv
  
- Create a postgresql database to host the downloaded CVEs:
  ./cve_manager.py -u <myuser> host <hostname or IP> -db <database_name> -ow <new_owner of database> -cd

- Create the tables and views at the database:
  ./cve_manager.py -u <myuser> -host <hostname or IP> -db <database_name> -ct

- Import all data into the created database (requires the download, parse and sdtore as CSV files first, as explained above):
  ./cve_manager.py -u <myuser> -host <hostname or IP> -db <database_name> -idb -p

- Query for a specific CVE:
  ./cve_manager.py -u <myuser> -host <hostname or IP> -db <database_name> -cve 2019-2434
    
- Truncate the contents of all tables (required if you want to repeat the import process so as to update the data): 
  ./cve_manager.py -u <myuser> -host <hostname or IP> -db <database_name> -tr
  
- Delete the database (remove it completely):
  ./cve_manager.py -u <myuser> -host <hostname or IP> -db <database_name> -dd

Complete list of supported arguments:

  -h, --help            show this help message and exit
  
  -v, --version         show program's version number and exit
  
  -p, --parse           Process downloaded CVEs.
  
  -d, --download        Download CVEs.
  
  -y YEAR, --year YEAR  The year for which CVEs shall be downloaded (e.g. 2019)
  
  -csv, --cvs_files     Create CSVs files.
  
  -idb, --import_to_db  Import CVEs into a database.
  
  -i INPUT, --input INPUT
                        The directory where NVD json files will been downloaded, and the one from where they will be parsed
                        (default: nvd/)
                        
  -o RESULTS, --output RESULTS
                        The directory where the csv files will be stored (default: results/)
                        
  -u USER, --user USER  The user to connect to the database.
  
  -ow OWNER, --owner OWNER
                        The owner of the database (if different from the connected user).                     
                      
  -host HOST, --host HOST
                        The host or IP of the database server.
                        
  -db DATABASE, --database DATABASE
                        The name of the database.
                        
  -cd, --create_database
                        Create the database
                        
  -dd, --drop_database  Drop the database
  
  -ct, --create_tables  Create the tables of the database
  
  -tr, --truncate_cves_tables
                        Truncate the CVEs-related tables
                        
  -cve CVE, --cvs_number CVE
                        Print info for a CVE (CVSS score and other)
                   
Please check the CVE Manager pdf file for more capabilities, information, and screenshots.
