#!/usr/bin/env python3

import psycopg2
from psycopg2 import Error
from psycopg2 import connect
import sys
from psycopg2.extensions import ISOLATION_LEVEL_AUTOCOMMIT
import argparse
import os
from os import listdir
from os.path import isfile, join, exists
from os import makedirs
import zipfile
import json
import requests
import re
import io 
import csv
import getpass

##This is the Postgresql Database Schema##
query = '''
CREATE TABLE public.cvss (
    cve character(20) NOT NULL,
    attack_complexity_3 character(5),
    attack_vector_3 character(20),
    availability_impact_3 character(5),
    confidentiality_impact_3 character(5),
    integrity_impact_3 character(5),
    privileges_required_3 character(5),
    scope_3 character(10),
    user_interaction_3 character(10),
    vector_string_3 character(50),
    exploitability_score_3 real,
    impact_score_3 real,
    base_score_3 real,
    base_severity_3 character(10),
    access_complexity character(10),
    access_vector character(20),
    authentication character(10),
    availability_impact character(10),
    confidentiality_impact character(10),
    integrity_impact character(10),
    obtain_all_privileges boolean,
    obtain_other_privileges boolean,
    obtain_user_privileges boolean,
    user_interaction_required boolean,
    vector_string character(50),
    exploitability_score real,
    impact_score real,
    base_score real,
    severity character(10),
    description text,
    published_date date,
    last_modified_date date
);

CREATE TABLE public.cpe (
    cve character(20) NOT NULL,
    cpe23uri text,
    vulnerable character(5)
);

CREATE TABLE public.cve_problem (
    cve character(20) NOT NULL,
    problem text
);

CREATE TABLE public.cwe (
    cwe_id integer NOT NULL,
    name text,
    description text,
    extended_description text,
    modes_of_introduction text,
    common_consequences text,
    potential_mitigations text
);

CREATE VIEW public.cvss_vs_cpes AS
 SELECT cvss.cve,
    cvss.base_score_3,
    cvss.base_severity_3,
    cvss.base_score,
    cvss.severity,
    cpe.cpe23uri,
    cvss.description,
    cvss.published_date
   FROM public.cpe,
    public.cvss
  WHERE (cpe.cve = cvss.cve) AND cpe.vulnerable = 'True'::bpchar;
'''

## functions to manage the database (optional)
#def create_database(myuser,mypassword,myhost,database, owner):
def create_database(myuser,myhost,database, owner):
    con = None
    try:
        con = connect(dbname=database, user=myuser, host = myhost)
    except (Exception, psycopg2.DatabaseError) as error :
        mypassword = getpass.getpass('Password:')
    finally:
        try:
            con = connect(dbname='postgres', user=myuser, host = myhost, password=mypassword)
            dbname = database
            con.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)
            cur = con.cursor()
            cur.execute('CREATE DATABASE ' + dbname)
            print("Database",database,"was created.")
            cur = con.cursor()
            query = '''ALTER DATABASE '''+ database + ''' OWNER TO ''' + owner+''';'''
            print("Owner of the database changed to:",owner) 
            cur.execute(query)
            con.commit()
        except (Exception, psycopg2.DatabaseError) as error :
            print("Error while creating PostgreSQL Database", error)
        finally:
            #closing database connection.
            if(con):
                cur.close()
                con.close()
                print("PostgreSQL connection is closed")

#def drop_database(myuser,mypassword,myhost,database):
def drop_database(myuser,myhost,database):
    con = None
    try:
        con = connect(dbname=database, user=myuser, host = myhost)
    except (Exception, psycopg2.DatabaseError) as error :
        mypassword = getpass.getpass('Password:')
    finally:
        try:
            con = connect(dbname='postgres', user=myuser, host = myhost, password=mypassword)
            con.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)
            cur = con.cursor()
            cur.execute('DROP DATABASE ' + database)
            print("Database",database,"was dropped.")
        except (Exception, psycopg2.DatabaseError) as error :
            print ("Error while dropping PostgreSQL Database", error)
        finally:
            #closing database connection.
            if(con):
                cur.close()
                con.close()
                print("PostgreSQL connection is closed")

#def create_tables(myuser,mypassword,myhost,database):
def create_tables(myuser,myhost,database):
    con = None
    try:
        con = connect(dbname=database, user=myuser, host = myhost)
    except (Exception, psycopg2.DatabaseError) as error :
        mypassword = getpass.getpass('Password:')
    finally:
        try:
            con = connect(dbname=database, user=myuser, host = myhost, password=mypassword)
            cursor = con.cursor()
            create_tables_query = query
            cursor.execute(create_tables_query)
            con.commit()
            print("Tables and Views created successfully for database: "+database)
        except (Exception, psycopg2.DatabaseError) as error :
            print ("Error while creating PostgreSQL tables", error)
        finally:
            #closing database connection.
            if(con):
                cursor.close()
                con.close()
                print("PostgreSQL connection is closed")


#Download CVEs
def download_cves(directory,year):
    if not os.path.exists(directory):
        try:
            os.makedirs(directory)
        except OSError:
            print ('Error: Creating directory. ' + directory)
            exit(0)
        else:  
            print ("Successfully created the directory %s" % directory)
    else:
        print ("Directory %s already exists" % directory)
    try:
        r = requests.get('https://nvd.nist.gov/vuln/data-feeds#JSON_FEED')
    except Exception as e:
        print(e)
    if year:
        print("downloading ",year," only")
        filename = "nvdcve-1.1-"+year+".json.zip"
        print(filename)
        r_file = requests.get("https://nvd.nist.gov/feeds/json/cve/1.1/" + filename, stream=True)
        with open(directory +"/" + filename, 'wb') as f:
            for chunk in r_file:
                f.write(chunk)
    else:
        for filename in re.findall("nvdcve-1.1-[0-9]*\.json\.zip",r.text):
            print(filename)
            r_file = requests.get("https://nvd.nist.gov/feeds/json/cve/1.1/" + filename, stream=True)
            with open(directory +"/" + filename, 'wb') as f:
                for chunk in r_file:
                    f.write(chunk)

#processes the already downloaded in json format CVEs
#def process_cves(directory, results, csv_file, import_db,myuser,mypassword,myhost,database):
def process_cves(directory, results, csv_file, import_db,myuser,myhost,database):
    if csv_file:
        if not os.path.exists(results):
            try:
                os.makedirs(results)
            except OSError:
                print ('Error: Creating directory. ' + results)
                exit(0)
            else:  
                print ("Successfully created the directory %s" % results)
        else:
            print ("Directory %s already exists" % results)

        file_cve_related_problems = open(results+"cve_related_problems.csv","w",encoding='utf8',newline='')
        writer_cwe=csv.writer(file_cve_related_problems,delimiter="\t")

        file_cvss_score = open(results+"cve_cvss_scores.csv","w",encoding='utf8',newline='')
        writer_cvss=csv.writer(file_cvss_score ,delimiter="\t")

        file_cpes = open(results+"cve_cpes.csv","w",encoding='utf8',newline='')
        writer_cpe=csv.writer(file_cpes,delimiter="\t")

        writer_cpe.writerow(["CVE","cpe23Uri","Vulnerable"])
        writer_cwe.writerow(["CVE","Problem"])
        writer_cvss.writerow(["CVE","Attack Complexity","Attack Vector","Availability Impact","Confidentiality Impact","Integrity Impact","Privileges Required","Scope","UserInteraction","Vector String","Exploitability Score","Impact Score","base Score","base Severity","Access Complexity","Access Vector","Authentication","Availability Impact","Confidentiality Impact","Integrity Impact","Obtain All Privilege","Obtain Other Privilege","Obtain User Privilege","User Interaction Required","Vector String","Exploitability Score","impact Score","baseScore","severity","Description","Published Date","Last Modified Date"])
        ########################################################################################
        all_cves = []
        directory = directory + "/"
        files = [f for f in listdir(directory) if isfile(join(directory, f))]
        files.sort(reverse=True)
        for file in files:
            print("\nProcessing", file)
            archive = zipfile.ZipFile(join(directory, file), 'r')
            jsonfile = archive.open(archive.namelist()[0])
            cve_dict = json.loads(jsonfile.read())
            print("CVE_data_timestamp: " + str(cve_dict['CVE_data_timestamp']))
            print("CVE_data_version: " + str(cve_dict['CVE_data_version']))
            print("CVE_data_format: " + str(cve_dict['CVE_data_format']))
            print("CVE_data_number of CVEs: " + str(cve_dict['CVE_data_numberOfCVEs']))
            print("CVE_data_type: " + str(cve_dict['CVE_data_type']))
            all_cves = all_cves + cve_dict['CVE_Items']
            #print(json.dumps(cve_dict['CVE_Items'][0], sort_keys=True, indent=4, separators=(',', ': ')))
            jsonfile.close()
        cvssv_score=[]
        for cves in all_cves:
            cve = cves['cve']['CVE_data_meta']['ID']
            description = ""
            for descriptions in cves['cve']['description']['description_data']:
                description = description + descriptions['value']
            description = description.replace("\r"," ")
            description = description.replace("\n"," ")
            description = description.replace("\t"," ")
            try:
                writer_cvss.writerow([cve,cves['impact']['baseMetricV3']['cvssV3']['attackComplexity'],cves['impact']['baseMetricV3']['cvssV3']['attackVector'],cves['impact']['baseMetricV3']['cvssV3']['availabilityImpact'],cves['impact']['baseMetricV3']['cvssV3']['confidentialityImpact'],cves['impact']['baseMetricV3']['cvssV3']['integrityImpact'],cves['impact']['baseMetricV3']['cvssV3']['privilegesRequired'],cves['impact']['baseMetricV3']['cvssV3']['scope'],cves['impact']['baseMetricV3']['cvssV3']['userInteraction'],cves['impact']['baseMetricV3']['cvssV3']['vectorString'],str(cves['impact']['baseMetricV3']['exploitabilityScore']),str(cves['impact']['baseMetricV3']['impactScore']),str(cves['impact']['baseMetricV3']['cvssV3']['baseScore']),str(cves['impact']['baseMetricV3']['cvssV3']['baseSeverity']),cves['impact']['baseMetricV2']['cvssV2']['accessComplexity'],cves['impact']['baseMetricV2']['cvssV2']['accessVector'],cves['impact']['baseMetricV2']['cvssV2']['authentication'],cves['impact']['baseMetricV2']['cvssV2']['availabilityImpact'],cves['impact']['baseMetricV2']['cvssV2']['confidentialityImpact'],cves['impact']['baseMetricV2']['cvssV2']['integrityImpact'],str(cves['impact']['baseMetricV2']['obtainAllPrivilege']),str(cves['impact']['baseMetricV2']['obtainOtherPrivilege']),str(cves['impact']['baseMetricV2']['obtainUserPrivilege']),str(cves['impact']['baseMetricV2']['userInteractionRequired']),cves['impact']['baseMetricV2']['cvssV2']['vectorString'],str(cves['impact']['baseMetricV2']['exploitabilityScore']),str(cves['impact']['baseMetricV2']['impactScore']),str(cves['impact']['baseMetricV2']['cvssV2']['baseScore']),str(cves['impact']['baseMetricV2']['severity']),description,cves['publishedDate'],cves['lastModifiedDate']])
            except Exception as e:
                if str(e) == "'baseMetricV3'":
                    try:
                        writer_cvss.writerow([cve,None,None,None,None,None,None,None,None,None,None,None,None,None,cves['impact']['baseMetricV2']['cvssV2']['accessComplexity'],cves['impact']['baseMetricV2']['cvssV2']['accessVector'],cves['impact']['baseMetricV2']['cvssV2']['authentication'],cves['impact']['baseMetricV2']['cvssV2']['availabilityImpact'],cves['impact']['baseMetricV2']['cvssV2']['confidentialityImpact'],cves['impact']['baseMetricV2']['cvssV2']['integrityImpact'],str(cves['impact']['baseMetricV2']['obtainAllPrivilege']),str(cves['impact']['baseMetricV2']['obtainOtherPrivilege']),str(cves['impact']['baseMetricV2']['obtainUserPrivilege']),str(cves['impact']['baseMetricV2']['userInteractionRequired']),cves['impact']['baseMetricV2']['cvssV2']['vectorString'],str(cves['impact']['baseMetricV2']['exploitabilityScore']),str(cves['impact']['baseMetricV2']['impactScore']),str(cves['impact']['baseMetricV2']['cvssV2']['baseScore']),str(cves['impact']['baseMetricV2']['severity']),description,cves['publishedDate'],cves['lastModifiedDate']])
                    except Exception as e2:
                        if str(e2) == "'baseMetricV2'":
                            try:
                                writer_cvss.writerow([cve,None,None,None,None,None,None,None,None,None,None,None,None,None,None,None,None,None,None,None,None,None,None,None,None,None,None,None,None,description,cves['publishedDate'],cves['lastModifiedDate']])
                            except Exception as e3:
                                print("Error e3",e3)
                        elif str(e2) == "'userInteractionRequired'":
                            writer_cvss.writerow([cve,None,None,None,None,None,None,None,None,None,None,None,None,None,cves['impact']['baseMetricV2']['cvssV2']['accessComplexity'],cves['impact']['baseMetricV2']['cvssV2']['accessVector'],cves['impact']['baseMetricV2']['cvssV2']['authentication'],cves['impact']['baseMetricV2']['cvssV2']['availabilityImpact'],cves['impact']['baseMetricV2']['cvssV2']['confidentialityImpact'],cves['impact']['baseMetricV2']['cvssV2']['integrityImpact'],str(cves['impact']['baseMetricV2']['obtainAllPrivilege']),str(cves['impact']['baseMetricV2']['obtainOtherPrivilege']),str(cves['impact']['baseMetricV2']['obtainUserPrivilege']),None,cves['impact']['baseMetricV2']['cvssV2']['vectorString'],str(cves['impact']['baseMetricV2']['exploitabilityScore']),str(cves['impact']['baseMetricV2']['impactScore']),str(cves['impact']['baseMetricV2']['cvssV2']['baseScore']),str(cves['impact']['baseMetricV2']['severity']),description,cves['publishedDate'],cves['lastModifiedDate']])
                        else:
                            print("Error e2",e2)
                elif str(e) == "'baseMetricV2'":
                    writer_cvss.writerow([cve,cves['impact']['baseMetricV3']['cvssV3']['attackComplexity'],cves['impact']['baseMetricV3']['cvssV3']['attackVector'],cves['impact']['baseMetricV3']['cvssV3']['availabilityImpact'],cves['impact']['baseMetricV3']['cvssV3']['confidentialityImpact'],cves['impact']['baseMetricV3']['cvssV3']['integrityImpact'],cves['impact']['baseMetricV3']['cvssV3']['privilegesRequired'],cves['impact']['baseMetricV3']['cvssV3']['scope'],cves['impact']['baseMetricV3']['cvssV3']['userInteraction'],cves['impact']['baseMetricV3']['cvssV3']['vectorString'],str(cves['impact']['baseMetricV3']['exploitabilityScore']),str(cves['impact']['baseMetricV3']['impactScore']),str(cves['impact']['baseMetricV3']['cvssV3']['baseScore']),str(cves['impact']['baseMetricV3']['cvssV3']['baseSeverity']),None,None,None,None,None,None,None,None,None,None,None,None,None,None,None,description,cves['publishedDate'],cves['lastModifiedDate']])
                elif str(e) == "'userInteractionRequired'":
                    writer_cvss.writerow([cve,cves['impact']['baseMetricV3']['cvssV3']['attackComplexity'],cves['impact']['baseMetricV3']['cvssV3']['attackVector'],cves['impact']['baseMetricV3']['cvssV3']['availabilityImpact'],cves['impact']['baseMetricV3']['cvssV3']['confidentialityImpact'],cves['impact']['baseMetricV3']['cvssV3']['integrityImpact'],cves['impact']['baseMetricV3']['cvssV3']['privilegesRequired'],cves['impact']['baseMetricV3']['cvssV3']['scope'],cves['impact']['baseMetricV3']['cvssV3']['userInteraction'],cves['impact']['baseMetricV3']['cvssV3']['vectorString'],str(cves['impact']['baseMetricV3']['exploitabilityScore']),str(cves['impact']['baseMetricV3']['impactScore']),str(cves['impact']['baseMetricV3']['cvssV3']['baseScore']),str(cves['impact']['baseMetricV3']['cvssV3']['baseSeverity']),cves['impact']['baseMetricV2']['cvssV2']['accessComplexity'],cves['impact']['baseMetricV2']['cvssV2']['accessVector'],cves['impact']['baseMetricV2']['cvssV2']['authentication'],cves['impact']['baseMetricV2']['cvssV2']['availabilityImpact'],cves['impact']['baseMetricV2']['cvssV2']['confidentialityImpact'],cves['impact']['baseMetricV2']['cvssV2']['integrityImpact'],str(cves['impact']['baseMetricV2']['obtainAllPrivilege']),str(cves['impact']['baseMetricV2']['obtainOtherPrivilege']),str(cves['impact']['baseMetricV2']['obtainUserPrivilege']),None,cves['impact']['baseMetricV2']['cvssV2']['vectorString'],str(cves['impact']['baseMetricV2']['exploitabilityScore']),str(cves['impact']['baseMetricV2']['impactScore']),str(cves['impact']['baseMetricV2']['cvssV2']['baseScore']),str(cves['impact']['baseMetricV2']['severity']),description,cves['publishedDate'],cves['lastModifiedDate']])
                else:
                    print("Error e",e)

            for problem_type in cves['cve']['problemtype']['problemtype_data']:
                for descr in problem_type['description']:
                    problem =  descr['value']
                    if csv_file:
                        writer_cwe.writerow([cve,problem])
            try:
                cpe_list_length=len(cves['configurations']['nodes'])
                if (cpe_list_length !=0):
                    for i in range(0,cpe_list_length):
                        if 'children' in cves['configurations']['nodes'][i]:
                            cpe_child_list_length=len(cves['configurations']['nodes'][i]['children'])
                            if (cpe_child_list_length !=0):
                                for j in range(0,cpe_child_list_length):
                                    if('cpe_match' in cves['configurations']['nodes'][i]['children'][j]):
                                        cpes = cves['configurations']['nodes'][i]['children'][j]['cpe_match']
                                        for cpe in cpes:
                                            if csv_file:
                                                if 'cpe23Uri' in cpe:
                                                    writer_cpe.writerow([cve,cpe['cpe23Uri'],str(cpe['vulnerable'])])
                        else:
                            if('cpe_match' in cves['configurations']['nodes'][i]):
                                cpes = cves['configurations']['nodes'][i]['cpe_match']
                                for cpe in cpes:
                                    if csv_file:
                                        if 'cpe23Uri' in cpe:
                                            writer_cpe.writerow([cve,cpe['cpe23Uri'],str(cpe['vulnerable'])])
                            else:
                                cpe_inner_list_length=len(cves['configurations']['nodes'])
                                if (cpe_inner_list_length!=0):
                                    for k in range(0,cpe_inner_list_length):
                                        if('cpe_match' in cves['configurations']['nodes'][i]):
                                            cpes = cves['configurations']['nodes'][i]['cpe_match']
                                            for cpe in cpes:
                                                if csv_file:
                                                    if 'cpe23Uri' in cpe:
                                                        writer_cpe.writerow([cve,cpe['cpe23Uri'],str(cpe['vulnerable'])])
            except Exception as e:
                print(str(e),cves['configurations']) #check it
        file_cve_related_problems.close()
        file_cvss_score.close()
        file_cpes.close()
    if import_db:
        print('Connecting to the PostgreSQL database...')
        try:
            con = connect(dbname=database, user=myuser, host = myhost)
        except (Exception, psycopg2.DatabaseError) as error :
            mypassword = getpass.getpass('Password:')
        finally:
            try:
                conn = psycopg2.connect("dbname='"+database+"' user='"+myuser+"' host='"+myhost+"' password='"+mypassword+"'")
            except psycopg2.Error as e:
                print( "I am unable to connect to the database. Error:",e)
                print( "Exiting")
                sys.exit(1)
            cur = conn.cursor()
            filename = results+"cve_cvss_scores.csv"
            with open(filename, 'r',encoding='utf8') as f:
                print("importing CVSS")
                filedata = f.read()
                filedata = filedata.replace("\\","\\\\")
                output = io.StringIO()
                output.write(filedata)
                output.seek(0)
                output.readline()
                cur.copy_from(output, 'cvss', sep='\t', null="")
            conn.commit()
            f.close()
            filename = results+"cve_related_problems.csv"
            with open(filename, 'r') as f:
                print("importing CVE-related problems")
                f.readline()
                cur.copy_from(f, 'cve_problem', sep='\t',columns=('cve', 'problem'))
            conn.commit()
            f.close()
            filename = results+"cve_cpes.csv"
            with open(filename, 'r') as f:
                print("importing CVEs vs CPEs")
                f.readline()
                cur.copy_from(f, 'cpe', sep='\t',columns=('cve','cpe23uri','vulnerable'))
            conn.commit()
            f.close()

#def truncate_database(myuser,mypassword,myhost,database):
def truncate_database(myuser,myhost,database):
    con = None
    mypassword = None
    try:
        con = connect(dbname=database, user=myuser, host = myhost)
    except (Exception, psycopg2.DatabaseError) as error :
        mypassword = getpass.getpass('Password:')
    finally:
      try:
        con = connect(dbname=database, user=myuser, host = myhost, password=mypassword)
        con.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)
        cur = con.cursor()
        print("Truncating CVEs tables")
        cur.execute("Truncate cpe, cve_problem, cvss;")
        con.commit()
      except (Exception, psycopg2.DatabaseError) as error :
        print("Error while Truncating PostgreSQL Database", error)
      finally:
        if(con):
            cur.close()
            con.close()
            print("PostgreSQL connection is closed")

#def execute_query(myuser,mypassword,myhost,database,cve,score,date,csv_on,output_folder):
def execute_query(myuser,myhost,database,cve,score,date,csv_on,output_folder):
    con = None
    mypassword = None
    try:
        con = connect(dbname=database, user=myuser, host = myhost)
    except (Exception, psycopg2.DatabaseError) as error :
        mypassword = getpass.getpass('Password:')
    finally:
      try:
        con = connect(dbname=database, user=myuser, host = myhost, password=mypassword)
        cur = con.cursor()
        print("Executing query\r\n")
        if cve:
            cur.execute("SELECT cve, vector_string_3, base_score_3, base_severity_3, vector_string, base_score, severity, description, published_date, last_modified_date FROM cvss WHERE cve LIKE '%"+cve+"%'")
            selected_cve = cur.fetchone()
            print("CVE:\t\t\t",selected_cve[0])
            print("CVSSv3.x Attack vector: ",selected_cve[1])
            print("CVSSv3.x Base Score:\t",selected_cve[2],selected_cve[3])
            print("CVSSv2.x Attack vector: ",selected_cve[4])
            print("CVSSv2.x Base Score:\t",selected_cve[5],selected_cve[6])
            print("Description:")
            print(selected_cve[7])
            print("\r\nPubished Date:\t\t",selected_cve[8])
            print("Last Modified Date:\t",selected_cve[9])
            cur.execute("SELECT problem FROM cve_problem WHERE cve LIKE '%"+cve+"%'")
            selected_cve = cur.fetchall()
            print("\r\nRelated Common Weakness Enumerations (CWE)")
            print("-------------------------------------------")
            for i in selected_cve:
                cwe=i[0].lstrip('CWE-')
                if cwe.isdigit():
                    cur.execute("SELECT name FROM cwe WHERE cwe_id = "+cwe)
                    selected_cve2 = cur.fetchone()
                    if (selected_cve2): 
                            print(i[0], selected_cve2[0])
                    else:   
                            print(i[0])
            cur.execute("SELECT cpe23uri FROM cpe WHERE cve LIKE '%"+cve+"%' AND vulnerable='True'")
            selected_cve = cur.fetchall()
            print("\r\nRelated Common Platform Enumerations (CPE)")
            print("-------------------------------------------")
            for i in selected_cve:
                print(i[0])
        elif score or date:
            if csv_on:
                cves=[]
            if date:
                cur.execute("SELECT cve, base_score_3,  vector_string_3, base_score, vector_string, published_date FROM cvss WHERE (base_score_3 >= "+score+"OR base_score >= "+ score+") AND (published_date >= '"+date+"'::date)")
                selected_cves = cur.fetchall()
                print("CVE \t\tCVSSv3.x Score CVSSv3.x Vector String \t\t\tCVSSv2 Score CVSSv2 Vector String\t\t\t Published Date")
                for r in selected_cves:
                    print(r[0],r[1],r[2],r[3],r[4],r[5])
                    if csv_on:
                        cves.append(r)
            else:
                cur.execute("SELECT cve, base_score_3, vector_string_3, base_score, vector_string, published_date FROM cvss WHERE base_score_3 >= "+score+"OR base_score >= "+ score)
                selected_cves = cur.fetchall()
                print("CVE \t\tCVSSv3.x Score CVSSv3.x Vector String \t\t\tCVSSv2 Score CVSSv2 Vector String")
                for r in selected_cves:
                    print(r[0],r[1],r[2],r[3],r[4])
                    if csv_on:
                        cves.append(r)
      except (Exception, psycopg2.DatabaseError) as error :
        print ("Error while Querying Database", error)
      finally:
        if(con):
            cur.close()
            con.close()
            print("\r\nPostgreSQL connection is closed")
        if csv_on:
            if not os.path.exists(output_folder):
                try:
                    os.makedirs(output_folder)
                except OSError:
                    print ('Error: Creating directory. ' + output_folder)
                    exit(0)
                else:  
                    print ("Successfully created the directory %s" % output_folder)
            else:
                print ("Directory %s already exists" % output_folder)
            file_cve = open(output_folder+"CVEs_score"+score+"_"+str(date)+".csv","w")
            writer_cve=csv.writer(file_cve,delimiter=",")
            writer_cve.writerow(["CVE","CVSSv3 Score","CVSSv3 Vector String","CVSSv2 Score","CVSSv2 Vector String","Published Date"])
            for r in cves:
                writer_cve.writerow([r[0],r[1],r[2],r[3],r[4],r[5]])
            file_cve.close()

#def execute_query_cpe(myuser,mypassword,myhost,database,cpe,score,date,csv_on,output_folder):
def execute_query_cpe(myuser,myhost,database,cpe,score,date,csv_on,output_folder):
    con = None
    mypassword = None
    if csv_on:
        cpes=[]
    try:
        con = connect(dbname=database, user=myuser, host = myhost)
        print("OK")
        exit(0)
    except (Exception, psycopg2.DatabaseError) as error :
        mypassword = getpass.getpass('Password:')
    finally:
      try:
        con = connect(dbname=database, user=myuser, host = myhost, password=mypassword)
        cur = con.cursor()
        print("Executing query\r\n")
        if date:
            cur.execute("SELECT cpe23uri, cve, base_score_3, base_score, published_date FROM cvss_vs_cpes WHERE cpe23uri LIKE '%"+cpe+"%' AND (base_score_3 >= "+score+"OR base_score >= "+ score+") AND (published_date >= '"+date+"'::date)")
            selected_cpe = cur.fetchall()
            print("CPE\t\t\t\t\t\t\tCVE\t\tCVSSv3.x CVSSv2\t Published Date")
            for r in selected_cpe:
                print(r[0],r[1],r[2],"\t",r[3],"\t",r[4])
                if csv_on:
                    cpes.append(r)
        else:
            cur.execute("SELECT cpe23uri, cve, base_score_3, base_score,published_date FROM cvss_vs_cpes WHERE cpe23uri LIKE '%"+cpe+"%' AND (base_score_3 >= "+score+"OR base_score >= "+ score+")")
            selected_cpe = cur.fetchall()
            print("CPE\t\t\t\t\t\t\tCVE\t\tCVSSv3.x CVSSv2")
            for r in selected_cpe:
                print(r[0],r[1],r[2],"\t",r[3])
                if csv_on:
                    cpes.append(r)
      except (Exception, psycopg2.DatabaseError) as error :
        print ("Error while Querying Database", error)
      finally:
        if(con):
            cur.close()
            con.close()
            print("\r\nPostgreSQL connection is closed")
        if csv_on:
            if not os.path.exists(output_folder):
                try:
                    os.makedirs(output_folder)
                except OSError:
                    print ('Error: Creating directory. ' + output_folder)
                    exit(0)
                else:  
                    print ("Successfully created the directory %s" % output_folder)
            else:
                print ("Directory %s already exists" % output_folder)
            file_cpe = open(output_folder+cpe+"_"+score+"_"+str(date)+".csv","w")
            writer_cpe=csv.writer(file_cpe,delimiter=",")
            writer_cpe.writerow(["CPE","CVE","CVSSv3 Score","CVSSv2 Score","Published Date"])
            for r in cpes:
                writer_cpe.writerow([r[0],r[1],r[2],r[3],r[4]])
            file_cpe.close()

#def execute_query_cwe(myuser,mypassword,myhost,database,cwe):
def execute_query_cwe(myuser,myhost,database,cwe):
    con = None
    mypassword = None
    try:
        con = connect(dbname=database, user=myuser, host = myhost)
    except (Exception, psycopg2.DatabaseError) as error :
        mypassword = getpass.getpass('Password:')
    finally:
      try:
        con = connect(dbname=database, user=myuser, host = myhost, password=mypassword)
        cur = con.cursor()
        print("Executing query\r\n")
        cur.execute("SELECT * FROM cwe WHERE cwe_id = "+cwe)
        selected_cwe = cur.fetchone()
        if selected_cwe:
            print("CWE-"+str(selected_cwe[0]))
            print("========")
            print(selected_cwe[1])
            if(selected_cwe[2]):
                print(selected_cwe[2])
            if(selected_cwe[3]):
                print(selected_cwe[3])
            if(selected_cwe[4]):
                print("\r\nModes of Introduction")
                print("--------------------")
                print(selected_cwe[4])
            if(selected_cwe[5]):
                print("\r\nCommon Consequences")
                print("--------------------")
                print(selected_cwe[5])
            if(selected_cwe[6]):
                print("\r\nPotential Mitigations")
                print("--------------------")
                print(selected_cwe[6])
        else:
            print("CWE-"+cwe,"not found")
      except (Exception, psycopg2.DatabaseError) as error :
        print ("Error while Querying Database")
        #print ("Error while Querying Database", error)
        print("Hint: Use just the number of teh CWE you are looking for, e.g.: 169")
      finally:
        if(con):
            cur.close()
            con.close()
            print("\r\nPostgreSQL connection is closed")

#def cwe(myuser,mypassword,myhost,database,filename):
def cwe(myuser,myhost,database,filename):
    con = None
    mypassword = None
    try:
        con = connect(dbname=database, user=myuser, host = myhost)
    except (Exception, psycopg2.DatabaseError) as error :
        mypassword = getpass.getpass('Password:')
    finally:
      try:
        con = connect(dbname=database, user=myuser, host = myhost, password=mypassword)
        cur = con.cursor()
        with open(filename, 'r') as f:
            print("importing cwe")
            reader = csv.reader(f)
            header_row = next(reader)
            cwe = io.StringIO()
            writer_cwe=csv.writer(cwe)
            writer_cwe.writerow(["cwe_id","name","description","extended_decription","modes_of_introduction","common_consequences","potential_mitigations"])
            for row in reader:
                writer_cwe.writerow([row[0],row[1],row[4],row[5],row[11],row[14],row[16]])
            cwe.seek(0)
            cwe.readline()
            cur.copy_expert("""COPY cwe(cwe_id, name, description, extended_description, modes_of_introduction, common_consequences, potential_mitigations) FROM STDIN WITH (FORMAT CSV)""", cwe)
            con.commit()
      except (Exception, psycopg2.DatabaseError) as error :
        print ("Error while Querying Database", error)
      finally:
        if(con):
            cur.close()
            con.close()
            print("PostgreSQL connection is closed")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='CVEs Manager.')
    parser.add_argument('-p', '--parse',  action="store_true", dest="process", default=False, help="Process downloaded CVEs.")
    parser.add_argument('-d', '--download',  action="store_true", dest="download", default=False, help="Download CVEs.")
    parser.add_argument('-y', '--year',  action="store", dest="year", default=False, help="The year for which CVEs shall be downloaded (e.g. 2019)")
    parser.add_argument('-csv', '--csv_files',  action="store_true", dest="csv_file", default=False, help="Create CSVs files.")
    parser.add_argument('-icwe', '--import_cwe',  action="store", dest="icwe", default=None, help="Import CWE from the provided filename into the database.")
    parser.add_argument('-idb', '--import_to_db',  action="store_true", dest="idb", default=False, help="Import CVEs into a database.")
    parser.add_argument('-i', '--input', action="store", default = 'nvd/', dest="input", help="The directory where NVD json files will been downloaded, and the one from where they will be parsed (default: nvd/")
    parser.add_argument('-o', '--output', action="store", default = 'results/', dest="results", help="The directory where the csv files will be stored (default: results/")
    parser.add_argument('-u', '--user',  action="store", dest="user", default="postgres", help="The user to connect to the database.")
    parser.add_argument('-ow', '--owner',  action="store", dest="owner", default=None, help="The owner of the database (if different from the connected user).")
    #parser.add_argument('-ps', '--password',  action="store", dest="password", default="", help="The password to connect to the database.")
    parser.add_argument('-host', '--host',  action="store", dest="host", default=None, help="The hostname or IP for which you want to list the applicable vulnerabilities")
    parser.add_argument('-server', '--server',  action="store", dest="server", default="localhost", help="The hostname or IP of the database server.")
    parser.add_argument('-db', '--database',  action="store", dest="database", default="postgres", help="The name of the database.")
    parser.add_argument('-cd', '--create_database',  action="store_true", dest="cd", default=False, help="Create the database")
    parser.add_argument('-dd', '--drop_database',  action="store_true", dest="dd", default=False, help="Drop the database")
    parser.add_argument('-ct', '--create_tables',  action="store_true", dest="ct", default=False, help="Create the tables of the database")
    parser.add_argument('-tr', '--truncate_cves_tables',  action="store_true", dest="tr", default=False, help="Truncate the CVEs-related tables")
    parser.add_argument('-cve', '--cve_number',  action="store", dest="cve", default=None, help="Print info for a CVE (CVSS score and other)")
    parser.add_argument('-cpe', '--cpe',  action="store", dest="cpe", default=None, help="List all the CVEs for the selected CPE(s)")
    parser.add_argument('-cwe', '--cwe',  action="store", dest="cwe", default=None, help="Provide info for the requested CWE)")
    parser.add_argument('-sc', '--score',  action="store", dest="score", default=0.0, help="Use base score of a CVE as a selection criterion")
    parser.add_argument('-dt', '--date',  action="store", dest="date", default=False, help="Use publication date of a CVE as a selection criterion")
    values = parser.parse_args()

    if not values.owner:
        values.owner=values.user
    if values.dd:
        print("Dropping the database")
        #drop_database(values.user,values.password,values.server,values.database)
        drop_database(values.user,values.server,values.database)
    if values.cd:
        print("Creating the database")
        #create_database(values.user,values.password,values.server,values.database,values.owner)
        create_database(values.user,values.server,values.database,values.owner)
    if values.ct:
        print("Creating the necessary schema of the database")
        #create_tables(values.user,values.password,values.server,values.database)
        create_tables(values.user,values.server,values.database)
    if values.download:
        print("Downloading NIST NVD")
        download_cves(values.input,values.year)
    if values.tr: 
        print("Truncating NIST NVD imported data")
        #truncate_database(values.user,values.password,values.server,values.database)
        truncate_database(values.user,values.server,values.database)
    if values.process:
        print("Processing downloaded data")
        #process_cves(values.input, values.results, values.csv_file, values.idb,values.user,values.password,values.server,values.database)
        process_cves(values.input, values.results, values.csv_file, values.idb,values.user,values.server,values.database)
    if values.icwe:
        print("Importing CWE data")
        #cwe(values.user,values.password,values.host,values.database,values.icwe)
        cwe(values.user,values.host,values.database,values.icwe)
    if values.cpe:
        print("CPE queries")
        #execute_query_cpe(values.user,values.password,values.host,values.database,values.cpe,str(values.score),values.date,values.csv_file,values.results)
        execute_query_cpe(values.user,values.host,values.database,values.cpe,str(values.score),values.date,values.csv_file,values.results)
    elif values.cwe:
        print("CWE queries")
        #execute_query_cwe(values.user,values.password,values.host,values.database,values.cwe)
        execute_query_cwe(values.user,values.host,values.database,values.cwe)
    elif values.cve or float(values.score) > 0.0: 
        print("CVE queries")
        #execute_query(values.user,values.password,values.host,values.database,values.cve,values.score,values.date,values.csv_file,values.results)
        execute_query(values.user,values.host,values.database,values.cve,values.score,values.date,values.csv_file,values.results)
    elif not values.download and not values.process and not values.cd and not values.ct and not values.dd and not values.tr and not values.icwe:
        print("Choose an option (check --help)")
