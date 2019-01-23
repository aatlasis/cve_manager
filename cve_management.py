#!/usr/bin/python
#check out the ~/.pgpass file to store password securely and not in the source code (http://www.postgresql.org/docs/9.2/static/libpq-pgpass.html). libpq, the postgresql client librairy, check for this file to get proper login information.

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
import argparse
import zipfile
import json
import requests
import re
import StringIO

##This is the Postgresql Database Schema##
query = '''
--
-- Name: affected_products; Type: TABLE; Schema: public; Owner: atlas
--
CREATE TABLE public.affected_products (
    cve character(20) NOT NULL,
    vendor_name text,
    product_name text,
    version_value text
);
--ALTER TABLE public.affected_products OWNER TO atlas;

--
-- Name: cvss; Type: TABLE; Schema: public; Owner: atlas
--
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
--ALTER TABLE public.cvss OWNER TO atlas;

--
-- Name: cvss_vs_products; Type: VIEW; Schema: public; Owner: atlas
--
CREATE VIEW public.cvss_vs_products WITH (security_barrier='false') AS
 SELECT cvss.cve,
    cvss.base_score_3,
    cvss.base_severity_3,
    cvss.base_score,
    cvss.severity,
    cvss.published_date,
    affected_products.vendor_name,
    affected_products.product_name,
    affected_products.version_value,
    cvss.description
   FROM public.affected_products,
    public.cvss
  WHERE (affected_products.cve = cvss.cve);
--ALTER TABLE public.cvss_vs_products OWNER TO atlas;

--
-- Name: count_affected_products_critical; Type: VIEW; Schema: public; Owner: atlas
--
CREATE VIEW public.count_affected_products_critical AS
 SELECT cvss_vs_products.product_name,
    count(cvss_vs_products.product_name) AS count
   FROM public.cvss_vs_products
  WHERE (cvss_vs_products.base_score_3 > (8.9)::double precision)
  GROUP BY cvss_vs_products.product_name
  ORDER BY (count(cvss_vs_products.product_name)) DESC;
--ALTER TABLE public.count_affected_products_critical OWNER TO atlas;

--
-- Name: count_products_per_severity; Type: VIEW; Schema: public; Owner: atlas
--
CREATE VIEW public.count_products_per_severity AS
 SELECT cvss_vs_products.product_name,
    cvss_vs_products.base_severity_3,
    count(*) AS count
   FROM public.cvss_vs_products
  GROUP BY cvss_vs_products.product_name, cvss_vs_products.base_severity_3;
--ALTER TABLE public.count_products_per_severity OWNER TO atlas;

--
-- Name: cpe; Type: TABLE; Schema: public; Owner: atlas
--
CREATE TABLE public.cpe (
    cve character(20) NOT NULL,
    cpe22uri text,
    cpe23uri text,
    vulnerable character(5)
);
--ALTER TABLE public.cpe OWNER TO atlas;

--
-- Name: critical_cves; Type: VIEW; Schema: public; Owner: atlas
--
CREATE VIEW public.critical_cves WITH (security_barrier='false') AS
 SELECT cvss.cve,
    cvss.base_score_3,
    cvss.base_severity_3,
    cvss.base_score,
    cvss.severity,
    affected_products.vendor_name,
    affected_products.product_name,
    affected_products.version_value,
    cvss.description
   FROM public.affected_products,
    public.cvss
  WHERE ((affected_products.cve = cvss.cve) AND ((cvss.base_severity_3 = 'CRITICAL'::bpchar) OR (cvss.severity = 'CRITICAL'::bpchar)));
--ALTER TABLE public.critical_cves OWNER TO atlas;

--
-- Name: cve_problem; Type: TABLE; Schema: public; Owner: atlas
--
CREATE TABLE public.cve_problem (
    cve character(20) NOT NULL,
    problem text
);
--ALTER TABLE public.cve_problem OWNER TO atlas;

--
-- Name: cvss_vs_cpes; Type: VIEW; Schema: public; Owner: atlas
--
CREATE VIEW public.cvss_vs_cpes AS
 SELECT cvss.cve,
    cvss.base_score_3,
    cvss.base_severity_3,
    cvss.base_score,
    cvss.severity,
    cpe.cpe23uri,
    cvss.description
   FROM public.cpe,
    public.cvss
  WHERE (cpe.cve = cvss.cve);
--ALTER TABLE public.cvss_vs_cpes OWNER TO atlas;
'''

def create_database(myuser,mypassword,myhost,database, owner):
    con = None
    try:
        con = connect(dbname='postgres', user=myuser, host = myhost, password=mypassword)
        dbname = database
        con.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)
        cur = con.cursor()
        cur.execute('CREATE DATABASE ' + dbname)
        print "Database",database,"was created."
        cur = con.cursor()
        query = '''ALTER DATABASE '''+ database + ''' OWNER TO ''' + owner+''';'''
        print "Owner of the database changed to:",owner 
        cur.execute(query)
        con.commit()
    except (Exception, psycopg2.DatabaseError) as error :
        print ("Error while creating PostgreSQL Database", error)
    finally:
        #closing database connection.
        if(con):
            cur.close()
            con.close()
            print("PostgreSQL connection is closed")

def drop_database(myuser,mypassword,myhost,database):
    con = None
    try:
        con = connect(dbname='postgres', user=myuser, host = myhost, password=mypassword)
        con.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)
        cur = con.cursor()
        cur.execute('DROP DATABASE ' + database)
        print "Database",database,"was dropped."
    except (Exception, psycopg2.DatabaseError) as error :
        print ("Error while dropping PostgreSQL Database", error)
    finally:
        #closing database connection.
        if(con):
            cur.close()
            con.close()
            print("PostgreSQL connection is closed")

def create_tables(myuser,mypassword,myhost,database):
    try:
        connection = None
        connection = connect(dbname=database, user=myuser, host = myhost, password=mypassword)
        cursor = connection.cursor()
        create_tables_query = query

        cursor.execute(create_tables_query)
        connection.commit()
        print("Tables and Views created successfully for database: "+database)
    except (Exception, psycopg2.DatabaseError) as error :
        print ("Error while creating PostgreSQL tables", error)
    finally:
        #closing database connection.
        if(connection):
            cursor.close()
            connection.close()
            print("PostgreSQL connection is closed")

def download_cves(directory):
    if not os.path.exists(directory):
        try:
            os.makedirs(directory)
            #os.mkdir(directory)
        except OSError:
            print ('Error: Creating directory. ' + directory)
            exit(0)
        else:  
            print ("Successfully created the directory %s" % directory)
    else:
        print ("Directory %s already exists" % directory)
    r = requests.get('https://nvd.nist.gov/vuln/data-feeds#JSON_FEED')
    for filename in re.findall("nvdcve-1.0-[0-9]*\.json\.zip",r.text):
        print(filename)
        r_file = requests.get("https://static.nvd.nist.gov/feeds/json/cve/1.0/" + filename, stream=True)
        with open(directory +"/" + filename, 'wb') as f:
            for chunk in r_file:
                f.write(chunk)

def process_cves(directory, results, csv, import_db,myuser,mypassword,myhost,database):
    if csv:
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
        file_products = open(results+"cve_affected_produts.csv","w")
        file_cve_related_problems = open(results+"cve_related_problems.csv","w")
        file_cvss_score = open(results+"cve_cvss_scores.csv","w")
        file_cpes = open(results+"cve_cpes.csv","w")
        file_products.write("CVE\tVendor name\tProduct name\tVersion_value\n")
        file_cve_related_problems.write("CVE\tProblem\n")
        file_cpes.write("CVE\tcpe22Uri\tcpe23Uri\tVulnerable\n")
        file_cvss_score.write("CVE\tAttack Complexity\tAttack Vector\tAvailability Impact\tConfidentiality Impact\tIntegrity Impact\tPrivileges Required\tScope\tUserInteraction\tVector String\tExploitability Score\tImpact Score\tbase Score\tbase Severity\tAccess Complexity\tAccess Vector\tAuthentication\tAvailability Impact\tConfidentiality Impact\tIntegrityImpact\tObtain All Privilege\tobtain Other Privilege\tobtain User Privilege\tuser Interaction Required\tvector String\tExploitability Score\timpact Score\tbaseScore\tseverity\tDescription\tPublished Date\tLast Modified Date\n")
        ########################################################################################
        all_cves = []
        directory = directory + "/"
        files = [f for f in listdir(directory) if isfile(join(directory, f))]
        files.sort(reverse=True)
        for file in files:
            print "\nProcessing", file
            archive = zipfile.ZipFile(join(directory, file), 'r')
            jsonfile = archive.open(archive.namelist()[0])
            cve_dict = json.loads(jsonfile.read())
            print("CVE_data_timestamp: " + str(cve_dict['CVE_data_timestamp']))
            print("CVE_data_version: " + str(cve_dict['CVE_data_version']))
            print("CVE_data_format: " + str(cve_dict['CVE_data_format']))
            print("CVE_data_numberOfCVEs: " + str(cve_dict['CVE_data_numberOfCVEs']))
            print("CVE_data_type: " + str(cve_dict['CVE_data_type']))
            all_cves = all_cves + cve_dict['CVE_Items']
            #print(json.dumps(cve_dict['CVE_Items'][0], sort_keys=True, indent=4, separators=(',', ': ')))
            jsonfile.close()
        cvssv_score=[]
        cve_realated_problem=[]
        for cves in all_cves:
            cve = cves['cve']['CVE_data_meta']['ID']
            try:
                cpes = cves['configurations']['nodes'][0]['cpe_match']
                for cpe in cpes:
                    if csv:
                        if 'cpe22Uri' in cpe:
                            file_cpes.write(cve+"\t"+cpe['cpe22Uri'].replace('cpe:/o:','')+"\t"+cpe['cpe23Uri'].replace('cpe:2.3:o:','')+"\t"+str(cpe['vulnerable'])+"\n")
                        else:
                            file_cpes.write(cve+"\t"+"\t"+cpe['cpe23Uri'].replace('cpe:2.3:o:','')+"\t"+str(cpe['vulnerable'])+"\n")
            except Exception, e:
                continue
                print str(e) ##check it
            for vendor in cves['cve']['affects']['vendor']['vendor_data']:
                try:
                    vendor_name = vendor['vendor_name']
                except:
                    vendor_name = ""
                for products in vendor['product']['product_data']:
                    product_name = products['product_name']
                    for version in products['version']['version_data']:
                        version_value = version['version_value']
                        if csv:
                            file_products.write(cve+"\t"+vendor_name+"\t"+product_name+"\t"+version_value+"\n")
            for problem_type in cves['cve']['problemtype']['problemtype_data']:
                for descr in problem_type['description']:
                    problem =  descr['value']
                    if csv:
                        file_cve_related_problems.write(cve+"\t"+problem+"\n")
            description = ""
            for descriptions in cves['cve']['description']['description_data']:
                description = description + descriptions['value']
            if description.find("** REJECT **"):
                description = description.replace('\r\n', ' ')
                description = description.replace('\n', ' ')
                description = description.replace('\t', ' ')
                separator = "\t"
                cvssv3 = ""
                cvssv2 = ""
                cvssv3_missing=False
                cvssv2_missing=False
                try:
                    cvssv3 = separator.join([cves['impact']['baseMetricV3']['cvssV3']['attackComplexity'],cves['impact']['baseMetricV3']['cvssV3']['attackVector'],cves['impact']['baseMetricV3']['cvssV3']['availabilityImpact'],cves['impact']['baseMetricV3']['cvssV3']['confidentialityImpact'],cves['impact']['baseMetricV3']['cvssV3']['integrityImpact'],cves['impact']['baseMetricV3']['cvssV3']['privilegesRequired'],cves['impact']['baseMetricV3']['cvssV3']['scope'],cves['impact']['baseMetricV3']['cvssV3']['userInteraction'],cves['impact']['baseMetricV3']['cvssV3']['vectorString'],str(cves['impact']['baseMetricV3']['exploitabilityScore']),str(cves['impact']['baseMetricV3']['impactScore']),str(cves['impact']['baseMetricV3']['cvssV3']['baseScore']),str(cves['impact']['baseMetricV3']['cvssV3']['baseSeverity'])])
                except Exception, e:
                    if str(e) == "'baseMetricV3'":
                        cvssv3_missing=True
                        cvssv3 = separator.join(["","","","","","","","","","","","",""])
                    else:
                        print str(e)
                try:
                    cvssv2 = separator.join([cves['impact']['baseMetricV2']['cvssV2']['accessComplexity'],cves['impact']['baseMetricV2']['cvssV2']['accessVector'],cves['impact']['baseMetricV2']['cvssV2']['authentication'],cves['impact']['baseMetricV2']['cvssV2']['availabilityImpact'],cves['impact']['baseMetricV2']['cvssV2']['confidentialityImpact'],cves['impact']['baseMetricV2']['cvssV2']['integrityImpact'],str(cves['impact']['baseMetricV2']['obtainAllPrivilege']),str(cves['impact']['baseMetricV2']['obtainOtherPrivilege']),str(cves['impact']['baseMetricV2']['obtainUserPrivilege']),str(cves['impact']['baseMetricV2']['userInteractionRequired']),cves['impact']['baseMetricV2']['cvssV2']['vectorString'],str(cves['impact']['baseMetricV2']['exploitabilityScore']),str(cves['impact']['baseMetricV2']['impactScore']),str(cves['impact']['baseMetricV2']['cvssV2']['baseScore']),str(cves['impact']['baseMetricV2']['severity'])])
                except Exception, e:
                    if str(e) == "'baseMetricV2'":
                        cvssv2 = separator.join(["","","","","","","","","","","","",""])
                        cvssv2_missing=True
                    elif str(e) == "'userInteractionRequired'":
                        cvssv2 = separator.join([cves['impact']['baseMetricV2']['cvssV2']['accessComplexity'],cves['impact']['baseMetricV2']['cvssV2']['accessVector'],cves['impact']['baseMetricV2']['cvssV2']['authentication'],cves['impact']['baseMetricV2']['cvssV2']['availabilityImpact'],cves['impact']['baseMetricV2']['cvssV2']['confidentialityImpact'],cves['impact']['baseMetricV2']['cvssV2']['integrityImpact'],str(cves['impact']['baseMetricV2']['obtainAllPrivilege']),str(cves['impact']['baseMetricV2']['obtainOtherPrivilege']),str(cves['impact']['baseMetricV2']['obtainUserPrivilege']),"",cves['impact']['baseMetricV2']['cvssV2']['vectorString'],str(cves['impact']['baseMetricV2']['exploitabilityScore']),str(cves['impact']['baseMetricV2']['impactScore']),str(cves['impact']['baseMetricV2']['cvssV2']['baseScore']),str(cves['impact']['baseMetricV2']['severity'])])
                    else:
                        print str(e)
                if cvssv2_missing and cvssv3_missing:
                    #print "Both CVSSv2 and CVSSv3 are missing"
                    file_cvss_score.write(cve.encode('utf-8')+"\t"+cvssv3+"\t"+cvssv2.encode('utf-8')+"\t"+"\t"+"\t"+description.encode('utf-8')+"\t"+cves['publishedDate'].encode('utf-8')+"\t"+cves['lastModifiedDate'].encode('utf-8')+"\n")
                else:
                    file_cvss_score.write(cve.encode('utf-8')+"\t"+cvssv3+"\t"+cvssv2.encode('utf-8')+"\t"+description.encode('utf-8')+"\t"+cves['publishedDate'].encode('utf-8')+"\t"+cves['lastModifiedDate'].encode('utf-8')+"\n")
        ###############################################################################################################
        file_products.close()
        file_cve_related_problems.close()
        file_cvss_score.close()
        file_cpes.close()
    if import_db:
        print('Connecting to the PostgreSQL database...')
        try:
            conn = psycopg2.connect("dbname='"+database+"' user='"+myuser+"' host='"+myhost+"' password='"+mypassword+"'")
        except psycopg2.Error as e:
            print "I am unable to connect to the database. Error:",e
            print "Exiting"
            sys.exit(1)
        cur = conn.cursor()
        filename = results+"cve_cvss_scores.csv"
        with open(filename, 'r') as f:
            print("importing CVSS")
            filedata = f.read()
            filedata = filedata.replace("\\","\\\\")
            output = StringIO.StringIO()
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
            cur.copy_from(f, 'cpe', sep='\t')
        conn.commit()
        f.close()
        filename = results+"cve_affected_produts.csv"
        with open(filename, 'r') as f:
            print("importing affected products")
            f.readline()
            cur.copy_from(f, 'affected_products', sep='\t')
        conn.commit()
        f.close()

def truncate_database(myuser,mypassword,myhost,database):
    con = None
    try:
        con = connect(dbname=database, user=myuser, host = myhost, password=mypassword)
        con.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)
        cur = con.cursor()
        print "Truncating CVEs tables"
        cur.execute("Truncate cpe, cve_problem, affected_products,cvss;")
        con.commit()
    except (Exception, psycopg2.DatabaseError) as error :
        print ("Error while Truncating PostgreSQL Database", error)
    finally:
        if(con):
            cur.close()
            con.close()
            print("PostgreSQL connection is closed")

def execute_query(myuser,mypassword,myhost,database,cve,product,vendor,score,date):
    con = None
    try:
        con = connect(dbname=database, user=myuser, host = myhost, password=mypassword)
        #con.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)
        cur = con.cursor()
        print "Executing query"
        if cve:
            cur.execute("SELECT cve, vector_string_3, base_score_3, base_severity_3, vector_string, base_score, severity, description, published_date FROM cvss WHERE cve LIKE '%"+cve+"%'")
            selected_cve = cur.fetchone()
            answer = ""
            for r in selected_cve:
                if type(r) is str:
                    answer = answer+r.strip()+"\t"
                else:
                    answer = answer+str(r)+"\t"
            answer = answer.rstrip('\t')
            print answer
        if product:
            cur.execute("SELECT * FROM public.cvss_vs_products WHERE product_name LIKE '%"+product+"%' and (base_score_3 > "+ str(score) + " or base_score > " + str(score)+") and published_date  >= '"+str(date)+"-01-01'")
            selected_cves = cur.fetchall()
            answer = ""
            for pr in selected_cves:
                for r in pr:
                    if type(r) is str:
                        answer = answer+r.strip()+"\t"
                    else:
                        answer = answer+str(r)+"\t"
                answer = answer.rstrip('\t')
                print answer
                answer = ""
        if vendor:
            cur.execute("SELECT * FROM public.cvss_vs_products WHERE vendor_name LIKE '%"+vendor+"%' and (base_score_3 > "+ str(score) + " or base_score > " + str(score)+") and published_date  >= '"+str(date)+"-01-01'")
            selected_cves = cur.fetchall()
            answer = ""
            for pr in selected_cves:
                for r in pr:
                    if type(r) is str:
                        answer = answer+r.strip()+"\t"
                    else:
                        answer = answer+str(r)+"\t"
                answer = answer.rstrip('\t')
                print answer
                answer = ""
    except (Exception, psycopg2.DatabaseError) as error :
        print ("Error while Querying Database", error)
    finally:
        if(con):
            cur.close()
            con.close()
            print("PostgreSQL connection is closed")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(version='0.1',description='CVEs Manager.')
    parser.add_argument('-p', '--parse',  action="store_true", dest="process", default=False, help="Process downloaded CVEs.")
    parser.add_argument('-d', '--download',  action="store_true", dest="download", default=False, help="Download CVEs.")
    parser.add_argument('-csv', '--cvs_files',  action="store_true", dest="csv", default=False, help="Create CSVs files.")
    parser.add_argument('-idb', '--import_to_db',  action="store_true", dest="idb", default=False, help="Import CVEs into a database.")
    parser.add_argument('-i', '--input', action="store", default = 'nvd/', dest="input", help="The directory where NVD json files will been downloaded, and the one from where they will be parsed (default: nvd/")
    parser.add_argument('-o', '--output', action="store", default = 'results/', dest="results", help="The directory where the csv files will be stored (default: results/")
    parser.add_argument('-u', '--user',  action="store", dest="user", default="postgres", help="The user to connect to the database.")
    parser.add_argument('-ow', '--owner',  action="store", dest="owner", default=None, help="The owner of the database (if different from the connected user).")
    parser.add_argument('-ps', '--password',  action="store", dest="password", default="", help="The password to connect to the database.")
    parser.add_argument('-host', '--host',  action="store", dest="host", default="localhost", help="The host or IP of the database server.")
    parser.add_argument('-db', '--database',  action="store", dest="database", default="postgres", help="The name of the database.")
    parser.add_argument('-cd', '--create_database',  action="store_true", dest="cd", default=False, help="Create the database")
    parser.add_argument('-dd', '--drop_database',  action="store_true", dest="dd", default=False, help="Drop the database")
    parser.add_argument('-ct', '--create_tables',  action="store_true", dest="ct", default=False, help="Create the tables of the database")
    parser.add_argument('-tr', '--truncate_cves_tables',  action="store_true", dest="tr", default=False, help="Truncate the CVEs-related tables")
    parser.add_argument('-cve', '--cvs_number',  action="store", dest="cve", default=None, help="Print info for a CVE (CVSS score and other)")
    parser.add_argument('-pr', '--product',  action="store", dest="product", default=None, help="Print CVEs for a product")
    parser.add_argument('-ve', '--vendor',  action="store", dest="vendor", default=None, help="Print CVEs for a vendor for all products")
    parser.add_argument('-sc', '--score',  action="store", dest="score", default=0.0, help="Use base score of a CVE as a selection criterion")
    parser.add_argument('-dt', '--date',  action="store", dest="date", default=1999, help="Use publication date of a CVE as a selection criterion")
    values = parser.parse_args()

    if not values.owner:
        values.owner=values.user
    if values.dd:
        drop_database(values.user,values.password,values.host,values.database)
    if values.cd:
        create_database(values.user,values.password,values.host,values.database,values.owner)
    if values.ct:
        create_tables(values.user,values.password,values.host,values.database)
    if values.download:
        download_cves(values.input)
    if values.process:
        process_cves(values.input, values.results, values.csv, values.idb,values.user,values.password,values.host,values.database)
    if values.tr: 
        truncate_database(values.user,values.password,values.host,values.database)
    if values.cve or values.product or values.vendor:
        execute_query(values.user,values.password,values.host,values.database,values.cve,values.product,values.vendor,values.score,values.date)
    if not values.input and not values.process and not values.dd and not values.cd and not values.ct and not values.download and not values.process and not values.tr and not values.cve and not values.product and not values.vendor:
        print "Choose an option (check --help)"
