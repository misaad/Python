"""
Qualys Parser

This tool converts raw csv outputs to secp format Excel .xlsx worksheets
"""

__version__ = '0.1'
__author__ = 'Dylan McAllister'
__email__ = 'dylan.mcallister@coalfire.com'
__company__ = 'Coalfire Systems'

from argparse import ArgumentParser
import pandas as pd
import numpy as np
import os.path
import csv
import datetime

# TODO Testing

"""
Main function coordinates program functions by taking in file or folder input 
from user and calling utilities.
"""
def main():

    ### Displays greeting to user and notes on how to use the software
    Utilities.greeting(__version__)
    
    ### Stores command-line argument as variable
    cmd_arg = Argparser.input()

    ### Stores current date and time
    now = datetime.datetime.now()

    ### Creates YYYY-MM-DD format string to hold today's date
    date_string = now.strftime("%Y-%m-%d")

    ### Handles directory input from a user
    if cmd_arg.path is not None:
        print('Path to DIRECTORY received...')
        print(cmd_arg.path)

        ### Enumerate all files in the directory and saves path and filenames
        file_mapping = Utilities.map_directory(cmd_arg)
        
        ### Parse all files discovered during file_mapping
        vuln_df, comp_df, status_string = Utilities.parse_csv(file_mapping)

        ### Print status to screen
        print(status_string)
        
        ### Check if vulnerability scan results exists
        if vuln_df is not None:
            ### Organizes dataframe and outputs to MS Office Excel format
            Utilities.cleaner(vuln_df).to_excel(
                os.path.join(cmd_arg.path, "Parsed Vuln Scan_"+date_string+".xlsx"), 
                sheet_name='Vuln Report')
        else:
            ### Prints status to screen.
            print("No vulnerability scan files available to parse")

        ### Check if compliance scan results exists
        if comp_df is not None:
            Utilities.cleaner(comp_df).to_excel(
                os.path.join(cmd_arg.path, 
                "Parsed Comp Scan_"+date_string+".xlsx"), sheet_name='Compliance Report')
        else:
            ### Prints status to screen
            print("No compliance scan files available to parse")
        

    ## When a specific file is provided from user..
    elif cmd_arg.filename is not None:
        print('Path to FILE received...')

        print(cmd_arg.filename.name)
        
        file_path = os.path.split(os.path.abspath(cmd_arg.filename.name))[0]

        ### Parse single file input
        file_mapping = Utilities.map_directory(cmd_arg)

        ### Parse single Qualys scan file
        vuln_df, comp_df, status_string = Utilities.parse_csv(file_mapping)

        ### Print status to screen
        print(status_string)

        ### Check if vulnerability scan results exists
        if vuln_df is not None:
            ### Organizes dataframe and outputs to MS Office Excel format
            Utilities.cleaner(vuln_df).to_excel(
                os.path.join(file_path, "Parsed Vuln Scan_"+date_string+".xlsx"), 
                sheet_name='Vuln Report')
        else:
            ### Prints status to screen.
            print("No vulnerability scan files available to parse")

        ### Check if compliance scan results exists
        if comp_df is not None:
            ### Organizes dataframe and outputs to MS Office Excel format
            Utilities.cleaner(comp_df).to_excel(
                os.path.join(file_path, "Parsed Comp Scan_"+date_string+".xlsx"), 
                sheet_name='Compliance Report')
        else:
            ### Prints status to screen
            print("No compliance scan files available to parse")

    return

class Utilities:

    def greeting(__version__):
        """
        Method to provide a greeting to the user. Also provides
        information about the build version as well as other useful information
        """
        print("\nWelcome to Qualys Parser " + __version__ + "!\n\nPlease include path to file or " \
              "directory that you would like to parse.\n")
    
    def scout(cmd_arg, path=None):
        """
        The scout method identifies the csv as type 'Compliance' or
        type 'Vulnerability'

        Returns a tuple: (<identified file type>, <skip_rows>) ex: (1, 15)
        1 : 'Vulnerability'
        2 : 'Compliance'
        0 : 'Cannot Parse'
        """
        f = open(os.path.join(path, cmd_arg))

        try:
            for i, row in enumerate(f):
                ### Searches for 'IP' and 'QID' in row
                if ("IP" in row) & ("QID" in row):
                    f.close()
                    ### Returns type 1 for 'Vulnerability'
                    return {"scan_type" : 1, "skip" : i-1}

                ### Searches for 'Host IP', 'DNS Hostname', and 'Control ID' in row
                if  ("Host IP" in row) & ("DNS Hostname" in row) & ("Control ID" in row):
                    f.close()
                    ### Returns type 2 for 'Compliance'
                    return {"scan_type" : 2, "skip" : i-1}
        
        ### Exception handles files that are not a valid scan file from qualys
        except:
            print("File:", cmd_arg, "is not a valid file type.")
            return {"scan_type" : 0, "skip" : None}

    def map_directory(cmd_arg):
        """
        map_directory enumerates all of the files contained within the specified
        directory and responds with a dictionary showing filenames and types
        of files
        """
        var = {}

        ### Coordinates operations to find all files within directory
        if cmd_arg.path:
            var[cmd_arg.path] = {file : Utilities.scout(file, cmd_arg.path) for file in 
                            os.listdir(cmd_arg.path)}

        ### Maps path and filename to dictionary and saves as variable
        if cmd_arg.filename:
            path, file = os.path.split(cmd_arg.filename.name)
            var[path] = {file : Utilities.scout(file, path)}

        return var

    def parse_csv(file_mapping):
        """
        Imports csv into a Pandas DataFrame and parsed to produce secp-like
        output.
        """

        ### Empty list to hold vulnerability dataframes
        vuln_dfs = []
        ### Empty list to hold compliance dataframes
        comp_dfs=[]

        [(path, files)] = file_mapping.items()

        ### Iterates over all files in mapping
        for file in files:
            
            ### Checks for vulnerability scan type files
            if file_mapping[path][file]['scan_type'] == 1:
                
                ### Reads csv to dataframe
                temp_df = pd.read_csv(os.path.join(path, file), 
                                      skiprows=file_mapping[path][file]['skip'], dtype=str)

                ### Drops any empty rows in column 'Type'
                temp_df.dropna(inplace=True, subset=['Type'])

                ### Creates 'Source of Discovery' column and appends filename
                temp_df['Source of Discovery'] = file

                ### Appends dataframe to list
                vuln_dfs.append(temp_df)

            ### Checks for compliance scan type files
            elif file_mapping[path][file]['scan_type'] == 2:
                
                ### Reads csv to dataframe
                temp_df = pd.read_csv(os.path.join(path, file), 
                                          skiprows=file_mapping[path][file]['skip'], dtype=str)
                
                ### Handles off by one bug
                if temp_df.columns.values.any() == 'RESULTS':
                    temp_df = pd.read_csv(os.path.join(path, file), 
                                          skiprows=file_mapping[path][file]['skip'] + 1, dtype=str)

                ### Creates 'Source of Discovery' column and appends filename
                temp_df['Source of Discovery'] = file
                
                ### Appends dataframe to list
                comp_dfs.append(temp_df)
            
            ### Check for invalid file types
            elif file_mapping[path][file]['scan_type'] == 0:

                ### Outputs skipped files to screen
                print("Skipped file:", file)
                continue

        ### Combines vulnerability dataframes
        try:
            vuln_df = pd.concat(vuln_dfs)

            ### Groups dataframes according to QID and combines Source of Discovery, IP, and DNS
            ### columns
            vuln_df = vuln_df.groupby('QID').agg({'Title':'first',
                                            'CVE ID':'first',
                                            'Type':'first',
                                            'Source of Discovery':', '.join,
                                            'Threat':'first',
                                            'IP':', '.join,
                                            'DNS': ', '.join,
                                            'CVSS Base':'first',
                                            'CVSS3 Base':'first',
                                            'Severity':'first',
                                            'Impact':'first',
                                            'Solution':'first'}).reset_index()
            
            ### Renames columns
            vuln_df = vuln_df.rename(columns = {'Title':'Title',
                                                'CVE ID':'CVE ID',
                                                'Type':'Type',
                                                'Source of Discovery':'Source of Discovery',
                                                'Threat':'Description',
                                                'IP':'Affected IPs',
                                                'DNS':'Affected Hostnames',
                                                'CVSS Base':'CVSS Base',
                                                'CVSS3 Base':'CVSS3 Base',
                                                'Severity':'Qualys Severity',
                                                'Impact':'Risk Statement',
                                                'Solution':'Recommendation for Remediation'
            })

            ### Converts QID column to type integer
            vuln_df['QID'] = vuln_df['QID'].astype(int)

            print("Vulnerability scan file(s) identified and parsed")
        
        ### Prints status to screen if no more than one scan was provided
        except:
            print("No vulnerability scans to concatenate")

        ### Combines compliance dataframes
        try:
            comp_df = pd.concat(comp_dfs, sort=False)

            # Groupby 'Control ID' and join 'Source of Discovery, Host IP, and DNS Hostname
            comp_df = comp_df.groupby(' Control ID').agg({' Control':'first',
                                                            'Source of Discovery':', '.join,
                                                            ' Rationale':'first',
                                                            'Host IP':', '.join,
                                                            ' DNS Hostname':', '.join,
                                                            ' Criticality Label':'first',
                                                            ' Criticality Value':'first',
                                                            ' Evidence':'first',
                                                            ' Status':'first',
                                                            ' Remediation':'first'}).reset_index()
            
            ### Renames columns
            comp_df = comp_df.rename(columns={' Control ID':'Control ID',
                                              ' Control':'Control', 
                                              ' Rationale':'Rationale',
                                              'Host IP':'Affected IPs',
                                              ' DNS Hostname':'Affected Hostnames',
                                              ' Criticality Label':'Criticality Label',
                                              ' Criticality Value':'Criticality Value',
                                              ' Evidence': 'Evidence',
                                              ' Status': 'Status',
                                              ' Remediation':'Remediation'})
            
            ### Output status to terminal
            print("Compliance scan file(s) identified and parsed")

        ### Prints status to terminal to no more than one scan was provided
        except:
            print("No compliance scans to concatenate")

        ### Returns combined dataframes
        try:
            return vuln_df, comp_df, "Vulnerability and Compliance scan files parsed successfully."
        except:
            try:
                return vuln_df, None, "Vulnerability scan files parsed successfully."
            except:
                try:
                    return None, comp_df, "Compliance scan files parsed successfully."
                except:
                    print("No files to parse.")
                    pass

    def cleaner(dirty_df):
        '''
        The cleaner method adds, renames, and re-arranges columns to refelect 
        the FedRAMP SAR template format. This method also removes duplicates in
        the "Source of Discovery" column that were created during the groupby
        operation. Adds "None" to empty "CVE ID" cells.
        '''

        ### Clean & organize vulnerability type dataframe
        try:

            ### Add 'None' where no CVE is reported from Qualys results
            dirty_df['CVE ID'] = dirty_df['CVE ID'].replace(np.NaN, 'None')

            ### Combine Name, QID, and CVE(s) into single cell
            dirty_df['Name'] = dirty_df['Title'] + '\n\n' + 'QID: ' + dirty_df.QID.map(str) + \
                                   '\n\n' + 'CVE(s): ' + dirty_df['CVE ID']
            
            ### Empty list to hold source of discovery data
            src_disco = []
            ### Empty list to hold dns hostname data
            dns = []
            ### Empty list to hold IPs
            affected_ips = []

            ### Remove duplicates
            for item in dirty_df['Source of Discovery']:
                src_disco.append(', '.join(set(item.split(', '))))

            ### Remove duplicates
            for item in dirty_df['Affected Hostnames']:
                dns.append(', '.join(set(item.split(', '))))

            ### Remove duplicates
            for item in dirty_df['Affected IPs']:
                affected_ips.append(', '.join(set(item.split(', '))))

            ### Update Source of Discovery column with deduped data
            dirty_df['Source of Discovery'] = src_disco

            ### Update Affected Hostnames with deduped data
            dirty_df['Affected Hostnames'] = dns

            ### Update Affected IPs with deduped data
            dirty_df['Affected IPs'] = affected_ips

            ### Filter rows where 'Type' is 'Ig'
            dirty_df = dirty_df[dirty_df["Type"] != "Ig"]

            ### Replace empty rows with 'N/A'
            dirty_df = dirty_df.replace(np.nan, "N/A", regex=True)

            ### Assign risk exposure rating to vulnerability
            dirty_df = Utilities.severity_classifier(dirty_df)

            ### Convert 'Risk Exposure' column to Categorical
            dirty_df['Risk Exposure'] = pd.Categorical(dirty_df['Risk Exposure'], 
                                                       categories=['High', 'Moderate', 'Low']
                                                       )
            
            ### Sort column according to HML
            dirty_df.sort_values("Risk Exposure", inplace=True)

            ### Reset index to start at 0
            dirty_df.reset_index(inplace=True, drop=True)

            ### Increment index to start at 1
            dirty_df.index += 1

            ### Rename columns
            dirty_df = dirty_df[['QID', 'Name', 'Title', 'CVE ID', 'Type', 'Source of Discovery', 
                                'Affected IPs', 'Affected Hostnames', 'Description',
                                'CVSS3 Base', 'CVSS Base', 'Qualys Severity', 'Risk Exposure',
                                'Risk Statement', 'Recommendation for Remediation']]

            ### Convert Qualys Severity to Numeric value
            dirty_df['Qualys Severity'] = pd.to_numeric(dirty_df['Qualys Severity'])

        except:
            pass

        ### Clean & organize compliance type dataframe
        try:
            
            ### Combines name and control id into single column
            dirty_df['Name'] = dirty_df['Control'] + '\n\n' + 'Control ID: ' + \
                               dirty_df['Control ID'].map(str)
            
            ### Empty list for source of discovery data
            src_disco = []
            ### Empty list for affected ip data
            host_ip = []
            ### Empty list for affected hostname data
            dns = []

            ### Removes duplicates in source of discovery
            for item in dirty_df['Source of Discovery']:
                src_disco.append(', '.join(set(item.split(', '))))

            ### Updates dataframe with deduped data
            dirty_df['Source of Discovery'] = src_disco

            ### Removes duplicates in affected ips column
            for item in dirty_df['Affected IPs']:
                host_ip.append(', '.join(set(item.split(', '))))

            ### Updates dataframe with deduped data
            dirty_df['Affected IPs'] = host_ip

            ### Removed duplicates in affected hostnames column
            for item in dirty_df['Affected Hostnames']:       
                dns.append(', '.join(set(item.split(', '))))

            ### Updates data in affected hostnames column with deduped data
            dirty_df['Affected Hostnames'] = dns

            ### Renames columns
            dirty_df = dirty_df[['Control ID', 'Name', 'Control', 'Source of Discovery', 
                                'Rationale', 'Affected IPs', 'Affected Hostnames', 
                                'Criticality Label', 'Criticality Value', 'Evidence', 'Status', 
                                'Remediation']]
            
            ### Replaces empty cells with 'N/A'
            dirty_df = dirty_df.replace(np.nan, "N/A", regex=True)

            ### Convert status column to categorical
            dirty_df['Status'] = pd.Categorical(dirty_df['Status'], categories=['Failed', 'Passed'])

            ### Sort status by failed first
            dirty_df.sort_values('Status', inplace=True)

            ### Drop un-needed columns from dataframe
            dirty_df.drop(columns=['Criticality Label', 'Criticality Value'], inplace=True)

            ### Reset index
            dirty_df.reset_index(inplace=True, drop=True)

            ### Convert control id column to numeric
            dirty_df['Control ID'] = pd.to_numeric(dirty_df['Control ID'])

            ### Increments index to start at 1
            dirty_df.index += 1

        except:
            pass

        ### Returns clean dataframe
        return dirty_df

    def severity_classifier(df):
        '''
        The severity_classifier method scores the vulnerability based on CVSSv3
        then CVSSv2, and then Qualys severity score if CVSS score is not
        present.
        '''

        df['Risk Exposure'] = np.nan

        exposure = []

        for row in df.iterrows():
            if row[1]['CVSS3 Base'] != 'N/A':
                exposure.append(Utilities.cvss(row[1]['CVSS3 Base']))
            elif row[1]['CVSS Base'] != 'N/A':
                exposure.append(Utilities.cvss(row[1]['CVSS Base'].split(' ')[0]))
            elif row[1]['Severity'] != 'N/A':
                exposure.append(qsev(row[1]['Severity']))

        df['Risk Exposure'] = exposure

        return df

    def cvss(cvss_score):
        """
        Cvss method takes CVSS base score and returns FedRAMP Risk Exposure
        rating as "High", "Moderate", "Low"
        """

        cvss_score = float(cvss_score)

        if 0 <= cvss_score <= 3.9:
            exposure = "Low"
        elif 4.0 <= cvss_score <= 6.9:
            exposure = "Moderate"
        elif 7.0 <= cvss_score <= 10:
            exposure = "High"
        else:
            exposure = None

        return exposure

    def qsev(qualys_severity):
        """
        qsev method assigns an overall risk exposure rating according to the 
        Qualys Severity value that was assigned by Qualys
        """

        if 0 <= qualys_severity <= 2:
            exposure = "Low"
        elif 2 < qualys_severity <= 4:
            exposure = "Moderate"
        elif 4 < qualys_severity <= 5:
            exposure = "High"
        else:
            exposure = "N/A"

        return exposure

class Argparser:

    def input():
        parser = ArgumentParser(description="Qualys Parser")
        parser.add_argument("-i", dest="filename", help="input raw csv file to be parsed", 
                            metavar="FILE", type=lambda x: Argparser.is_valid_file(parser, x))
        parser.add_argument("--path", 
                            help="input path to folder containing raw csv file(s) to be parsed", 
                            type=lambda x: Argparser.is_valid_dir(parser, x), metavar="DIRECTORY")
        args = parser.parse_args()
        return args

    def is_valid_file(parser, arg):
        if not os.path.exists(arg):
            parser.error("The file %s does not exist!\n" % arg)
        else:
            return open(arg, 'r')

    def is_valid_dir(parser, arg):
        if not os.path.isdir(arg):
            parser.error("The directory %s does not exist!\n" % arg)
        else:
            return arg

if __name__ == "__main__":
    main()
