#!/usr/bin/env python3

from prettytable import PrettyTable
import json
import csv
import sys


custom_sort_order = {
    "unknown": 0,
    "critical": 1,
    "high": 2,
    "medium": 3,
    "low": 4,
    "info": 5,
}

# Class to handle Nuclei Json file
class NucleiJsonFile:
    def __init__(self):
        self.entries = None
    
    def loadJson(self, filename):
        """
        Loads from json file
        """
        f = open(filename)
        data_list = json.load(f, strict=False)
        f.close()
        self.entries = [NucleiTemplate(**{key.replace('-', '_'): value for key, value in data.items()}) for data in data_list]

    def loadsJson(self, data):
        """
        Loads from stdin
        """
        data_list = json.loads(data, strict=False)
        self.entries = [NucleiTemplate(**{key.replace('-', '_'): value for key, value in data.items()}) for data in data_list]

    def filter(self, filter, values):
        """ 
        Filter values depending of filter; and return a list with matches
        """
        entries = []
        field_names = [value.strip() for value in values.split(",")]
        for entry in self.entries:
            for field in field_names:
                if (filter == "filter_severity" and entry.info.severity == field) or \
                      (filter == "filter_template" and entry.template_id == field) or \
                        (filter == "filter_url" and entry.url == field) or \
                            (filter == "filter_host" and entry.host == field):
                    entries.append(entry)
        self.entries = entries

    def printPretty(self, columns, sortby=None):
        """
        Print json by selected columns
        Parameters:
        columns: Comma separated list of Component Properties of Nuclei json (without spaces)
        """
        table = PrettyTable()
        table.field_names = [column.strip() for column in columns.split(",")]
        for entry in sorted(self.entries, key=lambda x: custom_sort_order.get(x.info.severity, float('inf'))):
            row = []
            for i in table.field_names:
                if ("template" == i.strip()):
                    row.append(entry.template)
                elif ("template-url" == i.strip()):
                    row.append(entry.template_url)
                elif ("template-id" == i.strip()):
                    row.append(entry.template_id)
                elif ("url" == i.strip()):
                    row.append(entry.url)
                elif ("info.severity" == i.strip()):
                    row.append(entry.info.severity)
                elif ("curl-command" == i.strip()):
                    row.append(entry.curl_command)
                elif ("timestamp" == i.strip()):
                    row.append(entry.timestamp)
                elif ("host" == i.strip()):
                    row.append(entry.host)
                elif ("port" == i.strip()):
                    row.append(entry.port)
                elif ("description" == i.strip()):
                    row.append(entry.info.description)
                else:
                    row.append(i.strip())
            table.add_row(row)
        if sortby != 'info.severity':
            table.sortby = sortby
        print(table)
    
    def printCsv(self, items, sortby=None):
        """
        Print CSV by selected items
        Parameters:
        items: Comma separated list of Component Properties of Nuclei json (without spaces)
        """
        field_names = [item.strip() for item in items.split(",")]
        output = csv.writer(sys.stdout)
        output.writerow(field_names)  
        for entry in self.entries:
                row = []
                for i in field_names:
                    if ("template" == i.strip()):
                        row.append(entry.template)
                    elif ("template-url" == i.strip()):
                        row.append(entry.template_url)
                    elif ("template-id" == i.strip()):
                        row.append(entry.template_id)
                    elif ("template-path" == i.strip()):
                        row.append(entry.template_path)
                    elif ("url" == i.strip()):
                        row.append(entry.url)
                    elif ("info.severity" == i.strip()):
                        row.append(entry.info.severity)
                    elif ("curl-command" == i.strip()):
                        row.append(entry.curl_command)
                    elif ("timestamp" == i.strip()):
                        row.append(entry.timestamp)
                    elif ("host" == i.strip()):
                        row.append(entry.host)
                    elif ("port" == i.strip()):
                        row.append(entry.port)
                    elif ("description" == i.strip()):
                        row.append(entry.info.description)
                    else:
                        row.append(i.strip())     
                output.writerow(row)      

# Class to handle the Nuclei template 
class NucleiTemplate:
    def __init__(self, template, template_url, template_id, template_path, template_encoded=None, info=None, matcher_name=None, extractor_name=None, type=None, host=None, \
                 port=None, scheme=None, url=None, path=None, matched_at=None, extracted_results=None, request=None, response=None, ip=None, \
                    meta=None, timestamp=None, curl_command=None, interaction=None, matcher_status=None, matched_line=None):
        self.template = template
        self.template_url = template_url
        self.template_id = template_id
        self.template_path = template_path
        self.template_encoded = template_encoded
        self.info = NucleiTemplateInfo(**info)
        self.matcher_name = matcher_name
        self.extractor_name = extractor_name
        self.type = type
        self.host = host
        self.port = port
        self.scheme = scheme
        self.url = url
        self.path = path
        self.matched_at = matched_at
        self.extracted_results = extracted_results
        self.request = request
        self.response = response
        self.meta = meta
        self.ip = ip
        self.timestamp = timestamp
        self.curl_command = curl_command
        self.interaction = interaction
        self.matcher_status = matcher_status
        self.matched_line = matched_line

    def __str__(self):
        return f"NucleiTemplate(template-id={self.template_id}, template-path={self.template_path}, info={self.info}, type={self.type}, host={self.host}, port={self.port}, scheme={self.scheme}, url={self.url}, marched_at={self.matched_at}, extracted_results={self.extracted_results}, request={repr(self.request)}, response={repr(self.response)}, ip={self.ip}, timestamp={self.timestamp}, curl_command={self.curl_command}, matcher_status={self.matcher_status} )"


class NucleiTemplateInfo:
    def __init__(self, description=None, reference=None, remediation=None, classification=None, name=None, author=None, tags=None, severity=None, metadata=None):
        self.description = description
        self.classification = classification
        self.reference = reference
        self.remediation = remediation
        self.name = name
        self.author = author
        self.tags = tags
        self.severity = severity
        self.metadata = metadata
    
    def __str__(self):
        return f"HttpMethodInfo(name={self.name}, author={self.author}, tags={self.tags}, severity={self.severity}, metadata={self.metadata})"




