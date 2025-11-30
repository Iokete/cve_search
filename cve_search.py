from dotenv import load_dotenv
import argparse
import configparser
import requests
import re
import csv
from datetime import datetime
from pprint import pprint

FIELD_NAMES = ["Nombre del producto", "CPE", "CVE", "Severity", "CVSS3.1 Base Score", "Vector (URL)", "Descripción", "Fecha de publicación", "CWE id"]

class api_conn:
	def __init__(self, baseurl):
		self.baseurl = baseurl

	def make_request(self, param):
		try:
			req = requests.get(self.baseurl, params=param)
			return req
		except Exception as e:
			print(f"[!] Error: {e}\n");
			return None

def retrieve_urls():
	config = configparser.ConfigParser()
	config.read('config')
	cve_url = config.get("API", "CVE_URL")
	cpe_url = config.get("API", "CPE_URL")

	if not cpe_url or not cve_url:
		print(f"[*] Error retrieving urls.");
		exit(1)

	return cve_url, cpe_url

def is_cpe(query): return query.startswith("cpe:2.3:") and len(query.split(":")) > 5

def validate_date(date): return re.fullmatch(r'^\d{2}-\d{4}/\d{2}-\d{4}$', date)

def define_parser():
	parser = argparse.ArgumentParser()

	parser.add_argument("query",help="producto/vendedor/cpe")
	parser.add_argument("--filter", dest="severity", choices=['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'NONE'], help="filtrar por CVSS3 severity - solo cve")
	parser.add_argument("--date", dest="date", help="especificar rango de fecha (mm-aaaa/mm-aaaa) - solo cve: Máximo 120 días de rango", required=False)
	parser.add_argument("-f", dest="outfile", help="guardar resultados a un archivo", metavar='FILE', required=False)
	parser.add_argument("-out", dest="verbose", help="imprimir output", required=False, action='store_true', default=False)

	return parser

# Devolver cpe de un nombre random
def cpe_from_vendor(client, string): return client.make_request({"keywordSearch" : string})

# Devolver cves a partir de un cpe
def cve_from_cpe(client, args): 
	params = {"virtualMatchString":args.query}
	if args.date:

		startDate = datetime.strptime(args.date.split('/')[0], '%m-%Y')
		startDate_iso = startDate.replace(day=1).strftime('%Y-%m-%dT00:00:00Z')

		endDate = datetime.strptime(args.date.split('/')[1], '%m-%Y')
		endDate_iso = endDate.replace(day=1).strftime('%Y-%m-%dT00:00:00Z')

		if (endDate.month - startDate.month) > 2 :
			print(f"[!] Bad date format, exiting. ")
			exit(1)  

		params.update({"pubStartDate" : startDate_iso, "pubEndDate" : endDate_iso})

	if args.severity:
		params.update({"cvssV3Severity" : args.severity})

	return client.make_request(params)

def export_csv(entries, filename):
	if not filename.endswith(".csv"):
		filename = filename + ".csv"	
	with open(filename, "w", newline="") as csvfile:
		fieldnames = FIELD_NAMES
		writer = csv.DictWriter(csvfile, fieldnames)
		writer.writeheader()
		for entr in entries:
			writer.writerow(entr)	

def parse_fields(data):
	entry = {field : "" for field in FIELD_NAMES}

	cve_data = data['vulnerabilities']

	entries = []

	for vuln in cve_data:

		cve = vuln['cve']

		cve_id = cve['id']
		date = cve['published'].split('T')[0]

		desc = "N/A"
		for d in cve.get("descriptions", []):
			if d.get("lang") == "en":
				desc = d.get("value", "N/A")
				break

		cwe_id = "N/A"
		for weakness in cve.get("weaknesses", []):
			for d in weakness.get("description", []):
				if d.get("lang") == "en" and "CWE-" in d.get("value", ""):
					cwe_id = d.get("value", "N/A")
					break
			if cwe_id != "N/A":
				break

		score = "N/A"
		severity = "N/A"
		vector_url = "N/A"
		metrics = cve.get("metrics", {})

		if "cvssMetricV31" in metrics and metrics["cvssMetricV31"]:
			cvss_data = metrics["cvssMetricV31"][0].get("cvssData", {})
			score = cvss_data.get("baseScore", "N/A")
			severity = metrics["cvssMetricV31"][0].get("baseSeverity", "N/A")
			vector_str = cvss_data.get("vectorString", "")
			if vector_str:
				vector_url = f"https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?vector={vector_str}"
        
 
		producto = "N/A"
		cpe = "N/A"
        
		for config in cve.get("configurations", []):
			for node in config.get("nodes", []):
				for cpe_match in node.get("cpeMatch", []):
					if cpe_match.get("vulnerable", False):
						cpe = cpe_match.get("criteria", "N/A")
                        # Extraer nombre del producto del CPE
						parts = cpe.split(":")
						if len(parts) >= 5:
							vendor = parts[3]
							product = parts[4]
							if vendor != "*" and product != "*":
								producto = f"{vendor} {product}"
						break
				if producto != "N/A":
					break
			if producto != "N/A":
				break

		entry = {
	       "Nombre del producto": producto,
            "CPE": cpe,
            "CVE": cve_id,
            "Severity": severity,
            "CVSS3.1 Base Score": score,
            "Vector (URL)": vector_url,
            "Descripción": desc,
            "Fecha de publicación": date,
            "CWE id": cwe_id
                }
		entries.append(entry)
	
	return entries



def main():
	p = define_parser()
	is_cve = False
	args = p.parse_args()
	cve_url, cpe_url = retrieve_urls()

	cve_client = api_conn(cve_url)
	cpe_client = api_conn(cpe_url)

	# cpe:2.3:a:cisco:ios:*

	if is_cpe(args.query):
		print(f"[*] Searching CVEs associated to: {args.query}")
		output = cve_from_cpe(cve_client, args)
		is_cve = True
	else:
		print(f"[*] Searching CPEs associated to: {args.query}")
		output = cpe_from_vendor(cpe_client, args.query)

	if (output.status_code) == 200:
		print(f"[*] Status 200")
		data = output.json()
		if(data['totalResults'] > 0):
			print(f"[*] Found {data['totalResults']} results.")
			if is_cve:
				if args.outfile is not None:
					entries = parse_fields(data)
					export_csv(entries, args.outfile)
			if args.verbose:
				pprint(output.json())	
		else:
			print(f"[-] No results found.")



if __name__ == '__main__':
	main()
