from dotenv import load_dotenv
import argparse
import configparser
import requests
import re
from datetime import datetime
from pprint import pprint

class api_conn:
	def __init__(self, baseurl):
		self.baseurl = baseurl

	def make_request(self, param):
		try:
			req = requests.get(self.baseurl, params=param)
			return req.json()
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
	parser.add_argument("--date", dest="date", help="especificar rango de fecha (mm-aaaa/mm-aaaa) - solo cve", required=False)
	parser.add_argument("-f", dest="outfile", help="guardar resultados a un archivo", metavar='FILE', required=False)
	parser.add_argument("-out", help="imprimir output", required=False, action='store_true', default=True)

	return parser

# Devolver cpe de un nombre random
def cpe_from_vendor(client, string): return client.make_request({"keywordSearch" : string})

# Devolver cves a partir de un cpe
def cve_from_cpe(client, args): 
	params = {"cpeName":args.query}
	if args.date:

		startDate = datetime.strptime(args.date.split('/')[0], '%m-%Y')
		startDate_iso = startDate.replace(day=1).strftime('%Y-%m-%dT00:00:00')

		endDate = datetime.strptime(args.date.split('/')[1], '%m-%Y')
		endDate_iso = endDate.replace(day=1).strftime('%Y-%m-%dT00:00:00')

		params.update({"pubStartDate" : startDate_iso, "pubEndDate" : endDate_iso})

	if args.severity:
		params.update({"cvssV3Severity" : args.severity})

	print(params)
	return client.make_request(params)

if __name__ == '__main__':
	p = define_parser()

	args = p.parse_args()
	cve_url, cpe_url = retrieve_urls()

	cve_client = api_conn(cve_url)
	cpe_client = api_conn(cpe_url)

	# cpe:2.3:a:cisco:ios:*

	if is_cpe(args.query):
		print(f"[*] Searching CVEs associated to: {args.query}")
		output = cve_from_cpe(cve_client, args)
	else:
		print(f"[*] Searching CPEs associated to: {args.query}")
		output = cpe_from_vendor(cpe_client, args.query)

	print(output)
