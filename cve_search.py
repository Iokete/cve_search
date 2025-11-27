from dotenv import load_dotenv
import argparse
import configparser
import requests
import re


cpe_regex = r'''cpe:2\.3:[aho\*\-](:(((\?*|\*?)([a-zA-Z0-9\-\._]|(\\[\\\*\?!"#$$%&'\(\)\+,/:;<=>@\[\]\^`\{\|}~]))+(\?*|\*?))|[\*\-])){5}(:(([a-zA-Z]{2,3}(-([a-zA-Z]{2}|[0-9]{3}))?)|[\*\-]))(:(((\?*|\*?)([a-zA-Z0-9\-\._]|(\\[\\\*\?!"#$$%&'\(\)\+,/:;<=>@\[\]\^`\{\|}~]))+(\?*|\*?))|[\*\-])){4}'''

class api_conn:
	def __init__(self, baseurl):
		self.baseurl = baseurl

	def make_request(self, param):
		try:
			req = requests.get(self.baseurl, params=param)
			return req.json()
		except:
			print(f"[!] Error\n");
			return None

class CPE:
	def __init__(self, )

def retrieve_urls():
	config = configparser.ConfigParser()
	config.read('config')
	cve_url = config.get("API", "CVE_URL")
	cpe_url = config.get("API", "CPE_URL")

	if not cpe_url or not cve_url:
		print(f"[*] Error retrieving urls.");
		exit(1)

	return cve_url, cpe_url

def CPEExtractor(query):



def define_parser():
	parser = argparse.ArgumentParser()

	parser.add_argument("query",help="producto/vendedor/cpe")
	parser.add_argument("--filter", dest="severity", choices=['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'NONE'], help="filtrar por CVSS3 severity")
	parser.add_argument("--date", dest="date", help="especificar rango de fecha (mm-aaaa/mm-aaaa)", required=False)
	parser.add_argument("-f", dest="outfile", help="guardar resultados a un archivo", metavar='FILE', required=False)
	parser.add_argument("-out", help="imprimir output", required=False, action='store_true', default=True)

	return parser


def search_cpe(): return
def search_vendor(): return

if __name__ == '__main__':
	p = define_parser()

	args = p.parse_args()
	cve_url, cpe_url = retrieve_urls()

	cve_client = api_conn(cve_url)
	cpe_client = api_conn(cpe_url)

	query = args.query
	severity = args.severity
	date = args.date
	outfile = args.outfile
	out = args.out

	# cpe:2.3:a:cisco:ios:*

	if True:
		print(f"CPE!")
	else:
		print(f"Not a cpe!")

	print(args)
