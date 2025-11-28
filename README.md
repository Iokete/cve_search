## cve_search.py
Proyecto para la asignatura auditoría, que presenta un script en Python que realiza búsquedas de CVE y CPE mediante el uso de las APIs de NVE:
* CVE: https://nvd.nist.gov/developers/vulnerabilities 
* CPE: https://nvd.nist.gov/developers/products

## Usage

```console
usage: cve_search.py [-h] [--filter {CRITICAL,HIGH,MEDIUM,LOW,NONE}] [--date DATE] [-f FILE] [-out] query

positional arguments:
  query                 producto/vendedor/cpe

options:
  -h, --help            show this help message and exit
  --filter {CRITICAL,HIGH,MEDIUM,LOW,NONE}
                        filtrar por CVSS3 severity - solo cve
  --date DATE           especificar rango de fecha (mm-aaaa/mm-aaaa) - solo cve: Máximo 120 días de rango
  -f FILE               guardar resultados a un archivo
  -out                  imprimir output

```
