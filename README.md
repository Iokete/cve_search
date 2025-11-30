## cve_search.py
Proyecto para la asignatura Auditoría, que presenta un script en Python que realiza búsquedas por CVE y CPE mediante el uso de las APIs de NVD:
* CVE: https://nvd.nist.gov/developers/vulnerabilities 
* CPE: https://nvd.nist.gov/developers/products

## Metodología utilizada en la práctica

- La herramienta tiene como objetivo realizar una búsqueda mediante el uso de CPE API para obtener la cadena CPE de un producto y, a partir de ella, poder listar CVEs asociados.
- En nuestro caso, seguimos los siguientes pasos:
   * Generamos una lista con todos los servicios/productos.
   * Recorremos esta lista obteniendo los CPEs con el siguiente comando en Bash:
     * `while read line; do python3 cve_search.py -out "$line" 2>/dev/null | head -n 1; done < servicios`
   * Con los resultados, utilizamos el script para devolver todos los CVE asociados y volcarlos en un archivo CSV, que luego puede importarse a un Excel para su análisis.

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
