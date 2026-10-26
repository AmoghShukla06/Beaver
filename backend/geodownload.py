"""Optional public database download; never transmits observed endpoints."""
import datetime
import gzip
import os
import time
import urllib.request
import uuid
from pathlib import Path
import maxminddb

ATTRIBUTION = "IP Geolocation by DB-IP — https://db-ip.com/ — CC BY 4.0 https://creativecommons.org/licenses/by/4.0/"

def download_city(directory):
    month = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m")
    url = f"https://download.db-ip.com/free/dbip-city-lite-{month}.mmdb.gz"
    directory = Path(directory)
    token = uuid.uuid4().hex[:12]
    compressed = directory / f"geoip-{token}.gz.tmp"
    decoded = directory / f"geoip-{token}.mmdb.tmp"
    target = directory / f"dbip-city-lite-{month}-{token}.mmdb"
    started = time.monotonic()
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Beaver/1.0"})
        with urllib.request.urlopen(req, timeout=20) as response, compressed.open("wb") as output:
            if not response.url.startswith("https://download.db-ip.com/"):
                raise ValueError("Unexpected geolocation download redirect")
            size = 0
            while True:
                block = response.read(65536)
                if not block:
                    break
                size += len(block)
                if size > 150_000_000 or time.monotonic() - started > 90:
                    raise ValueError("Geolocation download exceeded its size or time limit")
                output.write(block)
        with gzip.open(compressed, "rb") as source, decoded.open("wb") as output:
            size = 0
            while True:
                block = source.read(65536)
                if not block:
                    break
                size += len(block)
                if size > 400_000_000 or time.monotonic() - started > 110:
                    raise ValueError("Geolocation database exceeded its size or time limit")
                output.write(block)
        with maxminddb.open_database(str(decoded)) as reader:
            if "City" not in reader.metadata().database_type:
                raise ValueError("The downloaded database is not a City database")
        os.replace(decoded, target)
        (directory / "DB-IP-LICENSE.txt").write_text(ATTRIBUTION + "\n", encoding="utf-8")
        return str(target)
    finally:
        compressed.unlink(missing_ok=True)
        decoded.unlink(missing_ok=True)
