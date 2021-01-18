import json
import math
from datetime import datetime

import pika
import pytz
import requests
import schedule

from helper import network, setup_es

OTX_API_KEY = "779cc51038ddb07c5f6abe0832fed858a6039b9e8cdb167d3191938c1391dbba"

headers = {
    "X-OTX-API-KEY": OTX_API_KEY
}

proxies = {
    "http": "http://127.0.0.1:3131",
    "https": "http://127.0.0.1:3131",
}

http = requests.Session()
# retries
# http.mount("https://", network.retry_http_adapter())

# timeout 2s and retries
http.mount("https://", network.TimeoutHTTPAdapter(max_retries=network.retry_http_adapter()))
http.mount("http://", network.TimeoutHTTPAdapter(max_retries=network.retry_http_adapter()))


def send_indicator(channel, message):
    channel.basic_publish(exchange="",
                          routing_key="ioc_collect_queue",
                          body=json.dumps(message),
                          properties=pika.BasicProperties(priority=5))
    print("Sent %r" % message)


def get_total_page_otx():
    results = http.get("https://otx.alienvault.com/api/v1/pulses/subscribed", headers=headers, proxies=proxies).json()
    total_page = math.ceil(results["count"] / 50)
    return total_page


def crawler_otx():
    es = setup_es.connect_elasticsearch()
    # connection, channel = setup_rbmq.setup_connect("ioc_collect_queue")
    ist = pytz.timezone("Asia/Ho_Chi_Minh")
    total_page = get_total_page_otx()
    sample = {"sample": ["FileHash-MD5", "FileHash-PEHASH", "FileHash-SHA256", "FileHash-IMPHASH", "FileHash-MD5"]}
    url = {"url": ["URL", "URI"]}
    domain = {"domain": ["hostname", "domain"]}
    ipaddress = {"ipaddress": ["IPv6", "IPv4", "BitcoinAddress"]}

    for page in range(1, total_page + 1):
        data = http.get("https://otx.alienvault.com/api/v1/pulses/subscribed?limit=50&page={}".format(page),
                        headers=headers, proxies=proxies).json()
        for item in data["results"]:
            pulse_id = item["id"]
            name = item["name"]
            description = item["description"]
            author_name = item["author_name"]
            modified = item["modified"]
            created = item["created"]
            category = item["tags"]
            targeted_countries = item["targeted_countries"]
            industries = item["industries"]
            malware_families = item["malware_families"]
            attack_ids = item["attack_ids"]
            references = item["references"]

            for value in item["indicators"]:
                ioc_id = value["id"]
                ioc = value["indicator"]
                created_time = value["created"]
                ioc_type = value["type"]

                if ioc_type in sample["sample"]:
                    ioc_type = "sample"
                if ioc_type in url["url"]:
                    ioc_type = "url"
                if ioc_type in domain["domain"]:
                    ioc_type = "domain"
                if ioc_type in ipaddress["ipaddress"]:
                    ioc_type = "ipaddress"

                indicator = {
                    "pulse_id": pulse_id,
                    "name": name,
                    "description": description,
                    "author_name": author_name,
                    "modified": modified,
                    "created": created,
                    "targeted_countries": targeted_countries,
                    "industries": industries,
                    "malware_families": malware_families,
                    "attack_ids": attack_ids,
                    "references": references,
                    "ioc_id": ioc_id,
                    "ioc": ioc,
                    "ioc_type": ioc_type,
                    "created_time": created_time,
                    "crawled_time": datetime.now(ist).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3],
                    "source": "otx",
                    "category": category
                }
                print(indicator)
                if es is not None:
                    if setup_es.create_index_indicator(es, "ti-otx-test"):
                        setup_es.store_record(es, "ti-otx-test", indicator)
                # send_indicator(channel, indicator)
    # connection.close()


crawler_otx()
schedule.every(30).minutes.do(crawler_otx)
while True:
    schedule.run_pending()
