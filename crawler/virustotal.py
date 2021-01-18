from datetime import datetime

import requests
import schedule

from helper import network, setup_es

headers = {
    "X-Apikey": "7d42532bd1dea1e55f7a8e99cdee23d9b26c386a6485d6dcb4106b9d055f9277"
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


def hunting_notification_files():
    es = setup_es.connect_elasticsearch()
    engines_hash = {
        "Ad-Aware": 1,
        "AegisLab": 1,
        "ALYac": 2,
        "Antiy-AVL": 1,
        "Arcabit": 1,
        "Avast": 3,
        "AVG": 2,
        "Avira": 1,
        "Baidu": 2,
        "BitDefender": 3,
        "CAT-QuickHeal": 1,
        "Comodo": 2,
        "Cynet": 1,
        "Cyren": 1,
        "DrWeb": 1,
        "Emsisoft": 2,
        "eScan": 2,
        "ESET-NOD32": 3,
        "F-Secure": 2,
        "FireEye": 3,
        "Fortinet": 3,
        "GData": 1,
        "Ikarus": 2,
        "Kaspersky": 3,
        "MAX": 1,
        "McAfee": 3,
        "Microsoft": 3,
        "Panda": 2,
        "Qihoo-360": 2,
        "Rising": 1,
        "Sophos": 2,
        "TrendMicro": 3,
        "TrendMicro-HouseCall": 1,
        "ZoneAlarm by Check Point": 1,
        "Zoner": 1,
        "AhnLab - V3": 1,
        "BitDefenderTheta": 2,
        "Bkav": 1,
        "ClamAV": 3,
        "CMC": 1,
        "Gridinsoft": 1,
        "Jiangmin": 1,
        "K7AntiVirus": 1,
        "K7GW": 1,
        "Kingsoft": 1,
        "Malwarebytes": 3,
        "MaxSecure": 1,
        "McAfee - GW - Edition": 3,
        "NANO - Antivirus": 1,
        "Sangfor Engine Zero": 1,
        "SUPERAntiSpyware": 1,
        "Symantec": 3,
        "TACHYON": 1,
        "Tencent": 2,
        "TotalDefense": 1,
        "VBA32": 2,
        "VIPRE": 1,
        "ViRobot": 1,
        "Yandex": 3,
        "Zillya": 1,
        "Acronis": 3,
        "Alibaba": 2,
        "SecureAge APEX": 1,
        "Avast - Mobile": 2,
        "BitDefenderFalx": 3,
        "CrowdStrike Falcon": 3,
        "Cybereason": 3,
        "Cylance": 2,
        "eGambit": 1,
        "Elastic": 1,
        "Palo Alto Networks": 2,
        "SentinelOne (Static ML)": 1,
        "Symantec Mobile Insight": 3,
        "Trapmine": 1,
        "Trustlook": 1,
        "Webroot": 1,
    }
    cursor = [""]
    while len(cursor) > 0:
        api = "https://www.virustotal.com/api/v3/intelligence/hunting_notification_files?limit=40&cursor={}".format(
            cursor[0])
        data = http.get(api, headers=headers, proxies=proxies).json()
        if data["meta"]["cursor"] != "":
            cursor[0] = data["meta"]["cursor"]
            for item in data["data"]:
                names = "".join(item["attributes"]["names"])
                sha256 = item["attributes"]["sha256"]
                sha1 = item["attributes"]["sha1"]
                md5 = item["attributes"]["md5"]
                tags = item["attributes"]["tags"]
                first_submit = datetime.utcfromtimestamp(item["attributes"]["first_submission_date"]).strftime(
                    '%Y-%m-%dT%H:%M:%S')
                notification_date = datetime.utcfromtimestamp(item["context_attributes"]["notification_date"]).strftime(
                    '%Y-%m-%dT%H:%M:%S')
                type_description = item["attributes"]["type_description"]
                magic = item["attributes"]["magic"]
                country = item["context_attributes"]["notification_source_country"]
                rule_name = item["context_attributes"]["rule_name"]
                analysis_results = item["attributes"]["last_analysis_results"]

                category_clear = ["confirmed-timeout", "undetected", "timeout", "type-unsupported", "failure"]

                engines_detected = []
                points = []
                total = 0
                for name, category in analysis_results.items():
                    if category["category"] not in category_clear:
                        engines_detected.append(name)

                for engines_name in engines_detected:
                    if engines_name in engines_hash:
                        points.append({engines_name: engines_hash.get(engines_name)})

                for engines_point in points:
                    for name, point in engines_point.items():
                        total += point
                if total >= 13:
                    samples = {
                        "names": names,
                        "sha256": sha256,
                        "sha1": sha1,
                        "md5": md5,
                        "tags": tags,
                        "first_submit": first_submit,
                        "notification_date": notification_date,
                        "type_description": type_description,
                        "magic": magic,
                        "country": country,
                        "rule_name": rule_name,
                        "detected": engines_detected,
                        "rate": len(engines_detected),
                        "point": total,
                    }
                    if es is not None:
                        if setup_es.create_index_samples(es, "ti-virus-test"):
                            setup_es.store_record(es, "ti-virus-test", samples)
        else:
            cursor.clear()


hunting_notification_files()
schedule.every(30).minutes.do(hunting_notification_files)
while True:
    schedule.run_pending()

