import requests

headers = {
    'X-Apikey': '7d42532bd1dea1e55f7a8e99cdee23d9b26c386a6485d6dcb4106b9d055f9277'
}


def hunting_notification_files():
    engines_hash = {
        'Ad-Aware': 1,
        'AegisLab': 1,
        'ALYac': 2,
        'Antiy-AVL': 1,
        'Arcabit': 1,
        'Avast': 3,
        'AVG': 2,
        'Avira': 1,
        'Baidu': 2,
        'BitDefender': 3,
        'CAT-QuickHeal': 1,
        'Comodo': 2,
        'Cynet': 1,
        'Cyren': 1,
        'DrWeb': 1,
        'Emsisoft': 2,
        'eScan': 2,
        'ESET-NOD32': 3,
        'F-Secure': 2,
        'FireEye': 3,
        'Fortinet': 3,
        'GData': 1,
        'Ikarus': 2,
        'Kaspersky': 3,
        'MAX': 1,
        'McAfee': 3,
        'Microsoft': 3,
        'Panda': 2,
        'Qihoo-360': 2,
        'Rising': 1,
        'Sophos': 2,
        'TrendMicro': 3,
        'TrendMicro-HouseCall': 1,
        'ZoneAlarm by Check Point': 1,
        'Zoner': 1,
        'AhnLab - V3': 1,
        'BitDefenderTheta': 2,
        'Bkav': 1,
        'ClamAV': 3,
        'CMC': 1,
        'Gridinsoft': 1,
        'Jiangmin': 1,
        'K7AntiVirus': 1,
        'K7GW': 1,
        'Kingsoft': 1,
        'Malwarebytes': 3,
        'MaxSecure': 1,
        'McAfee - GW - Edition': 3,
        'NANO - Antivirus': 1,
        'Sangfor Engine Zero': 1,
        'SUPERAntiSpyware': 1,
        'Symantec': 3,
        'TACHYON': 1,
        'Tencent': 2,
        'TotalDefense': 1,
        'VBA32': 2,
        'VIPRE': 1,
        'ViRobot': 1,
        'Yandex': 3,
        'Zillya': 1,
        'Acronis': 3,
        'Alibaba': 2,
        'SecureAge APEX': 1,
        'Avast - Mobile': 2,
        'BitDefenderFalx': 3,
        'CrowdStrike Falcon': 3,
        'Cybereason': 3,
        'Cylance': 2,
        'eGambit': 1,
        'Elastic': 1,
        'Palo Alto Networks': 2,
        'SentinelOne (Static ML)': 1,
        'Symantec Mobile Insight': 3,
        'Trapmine': 1,
        'Trustlook': 1,
        'Webroot': 1,
    }
    cursor = ['']
    print("before cursor->", cursor[0])
    while len(cursor) > 0:
        path_api = "https://www.virustotal.com/api/v3/intelligence/hunting_notification_files?limit=40&cursor={}".format(
            cursor[0])
        print(path_api)
        data = requests.get(path_api, headers=headers).json()
        if data['meta']['cursor'] != '':
            cursor[0] = data['meta']['cursor']
            print("after cursor->", cursor[0])
            for item in data['data']:
                sha256 = item['attributes']['sha256']
                sha1 = item['attributes']['sha1']
                md5 = item['attributes']['md5']
                tags = item['attributes']['tags']
                first_submit = item['attributes']['first_submission_date']
                notification_date = item['context_attributes']['notification_date']
                file_type = item['attributes']['exiftool']['FileType']
                engines_detected = item['attributes']['last_analysis_results']

                type_clear = ["confirmed-timeout", "undetected", "timeout", "type-unsupported", "failure"]

                engines_name = []
                engines_points = []
                total_point = 0
                for av_name, av_type in engines_detected.items():
                    if av_type['category'] not in type_clear:
                        engines_name.append(av_name)

                for avname in engines_name:
                    if avname in engines_hash:
                        engines_points.append({avname: engines_hash.get(avname)})

                for av_point in engines_points:
                    for av_name, point in av_point.items():
                        total_point += point
                if total_point >= 13:
                    samples = {
                        "sha256": sha256,
                        "sha1": sha1,
                        "md5": md5,
                        "tags": tags,
                        "first_submit": first_submit,
                        "notification_date": notification_date,
                        "file_type": file_type,
                        "detected": len(engines_name),
                        "point": total_point,
                    }
                    print(samples)
        else:
            cursor.clear()
            print("clear")


if __name__ == '__main__':
    hunting_notification_files()
