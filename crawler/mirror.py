import datetime
import hashlib
import json
import time

# import pika
import requests
import schedule
from bs4 import BeautifulSoup

from helper import network, rbmq

headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) '
                  'Chrome/71.0.3578.98 Safari/537.36'}

http = requests.Session()
# retries
# http.mount("https://", network.retry_http_adapter())

# timeout 2s and retries
http.mount("https://", network.TimeoutHTTPAdapter(max_retries=network.retry_http_adapter()))


def send_compromised(channel, message):
    channel.basic_publish(exchange='',
                          routing_key='compromised_queue',
                          body=json.dumps(message))
    # properties=pika.BasicProperties(priority=5))
    print("Sent %r" % message)


def get_total_page_mirror():
    start_req = http.get('https://mirror-h.org/archive/', headers=headers)
    parse_req = BeautifulSoup(start_req.text, 'html.parser')
    last_link = [link for link in parse_req.find_all('a', {'title': 'Last'})]
    total_page = int(last_link[0]['href'].rsplit('/', 1)[1])
    return total_page


def crawler_mirror():
    connection, channel = rbmq.setup_connect('compromised_queue')
    total_page = get_total_page_mirror()
    pages = [str(page) for page in range(1, total_page + 1)]
    for page in pages:
        url = 'https://mirror-h.org/archive/page/{}'.format(page)
        res = http.get(url, headers=headers)
        if res.ok:
            parse = BeautifulSoup(res.text, 'html.parser')
            table = parse.find('table')
            for row in table.find_all('tr'):
                list_of_cells = []
                for cell in row.find_all('td'):
                    text = cell.text
                    list_of_cells.append(text)
                if len(list_of_cells) != 0:
                    hostname = list_of_cells[0]
                    country = list_of_cells[1].strip().replace('(', '').replace(')', '')
                    uid = list_of_cells[2]
                    src = list_of_cells[3]
                    date_time_str = list_of_cells[4].replace("/", " ")
                    date_time_obj = datetime.datetime.strptime(date_time_str, '%d %m %Y')
                    creation_date = date_time_obj.strftime("%Y-%m-%dT%H:%M:%S")
                    timestamp = int(time.mktime(time.strptime(creation_date, '%Y-%m-%dT%H:%M:%S')))
                    victim_hash = hashlib.sha1(
                        "{}-{}-{}".format(timestamp, src, hostname).encode('utf-8')).hexdigest()
                    compromised = {
                        "uid": uid,
                        "hostname": hostname,
                        "src": src,
                        "victim_hash": victim_hash,
                        "creation_date": creation_date,
                        "timestamp": timestamp,
                        "country": country
                    }
                    send_compromised(channel, compromised)
    connection.close()


crawler_mirror()
schedule.every(1).hours.do(crawler_mirror)
while True:
    schedule.run_pending()
