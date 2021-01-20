import json

import pika


def connect(queue_name):
    # connection = pika.BlockingConnection(pika.ConnectionParameters(host='localhost', port=5673,
    #                                                               credentials=pika.PlainCredentials(username='test',
    #                                                                                                 password='test')))
    connection = pika.BlockingConnection(pika.ConnectionParameters(host='localhost', port=5672,
                                                                   credentials=pika.PlainCredentials(username='guest',
                                                                                                     password='guest')))
    channel = connection.channel()
    # channel.queue_declare(queue=queue_name, durable=True, arguments={'x-max-priority': 5})
    channel.queue_declare(queue=queue_name, durable=True)
    return connection, channel


def send(channel, message, queue_name):
    channel.basic_publish(exchange="",
                          routing_key=queue_name,
                          body=json.dumps(message))
    # properties=pika.BasicProperties(priority=5))
    print("Sent %r" % message)
