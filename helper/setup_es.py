from elasticsearch import Elasticsearch


def connect_elasticsearch():
    _es = None
    _es = Elasticsearch([{'host': 'localhost', 'port': 9200}])
    if _es.ping():
        print('Connected Elasticsearch')
    else:
        print('Elasticsearch could not connect!')
    return _es


def create_index_indicator(es_object, index_name):
    created_index_indicator = False
    settings = {
        "settings": {
            "number_of_shards": 2,
            "number_of_replicas": 0
        },
        "mappings": {
            "properties": {
                "pulse_id": {
                    "type": "text"
                },
                "name": {
                    "type": "text"
                },
                "description": {
                    "type": "text"
                },
                "author_name": {
                    "type": "text"
                },
                "modified": {
                    "type": "date"
                },
                "created": {
                    "type": "date"
                },
                "targeted_countries": {
                    "type": "text",
                },
                "industries": {
                    "type": "text",
                },
                "malware_families": {
                    "type": "text",
                },
                "attack_ids": {
                    "type": "text",
                },
                "references": {
                    "type": "text",
                },
                "ioc_id": {
                    "type": "text"
                },
                "ioc": {
                    "type": "text"
                },
                "ioc_type": {
                    "type": "text"
                },
                "created_time": {
                    "type": "date"
                },
                "crawled_time": {
                    "type": "date"
                },
                "source": {
                    "type": "text"
                },
                "category": {
                    "type": "text",
                },
            }
        }
    }

    try:
        if not es_object.indices.exists(index_name):
            print("not exists")
            res = es_object.indices.create(index=index_name, ignore=400, body=settings)
            print(res)
        created_index_indicator = True
    except Exception as ex:
        print(str(ex))
    finally:
        return created_index_indicator


def create_index_compromised(es_object, index_name):
    created_index_compromised = False
    settings = {
        "settings": {
            "number_of_shards": 2,
            "number_of_replicas": 0
        },
        "mappings": {
            "properties": {
                "uid": {
                    "type": "text"
                },
                "hostname": {
                    "type": "text"
                },
                "src": {
                    "type": "text"
                },
                "victim_hash": {
                    "type": "text"
                },
                "creation_date": {
                    "type": "date"
                },
                "timestamp": {
                    "type": "date"
                },
                "country": {
                    "type": "text",
                },
            }
        }
    }

    try:
        if not es_object.indices.exists(index_name):
            res = es_object.indices.create(index=index_name, ignore=400, body=settings)
            print(res)
        created_index_compromised = True
    except Exception as ex:
        print(str(ex))
    finally:
        return created_index_compromised


def create_index_samples(es_object, index_name):
    created_index_samples = False
    settings = {
        "settings": {
            "number_of_shards": 2,
            "number_of_replicas": 0
        },
        "mappings": {
            "properties": {
                "names": {
                    "type": "text"
                },
                "sha256": {
                    "type": "text"
                },
                "sha1": {
                    "type": "text"
                },
                "md5": {
                    "type": "text"
                },
                "first_submit": {
                    "type": "date"
                },
                "notification_date": {
                    "type": "date"
                },
                "type_description": {
                    "type": "text",
                },
                "magic": {
                    "type": "text",
                },
                "country": {
                    "type": "text",
                },
                "rule_name": {
                    "type": "text",
                },
                "rate": {
                    "type": "text",
                },
                "tags": {
                    "type": "text",
                },
                "detected": {
                    "type": "text",
                },
                "point": {
                    "type": "integer",
                }
            }
        }
    }

    try:
        if not es_object.indices.exists(index_name):
            res = es_object.indices.create(index=index_name, ignore=400, body=settings)
            print(res)
        created_index_samples = True
    except Exception as ex:
        print(str(ex))
    finally:
        return created_index_samples


def store_record(elastic_object, index_name, index_id, record):
    is_stored = True
    try:
        output = elastic_object.index(index=index_name, id=index_id, body=record)
        print(output)
    except Exception as ex:
        print("Error in indexing data")
        print(str(ex))
        is_stored = False
    finally:
        return is_stored
