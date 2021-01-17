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
    # index settings
    settings = {
        "settings": {
            "number_of_shards": 1,
            "number_of_replicas": 0
        },
        "mappings": {
            "indicator": {
                "dynamic": "strict",
                "properties": {
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
                        "type": "integer"
                    },
                    "calories": {
                        "type": "nested",
                        "properties": {
                            "step": {"type": "text"}
                        }
                    },
                }
            }
        }
    }

    try:
        if not es_object.indices.exists(index_name):
            # Ignore 400 means to ignore "Index Already Exist" error.
            es_object.indices.create(index=index_name, ignore=400, body=settings)
            print('Created Index')
        created_index_indicator = True
    except Exception as ex:
        print(str(ex))
    finally:
        return created_index_indicator


def create_index_compromised(es_object, index_name):
    created_index_compromised = False
    # index settings
    settings = {
        "settings": {
            "number_of_shards": 1,
            "number_of_replicas": 0
        },
        "mappings": {
            "compromised": {
                "dynamic": "strict",
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
    }

    try:
        if not es_object.indices.exists(index_name):
            # Ignore 400 means to ignore "Index Already Exist" error.
            es_object.indices.create(index=index_name, ignore=400, body=settings)
            print('Created Index')
        created_index_compromised = True
    except Exception as ex:
        print(str(ex))
    finally:
        return created_index_compromised


def store_record(elastic_object, index_name, record):
    is_stored = True
    try:
        outcome = elastic_object.index(index=index_name, doc_type='indicator', body=record)
        print(outcome)
    except Exception as ex:
        print('Error in indexing data')
        print(str(ex))
        is_stored = False
    finally:
        return is_stored
