import json


class ServicesDB(object):

    def __init__(self, db_path=None):
        self.db_path = db_path
        self.services = self.load_services()

    def load_services(self):
        with open(self.db_path, 'r') as json_db_file:
            services = json.load(json_db_file)
        return services

    def get_service(self, public_id):
        #todo: change json list to dict structure
        #todo : index by service_public_id
        service = list(filter(lambda s: s['public_id'] == public_id, self.services))
        return service[0] if len(service) > 0 else None

    def validate_services(self):
        #todo: validate services db structure (required fields, regex ips, uuids, ports, etc)
        pass
