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
        t = list(filter(lambda n: n['public_id'] == public_id, self.services))
        return t[0] if len(t) > 0 else None
