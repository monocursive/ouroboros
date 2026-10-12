import yaml

class Store:
    def __init__(self, path):
        self.path = path

    def save(self, data):
        with open(self.path, 'w') as f:
            yaml.dump(data, f)

    def load(self):
        with open(self.path) as f:
            return yaml.safe_load(f)
