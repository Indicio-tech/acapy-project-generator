
class Container:
    pass

class ACAPYContainer(Container):
    pass


class Generator:

    def __init__(self):
        self.containers = list()
        pass

    def create_acapy(self) -> ACAPYContainer:
        acapy = ACAPYContainer()
        self.containers.append(acapy)
        return acapy
        pass

    def generate(self):
        for container in self.containers:
            pass
        return "hi"