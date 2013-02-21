# Yep, plain old data structure.
class StatsEntity:
    def __init__(self):
        self.lasttimestamp = None
        self.pcount = 0
        self.timings = {}
        self.psizes = {}
